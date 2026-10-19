package moseyPLK.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Host-testable installed-code identity; every source is treated only as data. */
public final class GmsApkSnapshot {
    public final File baseApk;
    public final File moduleApk;
    public final String identity;
    public final List<File> gmsFiles;
    public final List<File> files;
    private final long[] sizes;
    private final long[] modified;

    public GmsApkSnapshot(File base, List<File> splits, File module, String identity)
            throws IOException {
        if (identity == null || identity.length() > 4096) throw new IOException("invalid_snapshot_identity");
        this.identity = identity;
        baseApk = base.getCanonicalFile();
        ArrayList<File> entries = new ArrayList<File>();
        entries.add(baseApk);
        ArrayList<File> orderedSplits = new ArrayList<File>();
        for (File split : splits) orderedSplits.add(split.getCanonicalFile());
        Collections.sort(orderedSplits);
        entries.addAll(orderedSplits);
        gmsFiles = Collections.unmodifiableList(new ArrayList<File>(entries));
        moduleApk = module.getCanonicalFile();
        entries.add(moduleApk);
        if (entries.size() > 66) throw new IOException("too_many_apk_sources");
        files = Collections.unmodifiableList(entries);
        sizes = new long[files.size()];
        modified = new long[files.size()];
        for (int i = 0; i < files.size(); i++) {
            File file = files.get(i);
            if (!file.isFile() || !file.canRead() || file.length() <= 0)
                throw new IOException("apk_source_unreadable");
            if (files.subList(0, i).contains(file)) throw new IOException("duplicate_apk_source");
            sizes[i] = file.length();
            modified[i] = file.lastModified();
        }
    }

    public boolean unchanged() {
        return unchanged(0, files.size());
    }

    private boolean unchanged(int start, int end) {
        for (int i = start; i < end; i++) {
            File file = files.get(i);
            if (!file.isFile() || file.length() != sizes[i] || file.lastModified() != modified[i])
                return false;
        }
        return true;
    }

    /** Rehash every installed GMS APK for each process; metadata alone never accepts a cache. */
    public String gmsFingerprint() throws IOException {
        if (!unchanged(0, gmsFiles.size())) throw new IOException("gms_apk_changed_before_hash");
        MessageDigest digest = digest();
        update(digest, "mosey-gms-content:v1");
        update(digest, identity);
        update(digest, Integer.toString(gmsFiles.size()));
        byte[] buffer = new byte[65536];
        for (File file : gmsFiles) {
            update(digest, file.getPath());
            update(digest, Long.toString(file.length()));
            updateFile(digest, file, buffer);
        }
        if (!unchanged(0, gmsFiles.size())) throw new IOException("gms_apk_changed_during_hash");
        return hex(digest.digest());
    }

    /** The module is a same-resolution generation guard, never part of the persistent cache key. */
    public String moduleGeneration() throws IOException {
        int index = files.size() - 1;
        if (!unchanged(index, files.size())) throw new IOException("module_changed_before_hash");
        MessageDigest digest = digest();
        update(digest, "mosey-resolver-module-generation:v1");
        update(digest, moduleApk.getPath());
        update(digest, Long.toString(moduleApk.length()));
        updateFile(digest, moduleApk, new byte[65536]);
        if (!unchanged(index, files.size())) throw new IOException("module_changed_during_hash");
        return hex(digest.digest());
    }

    private static void updateFile(MessageDigest digest, File file, byte[] buffer) throws IOException {
        try (FileInputStream input = new FileInputStream(file)) {
            int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
    }

    static MessageDigest digest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    static void update(MessageDigest digest, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        digest.update(Integer.toString(bytes.length).getBytes(StandardCharsets.US_ASCII));
        digest.update((byte) ':');
        digest.update(bytes);
    }

    static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) value.append(Character.forDigit((b >>> 4) & 15, 16))
                .append(Character.forDigit(b & 15, 16));
        return value.toString();
    }
}
