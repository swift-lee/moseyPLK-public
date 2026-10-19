package moseyPLK.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;

/** A bounded private descriptor cache. It never deserializes executable objects. */
public final class GmsProfileCache {
    private static final int MAGIC = 0x4d504c4b;
    private static final int SCHEMA = 3;
    private static final String FILE_NAME = "profile-v3.bin";
    private final File directory;
    private final String compatibilityId;

    public GmsProfileCache(File privateCodeCache, String compatibilityId) throws IOException {
        validateIdentity(compatibilityId, "invalid_resolver_compatibility_id");
        this.compatibilityId = compatibilityId;
        File parent = privateCodeCache.getCanonicalFile();
        directory = new File(parent, "moseyplk-gms-resolver");
        if (!directory.equals(directory.getCanonicalFile())) throw new IOException("cache_directory_symlink");
    }

    public ResolvedGateSet read(String gmsFingerprint) throws IOException {
        validateIdentity(gmsFingerprint, "invalid_gms_fingerprint");
        if (!directory.equals(directory.getCanonicalFile())) throw new IOException("cache_directory_symlink");
        File file = new File(directory, FILE_NAME);
        if (!Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)) return null;
        if (file.length() < 32 || file.length() > 8192) return null;
        ByteArrayOutputStream bounded = new ByteArrayOutputStream();
        try (java.io.InputStream input = Files.newInputStream(file.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[1024];
            while (bounded.size() <= 8192) {
                int count = input.read(buffer, 0, Math.min(buffer.length, 8193 - bounded.size()));
                if (count < 0) break;
                bounded.write(buffer, 0, count);
            }
        }
        byte[] all = bounded.toByteArray();
        if (all.length < 32 || all.length > 8192) return null;
        int size = all.length - 32;
        byte[] payload = java.util.Arrays.copyOf(all, size);
        byte[] expected = java.util.Arrays.copyOfRange(all, size, all.length);
        if (!MessageDigest.isEqual(GmsApkSnapshot.digest().digest(payload), expected)) return null;
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(payload))) {
            if (input.readInt() != MAGIC || input.readInt() != SCHEMA
                    || input.readInt() != ResolvedGateSet.RULE_VERSION
                    || !gmsFingerprint.equals(input.readUTF())
                    || !compatibilityId.equals(input.readUTF())) return null;
            String getter = input.readUTF(), evidence = input.readUTF();
            if (input.available() != 0) return null;
            return ResolvedGateSet.phenotype(getter, evidence);
        } catch (IllegalArgumentException malformed) { return null; }
    }

    public void write(String gmsFingerprint, ResolvedGateSet gates) throws IOException {
        validateIdentity(gmsFingerprint, "invalid_gms_fingerprint");
        if (!directory.equals(directory.getCanonicalFile())) throw new IOException("cache_directory_symlink");
        if (!directory.isDirectory() && !directory.mkdir()) throw new IOException("cache_directory_unavailable");
        privatePermissions(directory, true);
        File destination = new File(directory, FILE_NAME);
        if (Files.exists(destination.toPath(), LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(destination.toPath(), LinkOption.NOFOLLOW_LINKS))
            throw new IOException("cache_file_unsafe");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(MAGIC); output.writeInt(SCHEMA); output.writeInt(ResolvedGateSet.RULE_VERSION);
            output.writeUTF(gmsFingerprint); output.writeUTF(compatibilityId);
            output.writeUTF(gates.getterDescriptor); output.writeUTF(gates.evidenceDigest);
        }
        byte[] payload = bytes.toByteArray();
        bytes.write(GmsApkSnapshot.digest().digest(payload));
        File temporary = File.createTempFile("profile-", ".tmp", directory);
        try {
            privatePermissions(temporary, false);
            try (java.io.FileOutputStream output = new java.io.FileOutputStream(temporary)) {
                output.write(bytes.toByteArray());
                output.getFD().sync();
            }
            Files.move(temporary.toPath(), destination.toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(temporary.toPath()); }
    }

    private static void validateIdentity(String value, String reason) throws IOException {
        if (value == null || !value.matches("[0-9a-f]{64}")) throw new IOException(reason);
    }

    private static void privatePermissions(File file, boolean directory) throws IOException {
        if (!file.setReadable(false, false) || !file.setWritable(false, false)
                || !file.setExecutable(false, false) || !file.setReadable(true, true)
                || !file.setWritable(true, true) || directory && !file.setExecutable(true, true))
            throw new IOException("cache_permissions_unavailable");
    }
}
