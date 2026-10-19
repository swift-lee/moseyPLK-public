package moseyPLK.client;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.LinkedHashMap;
import java.util.Map;

/** Small, versioned snapshot model. Caller performs disk operations on a private worker. */
final class HookStateStore {
    static final String FILE_NAME = "moseyplk-hook-state-v1.json";
    static final int MAX_BYTES = 16 * 1024;
    private final Map<String, Object> values = new LinkedHashMap<String, Object>();
    private boolean startupEnded, observedNatural;

    HookStateStore(String target) {
        values.put("schema", 1);
        values.put("targetPackage", target);
        values.put("resolution", "pending");
        values.put("workerResolution", "pending");
        values.put("installation", "pending");
        values.put("naturalHit", false);
        values.put("airdropDeclaration", "unconfirmed");
        values.put("binderReady", "unknown");
        values.put("componentRestore", "unknown");
    }

    synchronized void identity(Map<String, Object> identity) { values.putAll(identity); }

    synchronized void event(String name, String detail) {
        values.put("lastEvent", bounded(name));
        values.put("lastDetail", bounded(detail));
        if ("adaptive_start".equals(name)) values.put("resolution", "resolving");
        if ("resolution_complete".equals(name)) values.put("workerResolution", "verified");
        if ("resolution_rejected".equals(name)) {
            values.put("workerResolution", "rejected");
            if (!startupEnded) {
                values.put("resolution", "rejected"); values.put("installation", "inactive");
            }
        }
        if ("profile_verified".equals(name) && !startupEnded) values.put("resolution", "verified");
        if ("startup_timeout".equals(name) || "startup_interrupted".equals(name)) {
            startupEnded = true;
            values.put("resolution", "startup_timeout".equals(name) ? "timeout" : "interrupted");
            values.put("installation", "inactive");
        }
        if ("adaptive_rejected".equals(name)) {
            startupEnded = true; values.put("resolution", "rejected");
            values.put("installation", "inactive");
        }
        if ("adaptive_hooks_active".equals(name) && !startupEnded) {
            values.put("installation", "active");
            if (observedNatural) values.put("naturalHit", true);
        }
        if ("installation_rejected".equals(name)) values.put("installation", "rejected");
        if ("natural_result_0".equals(name) && !startupEnded) {
            // Runtime emits this only after backend activation. A concurrent callback
            // may arrive just before the installer publishes its active event.
            observedNatural = true;
            if ("active".equals(values.get("installation"))) values.put("naturalHit", true);
        }
        if ("airdrop_declared".equals(name)) values.put("airdropDeclaration", "declared");
        if ("hook_installed".equals(name)) {
            values.put("installation", "active"); values.put("resolution", "not_applicable");
        }
        if ("client_interface_ready".equals(name)) values.put("binderReady", "ready");
        if ("declared_lookup".equals(name))
            values.put("binderReady", detail.endsWith("result=ready") ? "ready" : "unavailable");
        if ("recovery_not_ready".equals(name)) {
            values.put("componentRestore", "pending");
            if (!detail.contains("reason=component_pending")) values.put("binderReady", "unavailable");
        }
        if ("component_recovered".equals(name)) values.put("componentRestore", "restored");
        if ("component_unchanged".equals(name)) values.put("componentRestore", "unchanged");
        if ("component_recovery_pending".equals(name) || "recovery_failed".equals(name))
            values.put("componentRestore", "pending");
    }

    synchronized byte[] snapshot(long elapsedMillis) throws IOException {
        values.put("capturedElapsedMs", elapsedMillis);
        StringBuilder out = new StringBuilder("{");
        boolean comma = false;
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            if (comma) out.append(',');
            quote(out, entry.getKey()); out.append(':');
            Object value = entry.getValue();
            if (value instanceof Number || value instanceof Boolean) out.append(value);
            else quote(out, bounded(String.valueOf(value)));
            comma = true;
        }
        byte[] bytes = out.append("}\n").toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_BYTES) throw new IOException("hook_state_too_large");
        return bytes;
    }

    static void write(File directory, byte[] bytes) throws IOException {
        if (bytes.length > MAX_BYTES) throw new IOException("hook_state_too_large");
        Path parent = directory.toPath();
        if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(parent))
            throw new IOException("hook_state_cache_unavailable");
        Path destination = parent.resolve(FILE_NAME);
        if (Files.isSymbolicLink(destination)) throw new IOException("hook_state_symlink");
        Path temporary = Files.createTempFile(parent, ".moseyplk-hook-state-", ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            Files.write(temporary, bytes);
            Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(temporary); }
    }

    private static String bounded(String value) {
        if (value == null) return "";
        return value.length() > 512 ? value.substring(0, 512) : value;
    }

    private static void quote(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 32) {
                out.append("\\u00");
                out.append(Character.forDigit(c >>> 4, 16)).append(Character.forDigit(c & 15, 16));
            } else out.append(c);
        }
        out.append('"');
    }
}
