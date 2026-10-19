package moseyPLK.client;

import android.os.Build;
import android.os.Process;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Zygote only records the path. Native loading happens lazily in the target GMS worker. */
final class GmsModuleIdentity {
    private static volatile String modulePath;
    private static boolean nativeLoaded;
    private GmsModuleIdentity() { }

    static void record(String path) { modulePath = path; }

    static File apk() throws Exception {
        String path = modulePath;
        if (path == null) throw new IllegalStateException("module_path_unavailable");
        File result = new File(path).getCanonicalFile();
        if (!result.isFile() || !result.canRead()) throw new IllegalStateException("module_apk_unavailable");
        return result;
    }

    static boolean forceAdaptive() throws Exception {
        // Legacy method name retained for build tooling: both variants now resolve
        // automatically. This checks only the separately labelled test APK identity.
        if (!GmsBuildVariant.ADAPTIVE_TEST) return false;
        byte[] expected = "force_adaptive_v1\n".getBytes(StandardCharsets.UTF_8);
        try (ZipFile zip = new ZipFile(apk())) {
            ZipEntry marker = zip.getEntry("assets/mosey-adaptive-test");
            if (marker == null) throw new IllegalStateException("missing_test_marker");
            if (marker.getSize() != expected.length) throw new IllegalStateException("invalid_test_marker");
            try (InputStream stream = zip.getInputStream(marker)) {
                for (byte value : expected) if (stream.read() != (value & 255))
                    throw new IllegalStateException("invalid_test_marker");
                if (stream.read() != -1) throw new IllegalStateException("invalid_test_marker");
            }
            return true;
        }
    }

    static synchronized void loadNative() throws Exception {
        if (nativeLoaded) return;
        if (!Process.is64Bit() || Build.SUPPORTED_64_BIT_ABIS.length == 0
                || !"arm64-v8a".equals(Build.SUPPORTED_64_BIT_ABIS[0]))
            throw new IllegalStateException("unsupported_native_abi");
        File module = apk();
        try (ZipFile zip = new ZipFile(module)) {
            ZipEntry library = zip.getEntry("lib/arm64-v8a/libdexkit.so");
            if (library == null || library.getMethod() != ZipEntry.STORED)
                throw new IllegalStateException("native_library_not_stored");
        }
        System.load(module.getPath() + "!/lib/arm64-v8a/libdexkit.so");
        nativeLoaded = true;
    }
}
