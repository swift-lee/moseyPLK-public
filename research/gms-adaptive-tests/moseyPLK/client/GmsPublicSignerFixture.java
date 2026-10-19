package moseyPLK.client;

import com.android.apksig.ApkVerifier;
import com.android.apksig.SigningCertificateLineage;
import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.List;

/** Extracts only public certificates from an API-36-verified retained APK into host test storage. */
public final class GmsPublicSignerFixture {
    private static final String[] EXPECTED = {
            "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83",
            "7ce83c1b71f3d572fed04c8d40c5cb10ff75e6d87d9df6fbd53f0468c2905053",
            "5f2391277b1dbd489000467e4c2fa6af802430080457dce2f618992e9dfb5402"};

    private static String hash(X509Certificate certificate) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        StringBuilder text = new StringBuilder();
        for (byte value : digest) text.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return text.toString();
    }

    public static void main(String[] args) throws Exception {
        ApkVerifier.Result result = new ApkVerifier.Builder(new File(args[0]))
                .setMinCheckedPlatformVersion(36).setMaxCheckedPlatformVersion(36).build().verify();
        if (!result.isVerified()) throw new IllegalStateException("fixture_apk_signature_invalid");
        if (result.getSignerCertificates().size() != 1
                || !EXPECTED[2].equals(hash(result.getSignerCertificates().get(0))))
            throw new IllegalStateException("fixture_current_signer_changed");
        SigningCertificateLineage lineage = result.getSigningCertificateLineage();
        if (lineage == null) throw new IllegalStateException("fixture_signing_history_missing");
        List<X509Certificate> certificates = lineage.getCertificatesInLineage();
        if (certificates.size() != EXPECTED.length) throw new IllegalStateException("fixture_history_changed");
        File directory = new File(args[1]);
        if (!directory.mkdir()) throw new IllegalStateException("fixture_directory_exists");
        for (int i = 0; i < EXPECTED.length; i++) {
            if (!EXPECTED[i].equals(hash(certificates.get(i))))
                throw new IllegalStateException("fixture_history_certificate_changed");
            Files.write(new File(directory, i + ".der").toPath(), certificates.get(i).getEncoded());
        }
        System.out.println("PASS API-36-verified GMS public signing lineage: 3 certificates");
    }
}
