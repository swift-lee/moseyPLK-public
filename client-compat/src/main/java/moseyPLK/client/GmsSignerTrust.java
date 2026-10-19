package moseyPLK.client;

import android.content.pm.Signature;
import android.content.pm.SigningInfo;

/** Google identity anchored in a reviewed certificate and Android-verified signing history. */
final class GmsSignerTrust {
    private static final String REVIEWED_ROOT =
            "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83";

    private GmsSignerTrust() { }

    static String currentSigner(SigningInfo info) throws Exception {
        if (info == null) throw new IllegalStateException("package_identity_unavailable");
        Signature[] signers = info.getApkContentsSigners();
        if (info.hasMultipleSigners() || signers == null || signers.length != 1 || signers[0] == null)
            throw new IllegalStateException("unsupported_signer_set");
        String current = digest(signers[0]);
        if (REVIEWED_ROOT.equals(current)) return current;
        // PackageManager supplies this history only after the platform verifies proof of
        // rotation. Never accept a history supplied by an APK string, config or cache.
        Signature[] history = info.getSigningCertificateHistory();
        if (history == null || history.length < 2)
            throw new IllegalStateException("unreviewed_gms_signer");
        boolean trusted = false;
        String last = null;
        for (Signature certificate : history) {
            if (certificate == null) throw new IllegalStateException("invalid_signing_history");
            last = digest(certificate);
            trusted |= REVIEWED_ROOT.equals(last);
        }
        if (!current.equals(last)) throw new IllegalStateException("invalid_signing_history");
        if (!trusted) throw new IllegalStateException("unreviewed_gms_signer");
        // Keep the actual current signer in package/cache identity; rotation invalidates
        // old content-bound results even though the new lineage remains trusted.
        return current;
    }

    private static String digest(Signature certificate) throws Exception {
        return GmsApkSnapshot.hex(GmsApkSnapshot.digest().digest(certificate.toByteArray()));
    }
}
