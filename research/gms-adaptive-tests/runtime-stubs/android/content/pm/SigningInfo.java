package android.content.pm;

public class SigningInfo {
    public Signature[] signers;
    public Signature[] history;
    public boolean multiple;
    public Signature[] getApkContentsSigners() { return signers; }
    public Signature[] getSigningCertificateHistory() { return history; }
    public boolean hasMultipleSigners() { return multiple; }
}
