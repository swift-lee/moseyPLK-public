import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import com.android.apksig.ApkVerifier;
import com.android.apksig.SigningCertificateLineage;

public final class ApkSigningAudit {
    static String hash(X509Certificate c)throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()));
    }
    public static void main(String[] args)throws Exception {
        for(String arg:args) {
            ApkVerifier.Result result = new ApkVerifier.Builder(new File(arg))
                .setMinCheckedPlatformVersion(36).setMaxCheckedPlatformVersion(36).build().verify();
            System.out.println("APK="+new File(arg).getParentFile().getName()+" verified_api36="+result.isVerified());
            if(!result.isVerified())throw new IllegalStateException(result.getAllErrors().toString());
            for(X509Certificate c:result.getSignerCertificates())System.out.println("current="+hash(c));
            SigningCertificateLineage lineage=result.getSigningCertificateLineage();
            if(lineage==null)System.out.println("lineage=absent");
            else for(X509Certificate c:lineage.getCertificatesInLineage())System.out.println("lineage="+hash(c));
        }
    }
}
