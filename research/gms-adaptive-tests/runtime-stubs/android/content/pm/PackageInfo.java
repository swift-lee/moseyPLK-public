package android.content.pm;

public class PackageInfo {
    public ApplicationInfo applicationInfo;
    public SigningInfo signingInfo;
    public String versionName;
    public long versionCode;
    public long lastUpdateTime;
    public long getLongVersionCode() { return versionCode; }
}
