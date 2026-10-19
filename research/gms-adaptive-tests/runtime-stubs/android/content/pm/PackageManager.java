package android.content.pm;

public class PackageManager {
    public static final int GET_SIGNING_CERTIFICATES = 0x08000000;
    public static final int MATCH_DISABLED_COMPONENTS = 512;
    public static final int COMPONENT_ENABLED_STATE_DISABLED = 2;
    public static final int COMPONENT_ENABLED_STATE_ENABLED = 1;
    public static final int DONT_KILL_APP = 1;
    public ServiceInfo getServiceInfo(android.content.ComponentName component, int flags) {
        throw new AssertionError("unexpected service lookup");
    }
    public int getComponentEnabledSetting(android.content.ComponentName component) {
        throw new AssertionError("unexpected component query");
    }
    public void setComponentEnabledSetting(android.content.ComponentName component, int state, int flags) {
        throw new AssertionError("unexpected component mutation");
    }
    public PackageInfo info;
    public int queries;
    public int changeOnQuery;
    public boolean fail;
    public PackageInfo getPackageInfo(String name, int flags) {
        if ("com.google.android.gms".equals(name) && flags == 0) return info;
        if (!"com.google.android.gms".equals(name) || flags != GET_SIGNING_CERTIFICATES)
            throw new AssertionError("Unexpected package lookup");
        queries++;
        if (fail) throw new IllegalStateException("package_manager_failure");
        if (queries == changeOnQuery) info.versionCode++;
        return info;
    }
}
