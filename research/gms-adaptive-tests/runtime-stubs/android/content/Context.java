package android.content;

public class Context {
    public String packageName = "com.google.android.gms";
    public String getPackageName() { return packageName; }
    public android.content.pm.PackageManager packages;
    public ClassLoader loader;
    public java.io.File codeCache;
    public android.content.pm.PackageManager getPackageManager() { return packages; }
    public ContentResolver getContentResolver() { return new ContentResolver(); }
    public ClassLoader getClassLoader() { return loader; }
    public java.io.File getCodeCacheDir() { return codeCache; }
}
