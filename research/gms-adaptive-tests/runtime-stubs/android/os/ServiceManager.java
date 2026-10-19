package android.os;
public final class ServiceManager {
 public static volatile IBinder binder;
 public static IBinder checkService(String name) { return binder; }
 public static IBinder waitForDeclaredService(String name) { throw new AssertionError("active declared wait"); }
}
