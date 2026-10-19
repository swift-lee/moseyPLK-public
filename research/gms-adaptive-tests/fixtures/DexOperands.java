/** Input data for host D8/parser tests. Never loaded into an Android process. */
public final class DexOperands {
    public Object value;
    public static Object singleton;
    public DexOperands(Object input) { value=input; }
    public Object copy(DexOperands other) { value=(String) other.value; return singleton; }
    public static int packed(int key) {
        switch (key) { case 1:return 17;case 2:return 23;case 3:return 29;default:return -7; }
    }
    public static int sparse(int key) {
        switch (key) { case 1:return 17;case 200:return 23;case 7000:return 29;default:return -7; }
    }
    public static int[] array() { return new int[]{19,23,29,31,37,41,43,47}; }
    public static long wide() { return 0xf123456789abcdefL; }
    public static String unicode() { return "a\u0000\u07ff\u0800\ud83d\ude00"; }
    public static int caught(Object value) {
        try { return value.hashCode(); } catch (NullPointerException e) { return 0; } catch (RuntimeException e) { return -1; }
    }
    public synchronized Object monitored(Object lock) { synchronized (lock) { return value; } }
}
