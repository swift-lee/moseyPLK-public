package android.util;

public final class Log {
    public static final java.util.List<String> lines = new java.util.ArrayList<String>();
    public static boolean fail;
    public static int failures;
    public static int i(String tag, String text) {
        if (fail) { failures++; throw new IllegalStateException("logger unavailable"); }
        lines.add(tag + " " + text);
        return 0;
    }
    public static void reset() { lines.clear(); fail = false; failures = 0; }
}
