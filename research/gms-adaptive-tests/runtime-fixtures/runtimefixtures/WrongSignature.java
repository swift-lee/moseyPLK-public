package runtimefixtures;

public abstract class WrongSignature {
    public static boolean staticGate() { testsupport.Probe.business(); return false; }
    public Object objectGate() { testsupport.Probe.business(); return Boolean.FALSE; }
    public abstract boolean abstractGate();
    public native boolean nativeGate();
    public boolean withArgument(int ignored) { testsupport.Probe.business(); return false; }
}
