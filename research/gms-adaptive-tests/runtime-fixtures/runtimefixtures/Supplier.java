package runtimefixtures;

public final class Supplier {
    static { testsupport.Probe.initializations++; }
    public Object value() { testsupport.Probe.business(); return Boolean.FALSE; }
}
