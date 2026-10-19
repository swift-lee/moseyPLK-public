package runtimefixtures;

public final class Getter {
    static { testsupport.Probe.initializations++; }
    public boolean gate() { testsupport.Probe.business(); return false; }
    public boolean secondary() { testsupport.Probe.business(); return false; }
}
