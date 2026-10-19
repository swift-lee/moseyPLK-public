package moseyPLK.client;

public final class GmsAdaptiveResolver {
    public static final class Rejected extends Exception implements GmsResolutionFailure.Classified {
        private static final long serialVersionUID = 1L;
        public Rejected(String reason) { super(reason); }
        @Override public String stage() { return "discovery"; }
        @Override public String reason() { return getMessage(); }
    }
    public static int calls;
    public static ResolvedGateSet resolve(java.io.File base) {
        calls++;
        throw new AssertionError("Runtime fixtures must use verified cache or reject before native loading");
    }
}
