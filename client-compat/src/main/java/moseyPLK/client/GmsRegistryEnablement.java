package moseyPLK.client;

/** False-only enablement on the selected build's two reviewed gate paths. */
public final class GmsRegistryEnablement {
    private GmsRegistryEnablement() {}

    /**
     * The caller also enforces user 0, the GMS main process and the exact method
     * signature. Only canonical Spec identities owned by this Profile qualify;
     * other builds, reconstructed Specs and observation-only flags cannot act.
     * The current composite supplier is a boolean fallback for W || U, never
     * an independent override of U and never a measurement of W's raw value.
     */
    public static boolean shouldEnable(GmsDiagnosticPolicy.Profile profile,
            GmsDiagnosticPolicy.Spec spec, boolean hasThrowable, Object result) {
        return profile != null && spec != null && !hasThrowable
                && result instanceof Boolean && !((Boolean) result).booleanValue()
                && profile.enables(spec);
    }
}
