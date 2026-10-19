package moseyPLK.client;

/** Checks both exact mutation allowlists without Android or business calls. */
public final class GmsRegistryEnablementTest {
    private static int checks;

    private static void check(boolean value, String name) {
        ++checks;
        if (!value) throw new AssertionError(name);
    }

    private static final class UntrustedResult {
        @Override public boolean equals(Object other) {
            throw new AssertionError("Result equality must not be invoked");
        }
        @Override public int hashCode() {
            throw new AssertionError("Result hashing must not be invoked");
        }
        @Override public String toString() {
            throw new AssertionError("Result formatting must not be invoked");
        }
    }

    private static void rejects(GmsDiagnosticPolicy.Profile profile,
            GmsDiagnosticPolicy.Spec spec, String name) {
        check(!GmsRegistryEnablement.shouldEnable(profile, spec, false, Boolean.FALSE), name);
    }

    public static void main(String[] args) {
        GmsDiagnosticPolicy.Profile old = GmsDiagnosticPolicy.profileFor(
                263332035L, "26.33.32 (260400-974685114)");
        GmsDiagnosticPolicy.Profile current = GmsDiagnosticPolicy.profileFor(
                263436035L, "26.34.36 (260400-981326859)");
        check(old != null && current != null, "both reviewed profiles exist");
        for (GmsDiagnosticPolicy.Profile profile : new GmsDiagnosticPolicy.Profile[] {old, current}) {
            int accepted = 0;
            GmsDiagnosticPolicy.Spec getter = null, supplier = null;
            String getterName = profile == old ? "jpsb.S" : "jtmb.W";
            String supplierName = profile == old ? "eabp.lr" : "ecyv.ln";
            for (GmsDiagnosticPolicy.Spec spec : profile.specs()) {
                boolean target = getterName.equals(spec.label()) || supplierName.equals(spec.label());
                check(GmsRegistryEnablement.shouldEnable(profile, spec, false, Boolean.FALSE) == target,
                        "only reviewed natural false returns admitted: " + spec.label());
                rejects(profile == old ? current : old, spec, "cross-profile spec rejected");
                rejects(null, spec, "missing verified profile rejected");
                if (target) {
                    ++accepted;
                    if (getterName.equals(spec.label())) getter = spec;
                    else supplier = spec;
                }
                check(!GmsRegistryEnablement.shouldEnable(profile, spec, false, Boolean.TRUE),
                        "true stays original: " + spec.label());
                check(!GmsRegistryEnablement.shouldEnable(profile, spec, true, Boolean.FALSE),
                        "throwable cannot be suppressed: " + spec.label());
                for (Object invalid : new Object[] {null, Integer.valueOf(0), "false", new UntrustedResult()}) {
                    check(!GmsRegistryEnablement.shouldEnable(profile, spec, false, invalid),
                            "non-Boolean must not be interpreted: " + spec.label());
                }
            }
            check(accepted == 2 && getter != null && supplier != null, "two canonical mutation contracts");
            check("flag_read".equals(getter.event) && "45704091".equals(getter.flag),
                    "direct getter identifies one raw flag");
            if (profile == current) {
                check("registry_gate_read".equals(supplier.event)
                        && "45704091|45830365".equals(supplier.flag),
                        "new supplier represents an OR expression, not one raw flag");
            }
            rejects(profile, null, "null contract");

            for (GmsDiagnosticPolicy.Spec target : new GmsDiagnosticPolicy.Spec[] {getter, supplier}) {
                String owner = target.owner, method = target.method, returns = target.returns;
                rejects(profile, new GmsDiagnosticPolicy.Spec(owner, method, returns, false,
                        target.event, target.flag), "same-fields clone is not canonical");
                rejects(profile, new GmsDiagnosticPolicy.Spec(owner, method, returns, false,
                        target.event, target.flag, "java.lang.String"), "added reference argument");
                rejects(profile, new GmsDiagnosticPolicy.Spec(owner, method, returns, false,
                        target.event, target.flag, "boolean"), "added primitive argument");
                rejects(profile, new GmsDiagnosticPolicy.Spec(owner, method, returns, true,
                        target.event, target.flag), "static signature rejected");
                rejects(profile, new GmsDiagnosticPolicy.Spec(owner, method, "java.lang.Boolean", false,
                        target.event, target.flag), "boxed-return mismatch rejected");
                rejects(profile, new GmsDiagnosticPolicy.Spec(owner + "Other", method, returns, false,
                        target.event, target.flag), "other declaring class");
                rejects(profile, new GmsDiagnosticPolicy.Spec(owner, method + "Other", returns, false,
                        target.event, target.flag), "other method");
                for (String flag : new String[] {null, "45802344", "45723015", "45824526", "45830365"}) {
                    rejects(profile, new GmsDiagnosticPolicy.Spec(owner, method, returns, false,
                            target.event, flag), "unreviewed flag");
                }
                rejects(profile, new GmsDiagnosticPolicy.Spec(owner, method, returns, false,
                        "provider_filter", target.flag), "other observation event");
            }

            GmsDiagnosticPolicy.Spec[] exported = profile.specs();
            for (int i = 0; i < exported.length; ++i) exported[i] = null;
            check(GmsRegistryEnablement.shouldEnable(profile, getter, false, Boolean.FALSE),
                    "getter canonical after caller modifies array");
            check(GmsRegistryEnablement.shouldEnable(profile, supplier, false, Boolean.FALSE),
                    "supplier canonical after caller modifies array");
        }
        System.out.println("PASS: " + checks + " GMS profile-isolated enablement allowlist checks");
    }
}
