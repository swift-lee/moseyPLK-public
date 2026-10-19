package moseyPLK.client;

import java.util.regex.Pattern;

/** Immutable output of the bounded verifier, never a live DexKit result. */
public final class ResolvedGateSet {
    public static final int RULE_VERSION = 3;
    private static final Pattern BOOLEAN = Pattern.compile("L[^;\\s]+;->[^();\\s]+\\(\\)Z");
    public final String getterDescriptor;
    public final String supplierDescriptor;
    public final String secondaryGetterDescriptor;
    public final String expression;
    public final String evidenceDigest;

    private ResolvedGateSet(String getter, String supplier, String secondary,
            String expression, String evidence) {
        if (getter == null || !BOOLEAN.matcher(getter).matches() || getter.length() > 512
                || supplier != null || secondary != null || !"A".equals(expression)
                || evidence == null || !evidence.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("invalid verified gate set");
        }
        getterDescriptor = getter;
        supplierDescriptor = supplier;
        secondaryGetterDescriptor = secondary;
        this.expression = expression;
        evidenceDigest = evidence;
    }

    static ResolvedGateSet verified(String getter, String supplier, String secondary,
            String expression, String evidenceDigest) {
        return new ResolvedGateSet(getter, supplier, secondary, expression, evidenceDigest);
    }

    static ResolvedGateSet phenotype(String getter, String evidenceDigest) {
        return new ResolvedGateSet(getter, null, null, "A", evidenceDigest);
    }

    static String owner(String descriptor) {
        return descriptor.substring(1, descriptor.indexOf(';')).replace('/', '.');
    }

    static String name(String descriptor) {
        return descriptor.substring(descriptor.indexOf("->") + 2, descriptor.indexOf('('));
    }
}
