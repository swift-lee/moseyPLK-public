import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.ClassData;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.UsingFieldData;

/** Host-only candidate discovery. Never loads GMS classes or installs hooks. */
public final class GmsDexProbe {
    private static final String NAMESPACE = "com.google.android.gms.nearby";
    private static final String SERVICE = NAMESPACE + ".sharing.NearbySharingChimeraService";
    private static final List<String> KEYS = Arrays.asList("45704091", "45830365");

    private static Map<String, Object> obj(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return result;
    }

    private static List<String> descriptors(Collection<MethodData> methods) {
        List<String> out = new ArrayList<>();
        for (MethodData method : methods) out.add(method.getDescriptor());
        return out;
    }

    private static Map<String, Object> describe(MethodData method) {
        List<Object> fields = new ArrayList<>();
        for (UsingFieldData use : method.getUsingFields()) {
            fields.add(obj("descriptor", use.getField().getDescriptor(),
                    "owner", use.getField().getClassName(), "type", use.getField().getTypeName(),
                    "use", use.getUsingType().toString()));
        }
        return obj("descriptor", method.getDescriptor(), "owner", method.getClassName(),
                "name", method.getMethodName(), "modifiers", method.getModifiers(),
                "parameters", method.getParamTypeNames(), "returns", method.getReturnTypeName(),
                "opcodes", method.getOpNames(), "strings", method.getUsingStrings(),
                "invokes", descriptors(method.getInvokes()), "fields", fields);
    }

    // This is an evidence graph, NOT proof that the namespace is passed as the
    // correct constructor argument. Operand/dataflow verification is separate.
    private static List<Object> namespaceEvidence(ClassData owner) {
        List<Object> hits = new ArrayList<>();
        if (owner == null) return hits;
        List<ClassData> queue = new ArrayList<>();
        List<Integer> depths = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        queue.add(owner);
        depths.add(0);
        for (int i = 0; i < queue.size() && i < 32; i++) {
            ClassData type = queue.get(i);
            int depth = depths.get(i);
            if (!seen.add(type.getDescriptor())) continue;
            for (MethodData method : type.getMethods()) {
                if (!method.getMethodName().equals("<clinit>")) continue;
                if (method.getUsingStrings().contains(NAMESPACE)) hits.add(describe(method));
                if (depth >= 3) continue;
                for (UsingFieldData field : method.getUsingFields()) {
                    ClassData next = field.getField().getDeclaredClass();
                    if (next != null && !seen.contains(next.getDescriptor())) {
                        queue.add(next);
                        depths.add(depth + 1);
                    }
                }
            }
        }
        return hits;
    }

    private static boolean booleanGetter(MethodData method) {
        return method.getParamCount() == 0 && method.getReturnTypeName().equals("boolean")
                && !Modifier.isStatic(method.getModifiers());
    }

    private static Map<String, Object> getter(MethodData method) {
        Map<String, MethodData> contracts = new LinkedHashMap<>();
        contracts.put(method.getDescriptor(), method);
        ClassData owner = method.getDeclaredClass();
        if (owner != null) {
            for (ClassData iface : owner.getInterfaces()) {
                for (MethodData contract : iface.getMethods()) {
                    if (contract.getMethodName().equals(method.getMethodName())
                            && contract.getParamTypeNames().equals(method.getParamTypeNames())
                            && contract.getReturnTypeName().equals(method.getReturnTypeName())) {
                        contracts.put(contract.getDescriptor(), contract);
                    }
                }
            }
        }
        Map<String, MethodData> callers = new LinkedHashMap<>();
        for (MethodData contract : contracts.values()) {
            for (MethodData caller : contract.getCallers()) callers.put(caller.getDescriptor(), caller);
        }
        List<Object> suppliers = new ArrayList<>();
        boolean serviceCreate = false;
        for (MethodData caller : callers.values()) {
            if (caller.getClassName().equals(SERVICE) && caller.getMethodName().equals("onCreate"))
                serviceCreate = true;
            if (caller.getParamCount() == 0 && caller.getReturnTypeName().equals("java.lang.Object")
                    && !Modifier.isStatic(caller.getModifiers())) {
                Map<String, Object> candidate = describe(caller);
                List<String> constructorsCalledByService = new ArrayList<>();
                ClassData type = caller.getDeclaredClass();
                if (type != null) for (MethodData constructor : type.getMethods()) {
                    if (!constructor.getMethodName().equals("<init>")) continue;
                    for (MethodData consumer : constructor.getCallers()) {
                        if (consumer.getClassName().equals(SERVICE))
                            constructorsCalledByService.add(consumer.getDescriptor());
                    }
                }
                candidate.put("service_constructor_consumers", constructorsCalledByService);
                suppliers.add(candidate);
            }
        }
        return obj("method", describe(method), "contracts", new ArrayList<>(contracts.keySet()),
                "callers", descriptors(callers.values()), "service_on_create_consumer", serviceCreate,
                "supplier_candidates", suppliers);
    }

    private static Object discover(DexKitBridge bridge, String key) {
        List<Object> matches = new ArrayList<>();
        for (MethodData literal : bridge.findMethod(FindMethod.create().matcher(
                MethodMatcher.create().usingEqStrings(key)))) {
            List<Object> getters = new ArrayList<>();
            // A key may occur inside a getter, or in its one-level builder.
            if (booleanGetter(literal)) getters.add(getter(literal));
            for (MethodData caller : literal.getCallers()) {
                if (booleanGetter(caller)) getters.add(getter(caller));
            }
            matches.add(obj("literal_method", describe(literal), "getters", getters,
                    "namespace_graph_evidence", namespaceEvidence(literal.getDeclaredClass())));
        }
        return obj("key", key, "literal_match_count", matches.size(), "matches", matches);
    }

    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?, ?>) {
            List<String> entries = new ArrayList<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet())
                entries.add(json(entry.getKey().toString()) + ":" + json(entry.getValue()));
            return "{" + String.join(",", entries) + "}";
        }
        if (value instanceof Collection<?>) {
            List<String> entries = new ArrayList<>();
            for (Object item : (Collection<?>) value) entries.add(json(item));
            return "[" + String.join(",", entries) + "]";
        }
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toString().toCharArray()) {
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 32) out.append(String.format("\\u%04x", (int) c));
            else out.append(c);
        }
        return out.append('"').toString();
    }

    public static void main(String[] args) {
        if (args.length != 2) throw new IllegalArgumentException("native-library apk-or-dex-zip");
        System.load(args[0]);
        long start = System.nanoTime();
        try (DexKitBridge bridge = DexKitBridge.create(args[1])) {
            bridge.setThreadNum(4);
            long opened = System.nanoTime();
            List<Object> keys = new ArrayList<>();
            for (String key : KEYS) keys.add(discover(bridge, key));
            System.out.println(json(obj("schema", 1, "report_only", true,
                    "dex_count", bridge.getDexNum(), "bridge_open_ms", (opened - start) / 1_000_000,
                    "query_ms", (System.nanoTime() - opened) / 1_000_000,
                    "keys", keys, "limitations", Arrays.asList(
                            "No GMS class loading, hook installation or code execution",
                            "Call graph and namespace reachability do not prove operand flow or receiver identity",
                            "Not an automatically approved hook profile"))));
        }
    }
}
