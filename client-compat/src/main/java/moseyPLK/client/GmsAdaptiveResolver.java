package moseyPLK.client;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.MethodData;

/** Bounded Phenotype getter resolver. Target classes are bytes only, never loaded or invoked. */
public final class GmsAdaptiveResolver {
    static final String SERVICE = "Lcom/google/android/gms/nearby/sharing/NearbySharingChimeraService;";
    static final String NAMESPACE = "com.google.android.gms.nearby";
    static final String BOX = "Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;";
    static final String UNBOX = "Ljava/lang/Boolean;->booleanValue()Z";
    // Covers only the flag's identity and local read/cache implementation.
    static final int MAX_METHODS = 80, MAX_DEPTH = 6;

    public static final class Rejected extends Exception implements GmsResolutionFailure.Classified {
        private static final long serialVersionUID = 1L;
        public final String reason;
        private final String stage;
        Rejected(String reason) { this("discovery",reason); }
        Rejected(String stage,String reason) { super(stage+":"+reason); this.stage=stage;this.reason=reason; }
        public String stage(){return stage;}
        public String reason(){return reason;}
        Rejected(String reason, Throwable cause) { super(reason, cause); this.stage="discovery";this.reason = reason; }
    }

    private GmsAdaptiveResolver() {}

    /** The lifecycle owner loads the module's verified DexKit library first. */
    public static ResolvedGateSet resolve(File baseApk) throws Exception {
        try (DexKitBridge bridge = DexKitBridge.create(baseApk.getPath());
                GmsDexFile dex = GmsDexFile.readApk(baseApk)) {
            bridge.setThreadNum(2);
            Graph graph = inspect(bridge, dex);
            return GmsGateVerifier.approve(graph);
        } catch (Rejected rejection) {
            throw rejection;
        } catch (Exception failure) {
            throw new Rejected("static_resolution_failed: " + failure.getClass().getSimpleName(), failure);
        }
    }

    static final class Gate {
        final MethodData factory, getter;
        final List<String> contracts;
        Gate(MethodData factory, MethodData getter, List<String> contracts) {
            this.factory = factory; this.getter = getter; this.contracts = contracts;
        }
    }

    /** Only primitive descriptors and decoded DEX data survive the bridge lifetime. */
    static final class Graph {
        final GmsDexFile dex;
        final LinkedHashMap<String, GmsDexFile.Method> methods = new LinkedHashMap<>();
        final LinkedHashMap<String, String> identities = new LinkedHashMap<>();
        final Set<String> decoded = new LinkedHashSet<>();
        final Set<String> proofs = new LinkedHashSet<>();
        String getter, supplier, secondary, expression;
        int totalCodeUnits;
        Graph(GmsDexFile dex) { this.dex = dex; }
        GmsDexFile.Method add(String role, String descriptor) throws Exception {
            GmsDexFile.Method method = dex.findMethod(descriptor);
            require(method != null, "missing_method:" + role);
            GmsDexFile.Method previous = methods.put(role, method);
            require(previous == null || previous == method, "conflicting_role:" + role);
            require(new LinkedHashSet<>(methods.values()).size() <= MAX_METHODS, "method_budget_exceeded");
            // Decode now: unsupported opcodes/handlers must reject before approval.
            decode(method);
            return method;
        }
        GmsDexFile.Code decode(GmsDexFile.Method method) throws Exception {
            boolean fresh=decoded.add(method.descriptor);
            require(decoded.size() <= MAX_METHODS, "method_budget_exceeded");
            GmsDexFile.Code code=method.code();
            if(fresh && code!=null)totalCodeUnits+=code.units;
            require(totalCodeUnits<=32768,"total_code_unit_budget_exceeded");
            return code;
        }
        void identity(String role, String descriptor) throws Rejected {
            String before = identities.put(role, descriptor);
            require(before == null || before.equals(descriptor), "conflicting_identity:" + role);
        }
    }

    static Graph inspect(DexKitBridge bridge, GmsDexFile dex) throws Exception {
        Graph discovery=new Graph(dex);
        List<Gate> primary=discover(bridge,discovery,"45704091");
        List<Graph> accepted=new ArrayList<>();Rejected last=null;
        for(Gate gate:primary){
            try {accepted.add(inspectCandidate(dex,gate));}
            catch(Rejected failure){last=failure;}
        }
        // The hook owns the keyed getter, not its callers. Consumer changes,
        // secondary flags and service wiring do not affect this proof. Never
        // choose between distinct valid getters by discovery/list order.
        LinkedHashMap<String,Graph> unique=new LinkedHashMap<>();
        for(Graph candidate:accepted)unique.put(candidate.getter,candidate);
        if(unique.isEmpty()&&last!=null)throw last;
        require(unique.size()==1,"phenotype_getter_candidates="+unique.size());
        return unique.values().iterator().next();
    }
    private static Graph inspectCandidate(GmsDexFile dex,Gate gate)throws Exception {
        Graph graph=new Graph(dex);
        graph.getter = gate.getter.getDescriptor();
        graph.expression = "A";
        try { GmsFlagProof.verify(graph,gate,"A","45704091"); }
        catch(Rejected failure){throw new Rejected("flag",failure.reason);}
        return graph;
    }

    private static List<Gate> discover(DexKitBridge bridge, Graph graph, String key) throws Exception {
        List<Gate> matches = new ArrayList<>();
        List<MethodData> literals = bridge.findMethod(FindMethod.create().matcher(MethodMatcher.create().usingEqStrings(key)));
        require(literals.size() <= 8, "literal_candidate_budget");
        for (MethodData factory : literals) {
            // Namespace reachability is only candidate filtering; the complete
            // constructor/field/operand chain is checked below and fingerprinted.
            if (!nearbyNamespace(graph, owner(factory.getDescriptor()))) continue;
            for (MethodData getter : factory.getCallers()) {
                if (getter.getParamCount() != 0 || !getter.getReturnTypeName().equals("boolean") || isStatic(getter)) continue;
                List<String> contracts = new ArrayList<>();
                contracts.add(getter.getDescriptor());
                // The concrete boolean getter is the hook target. Its caller
                // interfaces are irrelevant to key identity and remain outside
                // the proof, so adding or renaming one cannot block admission.
                matches.add(new Gate(factory, getter, contracts));
            }
        }
        require(matches.size()<=16,"getter_candidate_budget");
        require(!matches.isEmpty(),"getter_candidates_"+key+"="+matches.size());
        return matches;
    }

    private static boolean nearbyNamespace(Graph graph, String getterOwner) throws Exception {
        GmsDexFile.Method init = graph.dex.findMethod(getterOwner + "-><clinit>()V");
        if (init == null || graph.decode(init) == null) return false;
        int examined = 0;
        for (GmsDexFile.Instruction ins : init.code().instructions) if (ins.opname.equals("sget-object")) {
            if (++examined > 8) throw new Rejected("namespace_candidate_budget");
            GmsDexFile.Method next = graph.dex.findMethod(owner(ins.reference) + "-><clinit>()V");
            if (next != null && graph.decode(next) != null) for (GmsDexFile.Instruction item : next.code().instructions)
                if (item.opname.startsWith("const-string") && NAMESPACE.equals(item.reference)) return true;
        }
        return false;
    }

    static boolean writesFirst(GmsDexFile.Instruction x) {
        String n=x.opname;
        return x.registers.length>0 && !(n.startsWith("invoke")||n.startsWith("if-")||n.startsWith("goto")
                ||n.startsWith("return")||n.startsWith("iput")||n.startsWith("sput")||n.startsWith("aput")
                ||n.startsWith("monitor")||n.equals("throw")||n.contains("switch")||n.startsWith("fill"));
    }
    static boolean readsDestination(GmsDexFile.Instruction x) {
        return x.opname.equals("check-cast") || x.opname.endsWith("/2addr");
    }
    static int thisRegister(GmsDexFile.Method method) throws Exception {return code(method).registersSize-code(method).insSize;}
    static List<GmsDexFile.Instruction> ops(GmsDexFile.Method method,String...expected) throws Exception {
        List<GmsDexFile.Instruction> actual=code(method).instructions;
        require(code(method).triesSize==0 && actual.size()==expected.length, "shape:"+method.descriptor);
        for(int i=0;i<expected.length;i++) require(normalOp(actual.get(i).opname).equals(expected[i]), "opcode_shape:"+method.descriptor);
        return actual;
    }
    static String normalOp(String value) {
        if(value.equals("const/4")||value.equals("const/16")||value.equals("const/high16"))return "const";
        if(value.equals("const-string/jumbo"))return "const-string";
        if(value.endsWith("/range"))return value.substring(0,value.length()-6);
        if(value.endsWith("/from16"))return value.substring(0,value.length()-7);
        if(value.endsWith("/16") && (value.startsWith("move")||value.startsWith("goto")))return value.substring(0,value.length()-3);
        if(value.equals("goto/32"))return "goto";
        return value;
    }
    static GmsDexFile.Code code(GmsDexFile.Method m) throws Exception {GmsDexFile.Code c=m.code();require(c!=null,"missing_code:"+m.descriptor);return c;}
    static GmsDexFile.Field field(GmsDexFile dex,String descriptor) throws Exception {
        GmsDexFile.ClassDef c=dex.findClass(owner(descriptor)); require(c!=null,"missing_field_owner");
        for(GmsDexFile.Field f:c.fields)if(f.descriptor.equals(descriptor))return f;
        throw new Rejected("missing_field");
    }
    static Set<String> descriptors(Collection<MethodData> methods) {Set<String> result=new LinkedHashSet<>();for(MethodData method:methods)result.add(method.getDescriptor());return result;}
    static boolean isStatic(MethodData method) {return (method.getModifiers()&8)!=0;}
    static boolean regs(GmsDexFile.Instruction x,int...values) {return Arrays.equals(x.registers,values);}
    static int r(List<GmsDexFile.Instruction> xs,int i) {return xs.get(i).registers[0];}
    static String owner(String descriptor) {return descriptor.substring(0,descriptor.indexOf("->"));}
    static String suffix(String descriptor) {return descriptor.substring(descriptor.indexOf("->")+2);}
    static String fieldType(String descriptor) {return descriptor.substring(descriptor.indexOf(':')+1);}
    static String returnType(String descriptor) {return descriptor.substring(descriptor.indexOf(')')+1);}
    static void require(boolean value,String reason) throws Rejected {if(!value)throw new Rejected(reason);}
}
