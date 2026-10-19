package moseyPLK.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Phenotype proof receipts; the digest records evidence, never grants admission. */
final class GmsGateVerifier {
    private static final Pattern OBJECT = Pattern.compile("L[^;]+;");

    private GmsGateVerifier() {}

    static ResolvedGateSet approve(GmsAdaptiveResolver.Graph graph) throws Exception {
        String digest = digest(receipt(graph));
        GmsAdaptiveResolver.require(graph.proofs.contains("AFlag"),"missing_semantic_proof:AFlag");
        GmsAdaptiveResolver.require("A".equals(graph.expression)&&graph.supplier==null&&graph.secondary==null,
                "unexpected_phenotype_target");
        return ResolvedGateSet.phenotype(graph.getter,digest);
    }

    /** A receipt is descriptive only: incidental instruction layouts never grant or deny admission. */
    static String receipt(GmsAdaptiveResolver.Graph graph)throws Exception {
        StringBuilder out=new StringBuilder("mosey-phenotype-receipt-v3\n").append(graph.expression).append('\n');
        out.append(graph.proofs).append('\n').append(graph.identities).append('\n');
        for(Map.Entry<String,GmsDexFile.Method> role:graph.methods.entrySet()){
            GmsDexFile.Method method=role.getValue();out.append(role.getKey()).append('=').append(method.descriptor).append(':').append(method.accessFlags).append('\n');
            GmsDexFile.Code code=method.code();if(code==null)continue;
            for(GmsDexFile.Instruction x:code.instructions)out.append(x.pc).append(':').append(x.opname).append(Arrays.toString(x.registers)).append(':').append(x.literal).append(':').append(x.reference).append(':').append(x.target).append(Arrays.toString(x.targets)).append(Arrays.toString(x.payloadWords)).append('\n');
            for(GmsDexFile.TryBlock block:code.tryBlocks){out.append("try ").append(block.start).append(':').append(block.end);for(GmsDexFile.Handler h:block.handlers)out.append(':').append(h.type).append('@').append(h.target);out.append('\n');}
        }return out.toString();
    }

    static String digest(String evidence) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(evidence.getBytes(StandardCharsets.UTF_8));
        StringBuilder result = new StringBuilder();
        for (byte value : hash) result.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return result.toString();
    }

    static String evidence(GmsAdaptiveResolver.Graph graph) throws Exception {
        Canonical names = new Canonical(graph);
        StringBuilder text = new StringBuilder("mosey-phenotype-semantic-v3\n").append(graph.expression).append('\n');
        // Seed identities by semantic role, before incidental instruction order.
        for (Map.Entry<String,GmsDexFile.Method> role : graph.methods.entrySet())
            text.append(role.getKey()).append('=').append(names.reference(role.getValue().descriptor)).append('\n');
        for (Map.Entry<String,String> role : graph.identities.entrySet())
            text.append(role.getKey()).append('=').append(names.reference(role.getValue())).append('\n');
        for (Map.Entry<String,GmsDexFile.Method> role : graph.methods.entrySet()) {
            text.append("METHOD ").append(role.getKey()).append('\n');
            appendMethod(text,names,role.getValue());
        }
        return text.toString();
    }

    static String boundaryCounts(GmsAdaptiveResolver.Graph graph) throws Exception {
        Canonical names=new Canonical(graph);
        StringBuilder ignored=new StringBuilder();
        for(GmsDexFile.Method method:graph.methods.values())appendMethod(ignored,names,method);
        return "reviewed_types="+names.reviewedTypes.size()+" reviewed_methods="+names.reviewedMethods.size()
                +" reviewed_fields="+names.reviewedFields.size()+" opaque_types="+names.opaqueTypes.size()
                +" opaque_methods="+names.opaqueMethods.size()+" opaque_fields="+names.opaqueFields.size()
                +" renamed_type_slots="+names.types.size()+" renamed_method_slots="+names.methods.size()
                +" renamed_field_slots="+names.fields.size();
    }

    static String standaloneMethod(GmsDexFile.Method method) throws Exception {
        StringBuilder result=new StringBuilder();
        appendMethod(result,new Canonical(method),method);
        return result.toString();
    }

    private static void appendMethod(StringBuilder out,Canonical names,GmsDexFile.Method method) throws Exception {
        out.append(names.reference(method.descriptor)).append(" flags=").append(method.accessFlags).append('\n');
        if(names.dex!=null) {
            GmsDexFile.ClassDef owner=names.dex.findClass(method.owner);
            out.append("owner=").append(owner.accessFlags).append(' ').append(names.types(owner.superclass)).append(" interfaces=");
            List<String> interfaces=new ArrayList<>();
            for(String type:owner.interfaces)interfaces.add(names.types(type));
            java.util.Collections.sort(interfaces);
            out.append(interfaces).append('\n');
        }
        GmsDexFile.Code code=method.code();
        if(code==null){out.append("abstract\n");return;}
        Map<Integer,Integer> positions=new LinkedHashMap<>();
        for(int i=0;i<code.instructions.size();i++)positions.put(code.instructions.get(i).pc,i);
        positions.put(code.units,code.instructions.size());
        RegisterNames registers=new RegisterNames(code.registersSize-code.insSize,code.registersSize);
        for(GmsDexFile.Instruction instruction:code.instructions) {
            out.append(GmsAdaptiveResolver.normalOp(instruction.opname)).append(' ');
            boolean writes=GmsAdaptiveResolver.writesFirst(instruction);
            // Preserve parameter identities and every local-slot alias.
            for(int i=writes?1:0;i<instruction.registers.length;i++) {
                registers.read(instruction.registers[i]);
                if(wideOperand(instruction.opname,i))registers.read(instruction.registers[i]+1);
            }
            if(writes && GmsAdaptiveResolver.readsDestination(instruction)) {
                registers.read(instruction.registers[0]);
                if(wideOperand(instruction.opname,0))registers.read(instruction.registers[0]+1);
            }
            if(writes)registers.write(instruction.registers[0]);
            if(writes && wideOperand(instruction.opname,0))registers.write(instruction.registers[0]+1);
            for(int i=0;i<instruction.registers.length;i++) {
                int register=instruction.registers[i];out.append(registers.name(register));
                if(wideOperand(instruction.opname,i))out.append('{').append(registers.name(register+1)).append('}');
                out.append(',');
            }
            out.append(" lit=").append(instruction.literal);
            if(instruction.reference!=null) {
                String ref=instruction.opname.startsWith("const-string") ? "STR:"+instruction.reference : names.reference(instruction.reference);
                out.append(" ref[").append(ref.length()).append("]=").append(ref);
            }
            if(instruction.target>=0)out.append(" target=").append(position(positions,instruction.target));
            if(instruction.targets.length>0) {
                out.append(" cases=");
                for(int target:instruction.targets)out.append(position(positions,target)).append(',');
            }
            if(instruction.payloadWords.length>0) {
                int[] words=instruction.payloadWords;
                // Switch displacements are already represented as instruction
                // ordinals above. Preserve every switch key and array data byte.
                int count=instruction.opcode==0x100 ? 4 : instruction.opcode==0x200 ? 2+2*words[1] : words.length;
                out.append(" payload=").append(Arrays.toString(Arrays.copyOf(words,count)));
            }
            out.append('\n');
        }
        for(GmsDexFile.TryBlock block:code.tryBlocks) {
            out.append("try ").append(position(positions,block.start)).append(':').append(position(positions,block.end));
            for(GmsDexFile.Handler handler:block.handlers)
                out.append(' ').append(handler.type==null?"all":names.types(handler.type)).append('@').append(position(positions,handler.target));
            out.append('\n');
        }
    }

    private static boolean wideOperand(String op,int index) {
        if(op.startsWith("invoke-"))return false; // invoke operands explicitly list both words
        if(op.contains("wide")) {
            if(op.startsWith("move-wide"))return true;
            return index==0; // wide field/array values, returns and constants
        }
        if(op.startsWith("cmp"))return index>0 && (op.endsWith("-long")||op.endsWith("-double"));
        int conversion=op.indexOf("-to-");
        if(conversion>=0) {
            String from=op.substring(0,conversion),to=op.substring(conversion+4);
            return index==0 ? to.equals("long")||to.equals("double") : from.equals("long")||from.equals("double");
        }
        boolean wide=op.endsWith("-long")||op.endsWith("-double")||op.endsWith("-long/2addr")||op.endsWith("-double/2addr");
        if(!wide)return false;
        if(op.startsWith("shl-")||op.startsWith("shr-")||op.startsWith("ushr-"))return index < (op.endsWith("/2addr")?1:2);
        return true;
    }

    private static int position(Map<Integer,Integer> positions,int pc) throws GmsAdaptiveResolver.Rejected {
        Integer result=positions.get(pc);
        GmsAdaptiveResolver.require(result!=null,"invalid_normalized_control_flow_target");
        return result;
    }

    private static final class RegisterNames {
        final Map<Integer,String> names=new LinkedHashMap<>();
        final int parameters,end;
        int locals;
        RegisterNames(int parameters,int end){
            this.parameters=parameters;this.end=end;
            // Incoming slots always keep their parameter identity, including
            // writes before the first textual read: a branch may skip that write.
            for(int register=parameters;register<end;register++)names.put(register,"P"+(register-parameters));
        }
        void read(int register) throws GmsAdaptiveResolver.Rejected {
            if(names.containsKey(register))return;
            GmsAdaptiveResolver.require(register>=parameters && register<end,"read_before_definition");
            names.put(register,"P"+(register-parameters));
        }
        void write(int register) throws GmsAdaptiveResolver.Rejected {
            GmsAdaptiveResolver.require(register>=0 && register<end,"invalid_normalized_register");
            if(!names.containsKey(register))names.put(register,"R"+(locals++));
        }
        String name(int register) throws GmsAdaptiveResolver.Rejected {
            read(register);return names.get(register);
        }
    }

    private static final class Canonical {
        final GmsDexFile dex;
        final java.util.Set<String> reviewedTypes=new java.util.LinkedHashSet<>(),reviewedMethods=new java.util.LinkedHashSet<>(),reviewedFields=new java.util.LinkedHashSet<>();
        final java.util.Set<String> opaqueTypes=new java.util.LinkedHashSet<>(),opaqueMethods=new java.util.LinkedHashSet<>(),opaqueFields=new java.util.LinkedHashSet<>();
        final Map<String,String> types=new LinkedHashMap<>(),methods=new LinkedHashMap<>(),fields=new LinkedHashMap<>();
        Canonical(GmsAdaptiveResolver.Graph graph){
            dex=graph.dex;
            for(GmsDexFile.Method method:graph.methods.values()) {
                reviewedMethods.add(method.descriptor);reviewedTypes.add(method.owner);
            }
            for(String reference:graph.identities.values()) if(reference.contains("->")&&reference.contains(":")) {
                reviewedFields.add(reference);reviewedTypes.add(GmsAdaptiveResolver.owner(reference));
            }
        }
        Canonical(GmsDexFile.Method method){
            dex=null;reviewedTypes.add(method.owner);reviewedMethods.add(method.descriptor);
        }
        boolean fixed(String type) {
            return type.startsWith("Ljava/")||type.startsWith("Ljavax/")||type.startsWith("Landroid/")
                    ||type.startsWith("Lj$/")||type.startsWith("Ldagger/")||type.equals(GmsAdaptiveResolver.SERVICE);
        }
        // Role IDs inhabit a tagged namespace distinct from every literal DEX
        // name. Length framing also prevents delimiter-containing raw names
        // from impersonating an encoded component.
        static String component(String kind,String value) {
            return kind+"("+value.length()+":"+value+")";
        }
        String type(String type) {
            if(fixed(type))return component("TYPE_FIXED",type);
            if(!reviewedTypes.contains(type)){opaqueTypes.add(type);return component("TYPE_OPAQUE",type);}
            if(!types.containsKey(type))types.put(type,Integer.toString(types.size()));
            return component("TYPE_ROLE",types.get(type));
        }
        String types(String descriptor) {
            if(descriptor==null)return "null";
            Matcher matcher=OBJECT.matcher(descriptor);StringBuffer out=new StringBuffer();
            while(matcher.find())matcher.appendReplacement(out,Matcher.quoteReplacement(type(matcher.group())));
            matcher.appendTail(out);return out.toString();
        }
        String reference(String reference) throws Exception {
            int arrow=reference.indexOf("->");
            if(arrow<0)return types(reference);
            String owner=reference.substring(0,arrow),tail=reference.substring(arrow+2),normalOwner=type(owner);
            int params=tail.indexOf('(');
            if(params>=0) {
                String name=tail.substring(0,params),normalName;
                if(name.startsWith("<") || fixed(owner) && !owner.equals(GmsAdaptiveResolver.SERVICE)
                        || owner.equals(GmsAdaptiveResolver.SERVICE) && name.equals("onCreate"))normalName=component("METHOD_FIXED",name);
                else if(!reviewedMethods.contains(reference)){opaqueMethods.add(reference);normalName=component("METHOD_OPAQUE",name);}
                else {if(!methods.containsKey(reference))methods.put(reference,Integer.toString(methods.size()));normalName=component("METHOD_ROLE",methods.get(reference));}
                return normalOwner+"->"+normalName+types(tail.substring(params));
            }
            int colon=tail.indexOf(':');
            GmsAdaptiveResolver.require(colon>0,"malformed_reference");
            String name=tail.substring(0,colon),normalName;
            if(fixed(owner)&&!owner.equals(GmsAdaptiveResolver.SERVICE))normalName=component("FIELD_FIXED",name);
            else if(!reviewedFields.contains(reference)){opaqueFields.add(reference);normalName=component("FIELD_OPAQUE",name);}
            else {if(!fields.containsKey(reference))fields.put(reference,Integer.toString(fields.size()));normalName=component("FIELD_ROLE",fields.get(reference));}
            String result=normalOwner+"->"+normalName+":"+types(tail.substring(colon+1));
            if(dex!=null && dex.findClass(owner)!=null)result+="#"+GmsAdaptiveResolver.field(dex,reference).accessFlags;
            return result;
        }
    }
}
