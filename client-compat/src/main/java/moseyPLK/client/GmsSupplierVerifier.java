package moseyPLK.client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Bounded local expression proof, conditional on separately verified role identities.
 * This does NOT establish getter/namespace semantics, receiver dispatch, downstream
 * consumers, runtime provenance or general side-effect equivalence of an override.
 */
public final class GmsSupplierVerifier {
    private GmsSupplierVerifier() {}
    public enum Classification { PURE_A, A_OR_B, UNSUPPORTED }
    public static final String BOX="Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;";
    private static final String TRUE="Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;";
    private static final String FALSE="Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;";
    public static final class Roles {
        public final Set<String> aGetters,bGetters,receiverAccessors,serviceInitFields,receiverFields;
        public Roles(Collection<String> a,Collection<String> b,Collection<String> accessors,
                     Collection<String> initFields,Collection<String> roots) {
            aGetters=copy(a);bGetters=copy(b);receiverAccessors=copy(accessors);
            serviceInitFields=copy(initFields);receiverFields=copy(roots);
        }
        private static Set<String> copy(Collection<String> values) {
            return Collections.unmodifiableSet(new HashSet<>(values));
        }
    }
    public static final class Case {
        public final boolean a,b,result;
        public final List<String> getterTrace;
        public final int accessorCalls;
        Case(boolean a,boolean b,boolean result,List<String> trace,int count) {
            this.a=a;this.b=b;this.result=result;getterTrace=Collections.unmodifiableList(new ArrayList<>(trace));accessorCalls=count;
        }
    }
    public static final class Result {
        public final Classification classification;
        public final String reason;
        public final List<Case> cases;
        Result(Classification kind,String why,List<Case> values) {
            classification=kind;reason=why;cases=Collections.unmodifiableList(new ArrayList<>(values));
        }
        public boolean accepted() {return classification!=Classification.UNSUPPORTED;}
    }
    private static final class Reject extends Exception {
        private static final long serialVersionUID=1L;
        Reject(String reason){super(reason);}
    }
    private static final class Value {
        final String kind,type;final boolean bit;
        Value(String kind,String type,boolean bit){this.kind=kind;this.type=type;this.bit=bit;}
    }
    private static final Set<String> ALLOWED=new HashSet<>(Arrays.asList(
        "move","move/16","move/from16","move-object","move-object/16","move-object/from16",
        "const","const/4","const/16","const/high16","sget","sget-object","move-result","move-result-object",
        "invoke-virtual","invoke-virtual/range","invoke-interface","invoke-interface/range","invoke-static","invoke-static/range",
        "if-eqz","if-nez","if-eq","if-ne","check-cast","goto","goto/16","goto/32","nop","return-object"));

    public static Result verify(GmsDexFile.Method method,Roles roles) {
        List<Case> cases=new ArrayList<>();
        try {
            if(method==null||roles==null)throw new Reject("missing method or verified roles");
            if(!method.parameterTypes.isEmpty()||!"Ljava/lang/Object;".equals(method.returnType))
                throw new Reject("requires no-argument Object supplier");
            if((method.accessFlags&(0x8|0x20|0x20000))!=0)throw new Reject("static/synchronized supplier unsupported");
            GmsDexFile.Code code=method.code();
            if(code==null||code.triesSize!=0||!code.tryBlocks.isEmpty())throw new Reject("missing code or exception handlers");
            if(code.insSize!=1||code.registersSize<1)throw new Reject("inconsistent register frame");
            validateRoles(roles);
            Map<Integer,GmsDexFile.Instruction> graph=graph(code,roles);
            for(boolean a:new boolean[]{false,true})for(boolean b:new boolean[]{false,true})cases.add(execute(code,graph,roles,a,b));
            boolean pure=true,or=!roles.bGetters.isEmpty();
            for(Case c:cases){
                pure &= c.result==c.a&&c.getterTrace.equals(Collections.singletonList("A"));
                or &= c.result==(c.a||c.b)&&c.getterTrace.equals(c.a?Collections.singletonList("A"):Arrays.asList("A","B"));
            }
            if(pure)return new Result(Classification.PURE_A,"four inputs return boxed A with one A read",cases);
            if(or)return new Result(Classification.A_OR_B,"four inputs implement short-circuit A || B",cases);
            return new Result(Classification.UNSUPPORTED,"truth table or getter trace differs from supported expressions",cases);
        } catch(IOException|Reject|IllegalArgumentException|IndexOutOfBoundsException e) {
            return new Result(Classification.UNSUPPORTED,e.getMessage(),cases);
        }
    }
    private static void validateRoles(Roles r) throws Reject {
        if(r.aGetters.isEmpty())throw new Reject("missing verified A role");
        Set<String> seen=new HashSet<>();
        for(Set<String> calls:Arrays.asList(r.aGetters,r.bGetters,r.receiverAccessors))for(String ref:calls){
            if(ref==null||!seen.add(ref)||BOX.equals(ref))throw new Reject("overlapping call roles");
            String[] parts=method(ref);
            if(calls==r.receiverAccessors ? !object(parts[1]) : !"Z".equals(parts[1]))throw new Reject("role method type");
        }
        for(String ref:r.serviceInitFields)if(!"I".equals(field(ref)))throw new Reject("initialization field type");
        for(String ref:r.receiverFields)if(!object(field(ref)))throw new Reject("receiver field type");
    }
    private static boolean object(String type){return type!=null&&type.startsWith("L")&&type.endsWith(";")&&type.length()>2;}
    private static String[] method(String ref) throws Reject {
        int arrow=ref.indexOf("->"),args=ref.indexOf("()",arrow+2);
        if(arrow<1||args<=arrow+2||!object(ref.substring(0,arrow))||args+2>=ref.length())throw new Reject("invalid no-arg method role");
        return new String[]{ref.substring(0,arrow),ref.substring(args+2)};
    }
    private static String field(String ref) throws Reject {
        if(ref==null)throw new Reject("null field role");int arrow=ref.indexOf("->"),colon=ref.indexOf(':',arrow+2);
        if(arrow<1||colon<=arrow+2||!object(ref.substring(0,arrow))||colon+1>=ref.length())throw new Reject("invalid field role");
        return ref.substring(colon+1);
    }
    private static Map<Integer,GmsDexFile.Instruction> graph(GmsDexFile.Code code,Roles roles) throws Reject {
        if(code.instructions.isEmpty()||code.instructions.size()>128)throw new Reject("supplier instruction bound");
        Map<Integer,GmsDexFile.Instruction> graph=new LinkedHashMap<>();int next=0;
        Set<String> calls=new HashSet<>(roles.aGetters);calls.addAll(roles.bGetters);calls.addAll(roles.receiverAccessors);calls.add(BOX);
        for(GmsDexFile.Instruction i:code.instructions){
            if(!ALLOWED.contains(i.opname)||i.pc!=next||i.width<=0)throw new Reject("unsupported opcode/boundary: "+i.opname);
            for(int r:i.registers)if(r<0||r>=code.registersSize)throw new Reject("register outside frame");
            if(i.opname.startsWith("invoke-")&&!calls.contains(i.reference))throw new Reject("unapproved invocation");
            if("sget".equals(i.opname)&&!roles.serviceInitFields.contains(i.reference))throw new Reject("unapproved init read");
            if("sget-object".equals(i.opname)&&!roles.receiverFields.contains(i.reference)
                    &&!TRUE.equals(i.reference)&&!FALSE.equals(i.reference))throw new Reject("unapproved root read");
            next+=i.width;graph.put(i.pc,i);
        }
        if(next!=code.units)throw new Reject("code unit length mismatch");
        Set<Integer> visiting=new HashSet<>(),visited=new HashSet<>();walk(0,graph,visiting,visited);
        if(visited.size()!=graph.size())throw new Reject("unreachable instructions");return graph;
    }
    private static void walk(int pc,Map<Integer,GmsDexFile.Instruction> graph,Set<Integer> visiting,Set<Integer> visited) throws Reject {
        if(visiting.contains(pc))throw new Reject("control-flow cycle");if(visited.contains(pc))return;
        GmsDexFile.Instruction i=graph.get(pc);if(i==null)throw new Reject("branch/fallthrough is not an instruction boundary");
        visiting.add(pc);
        if(i.opname.startsWith("goto"))walk(i.target,graph,visiting,visited);
        else if(i.opname.startsWith("if-")){walk(i.target,graph,visiting,visited);walk(i.pc+i.width,graph,visiting,visited);}
        else if(!"return-object".equals(i.opname))walk(i.pc+i.width,graph,visiting,visited);
        visiting.remove(pc);visited.add(pc);
    }
    private static void arity(GmsDexFile.Instruction i,int count) throws Reject {if(i.registers.length!=count)throw new Reject("register arity");}
    private static Value read(Map<Integer,Value> regs,int r) throws Reject {Value v=regs.get(r);if(v==null)throw new Reject("undefined register");return v;}
    private static Case execute(GmsDexFile.Code code,Map<Integer,GmsDexFile.Instruction> graph,Roles roles,boolean a,boolean b) throws Reject {
        Map<Integer,Value> regs=new HashMap<>();regs.put(code.registersSize-1,new Value("this","",false));
        Value pending=null;List<String> trace=new ArrayList<>();int pc=0,accessCount=0;
        for(int step=0;step<128;step++){
            GmsDexFile.Instruction i=graph.get(pc);if(i==null)throw new Reject("invalid execution target");
            String op=i.opname;int[] rs=i.registers;int next=i.pc+i.width;
            if(pending!=null&&!op.equals("move-result")&&!op.equals("move-result-object"))throw new Reject("invocation result not immediately consumed");
            if(op.equals("sget")||op.equals("sget-object")){
                arity(i,1);
                if(TRUE.equals(i.reference)||FALSE.equals(i.reference))
                    regs.put(rs[0],new Value("boxed","Ljava/lang/Boolean;",TRUE.equals(i.reference)));
                else regs.put(rs[0],new Value(op.equals("sget")?"init":"root",field(i.reference),false));
            }else if(op.startsWith("move-result")){
                arity(i,1);if(pending==null||pending.kind.equals("bool")!=op.equals("move-result"))throw new Reject("move-result kind or missing invocation");
                regs.put(rs[0],pending);pending=null;
            }else if(op.startsWith("move")){
                arity(i,2);Value v=read(regs,rs[1]);boolean obj=v.kind.equals("root")||v.kind.equals("receiver")||v.kind.equals("boxed")||v.kind.equals("this");
                if(obj!=op.startsWith("move-object"))throw new Reject("move kind mismatch");regs.put(rs[0],v);
            }else if(op.startsWith("const")){
                arity(i,1);if(i.literal!=0&&i.literal!=1)throw new Reject("non Boolean constant");regs.put(rs[0],new Value("bool","Z",i.literal==1));
            }else if(op.equals("check-cast")){
                arity(i,1);Value value=read(regs,rs[0]);
                // A cast must not invent a different receiver identity. Keep the
                // already proved concrete type through an Object upcast.
                if(!(value.kind.equals("root")||value.kind.equals("receiver")||value.kind.equals("boxed"))
                        ||!(value.type.equals(i.reference)||"Ljava/lang/Object;".equals(i.reference)))
                    throw new Reject("cast changes verified receiver type");
            }else if(op.startsWith("invoke-")){
                arity(i,1);Value receiver=read(regs,rs[0]);
                if(BOX.equals(i.reference)){
                    if(!op.startsWith("invoke-static")||!receiver.kind.equals("bool"))throw new Reject("boxing wrong operand");
                    pending=new Value("boxed","Ljava/lang/Boolean;",receiver.bit);
                }else{
                    if(op.startsWith("invoke-static"))throw new Reject("instance getter/accessor required");String[] parts=method(i.reference);
                    if(!(receiver.kind.equals("root")||receiver.kind.equals("receiver"))||!receiver.type.equals(parts[0]))throw new Reject("receiver does not flow from verified owner");
                    if(roles.receiverAccessors.contains(i.reference)){pending=new Value("receiver",parts[1],false);accessCount++;}
                    else {boolean isA=roles.aGetters.contains(i.reference);trace.add(isA?"A":"B");pending=new Value("bool","Z",isA?a:b);}
                }
            }else if(op.startsWith("if-")){
                boolean paired=op.equals("if-eq")||op.equals("if-ne");
                arity(i,paired?2:1);Value condition=read(regs,rs[0]);if(!condition.kind.equals("bool"))throw new Reject("branch on unverified Boolean");
                boolean equal;
                if(paired){
                    Value other=read(regs,rs[1]);
                    if(!other.kind.equals("bool"))throw new Reject("branch on unverified Boolean");
                    equal=condition.bit==other.bit;
                }else equal=!condition.bit;
                if((op.equals("if-eq")||op.equals("if-eqz"))==equal)next=i.target;
            }else if(op.startsWith("goto")){arity(i,0);next=i.target;
            }else if(op.equals("return-object")){
                arity(i,1);Value v=read(regs,rs[0]);if(!v.kind.equals("boxed"))throw new Reject("return is not verified boxing result");
                // Each getter operand was checked against its proved receiver.
                // Reusing that immutable receiver does not require another
                // accessor call for every getter invocation.
                return new Case(a,b,v.bit,trace,accessCount);
            }else if(op.equals("nop"))arity(i,0);
            pc=next;
        }
        throw new Reject("execution instruction bound");
    }
}
