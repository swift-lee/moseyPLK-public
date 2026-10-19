package moseyPLK.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Collision regressions for register/branch identity in reviewed templates. */
public final class GmsGateVerifierTest {
    private static int assertions;
    private static GmsDexFile.Instruction ins(int pc,int op,int[] rs,String ref,int target) {
        return new GmsDexFile.Instruction(pc,op,1,rs,0,ref,target,new int[0],new int[0]);
    }
    private static GmsDexFile.Method method(String owner,String name,List<String> params,int registers,
            int incoming,List<GmsDexFile.Instruction> instructions) {
        return new GmsDexFile.Method(owner,name,"Ljava/lang/Object;",params,8,
                new GmsDexFile.Code(registers,incoming,4,0,instructions.size(),instructions,
                        Collections.<GmsDexFile.TryBlock>emptyList()));
    }
    private static GmsDexFile.Method receiver(int first,int second,int output,boolean wrongReceiver,boolean wrongReturn) {
        List<GmsDexFile.Instruction> xs=new ArrayList<>();
        xs.add(ins(0,0x22,new int[]{first},"LThing;",-1));
        xs.add(ins(1,0x70,new int[]{first},"LThing;-><init>()V",-1));
        xs.add(ins(2,0x22,new int[]{second},"LThing;",-1));
        xs.add(ins(3,0x70,new int[]{second},"LThing;-><init>()V",-1));
        xs.add(ins(4,0x6e,new int[]{wrongReceiver?second:first},"LThing;->get()Ljava/lang/Object;",-1));
        xs.add(ins(5,0x0c,new int[]{output},null,-1));
        xs.add(ins(6,0x11,new int[]{wrongReturn?second:output},null,-1));
        return method("LTest;","f",Collections.<String>emptyList(),4,0,xs);
    }
    private static GmsDexFile.Method skippedParameterWrite(int written,int returned) {
        return method("LTest;","f",Arrays.asList("Z","Ljava/lang/Object;","Ljava/lang/Object;"),3,3,Arrays.asList(
                ins(0,0x38,new int[]{0},null,2),
                ins(1,0x12,new int[]{written},null,-1),
                ins(2,0x11,new int[]{returned},null,-1)));
    }
    private static void check(boolean condition,String label) {
        assertions++;
        if(!condition)throw new AssertionError(label);
    }
    private static String normalized(GmsDexFile.Method method) throws Exception {
        return GmsGateVerifier.standaloneMethod(method);
    }
    private static GmsDexFile.Method wide(int highWord) {
        return method("LTest;","f",Collections.<String>emptyList(),4,0,Arrays.asList(
                ins(0,0x16,new int[]{0},null,-1),
                ins(1,0x12,new int[]{highWord},null,-1),
                ins(2,0x10,new int[]{0},null,-1)));
    }
    private static String symbolEvidence(int opcode,String reference) throws Exception {
        List<GmsDexFile.Instruction> instructions=new ArrayList<>();
        instructions.add(ins(0,opcode,opcode==0x71?new int[0]:new int[]{0},reference,-1));
        if(opcode==0x71)instructions.add(ins(1,0x0c,new int[]{0},null,-1));
        instructions.add(ins(instructions.size(),0x11,new int[]{0},null,-1));
        GmsDexFile.Method selected=method("LFoo;","reviewedMethod",Collections.<String>emptyList(),1,0,instructions);
        GmsAdaptiveResolver.Graph graph=new GmsAdaptiveResolver.Graph(null);
        graph.expression="A";
        graph.methods.put("tested",selected);
        graph.identities.put("reviewedField","LFoo;->reviewedField:Ljava/lang/Object;");
        return GmsGateVerifier.evidence(graph);
    }
    public static void main(String[] args) throws Exception {
        String baseline=normalized(receiver(0,1,2,false,false));
        check(baseline.equals(normalized(receiver(3,0,1,false,false))),"local register bijection survives");
        check(!baseline.equals(normalized(receiver(0,1,2,true,false))),"different receiver rejected");
        check(!baseline.equals(normalized(receiver(0,1,2,false,true))),"different returned register rejected");
        check(!normalized(skippedParameterWrite(1,1)).equals(normalized(skippedParameterWrite(2,2))),
                "branch skipping first write preserves incoming argument identity");
        check(!normalized(skippedParameterWrite(1,1)).equals(normalized(skippedParameterWrite(1,2))),
                "returning a different parameter remains different");
        List<GmsDexFile.Instruction> changed=new ArrayList<>(receiver(0,1,2,false,false).code().instructions);
        changed.set(4,ins(4,0x6e,new int[]{0},"LThing;->other()Ljava/lang/Object;",-1));
        check(!baseline.equals(normalized(method("LTest;","f",Collections.<String>emptyList(),4,0,changed))),
                "opaque same-signature callee replacement rejected");
        check(!normalized(wide(1)).equals(normalized(wide(2))),"wide high-half overwrite differs from unrelated local");
        List<GmsDexFile.Instruction> branch=new ArrayList<>(skippedParameterWrite(1,1).code().instructions);
        branch.set(0,ins(0,0x38,new int[]{0},null,1));
        check(!normalized(skippedParameterWrite(1,1)).equals(normalized(method("LTest;","f",Arrays.asList("Z","Ljava/lang/Object;","Ljava/lang/Object;"),3,3,branch))),"branch target is preserved");
        GmsDexFile.Method original=receiver(0,1,2,false,false);
        check(baseline.equals(normalized(method("LRenamedOwner;","renamedMethod",Collections.<String>emptyList(),4,0,original.code().instructions))),
                "reviewed method and owner alpha rename survives");
        List<GmsDexFile.Instruction> fieldA=Arrays.asList(ins(0,0x62,new int[]{0},"LOpaque;->a:Ljava/lang/Object;",-1),ins(1,0x11,new int[]{0},null,-1));
        List<GmsDexFile.Instruction> fieldB=Arrays.asList(ins(0,0x62,new int[]{0},"LOpaque;->b:Ljava/lang/Object;",-1),ins(1,0x11,new int[]{0},null,-1));
        check(!normalized(method("LTest;","f",Collections.<String>emptyList(),1,0,fieldA)).equals(
                normalized(method("LTest;","f",Collections.<String>emptyList(),1,0,fieldB))),"opaque same-type field substitution rejected");
        changed=new ArrayList<>(original.code().instructions);
        changed.set(0,ins(0,0x22,new int[]{0},"LOtherThing;",-1));
        check(!baseline.equals(normalized(method("LTest;","f",Collections.<String>emptyList(),4,0,changed))),"opaque new-instance type substitution rejected");
        check(!symbolEvidence(0x71,"LFoo;->reviewedMethod()Ljava/lang/Object;").equals(
                symbolEvidence(0x71,"LFoo;->m0()Ljava/lang/Object;")),"opaque m0 cannot impersonate reviewed method slot");
        check(!symbolEvidence(0x62,"LFoo;->reviewedField:Ljava/lang/Object;").equals(
                symbolEvidence(0x62,"LFoo;->f0:Ljava/lang/Object;")),"opaque f0 cannot impersonate reviewed field slot");
        check(!symbolEvidence(0x1c,"LFoo;").equals(symbolEvidence(0x1c,"LC0;")),
                "opaque LC0 cannot impersonate reviewed type slot");
        System.out.println("GmsGateVerifierTest: "+assertions+" assertions passed");
    }
}
