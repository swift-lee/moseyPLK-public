package moseyPLK.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class GmsSupplierVerifierTest {
    private static final String A="LFlags;->a()Z",B="LFlags;->b()Z",ACCESS="LHolder;->get()LFlags;",ROOT="LHolder;->instance:LHolder;",INIT="LService;->trigger:I";
    private static final GmsSupplierVerifier.Roles ROLES=new GmsSupplierVerifier.Roles(Arrays.asList(A),Arrays.asList(B),Arrays.asList(ACCESS),Arrays.asList(INIT),Arrays.asList(ROOT));
    private static int assertions;
    private static final class Op {
        int opcode;int[] regs;String ref;long literal;int target=-1;
        Op(int opcode,int...regs){this.opcode=opcode;this.regs=regs;}
        Op ref(String ref){this.ref=ref;return this;}
        Op val(long value){literal=value;return this;}
        Op to(int target){this.target=target;return this;}
        int width(){return opcode>=0x6e&&opcode<=0x78?3:opcode==0x60||opcode==0x62||opcode==0x38||opcode==0x39||opcode==0x32||opcode==0x33||opcode==0x1f?2:1;}
    }
    private static Op op(int opcode,int...regs){return new Op(opcode,regs);}
    private static List<Op> prefix(){return new ArrayList<>(Arrays.asList(op(0x60,3).ref(INIT),op(0x62,0).ref(ROOT),op(0x6e,0).ref(ACCESS),op(0x0c,1),op(0x72,1).ref(A),op(0x0a,1)));}
    private static List<Op> pure(){List<Op>x=prefix();x.addAll(Arrays.asList(op(0x71,1).ref(GmsSupplierVerifier.BOX),op(0x0c,2),op(0x11,2)));return x;}
    private static List<Op> or(){List<Op>x=prefix();x.addAll(Arrays.asList(op(0x12,2).val(1),op(0x39,1).to(15),op(0x6e,0).ref(ACCESS),op(0x0c,1),op(0x72,1).ref(B),op(0x0a,1),op(0x38,1).to(14),op(0x28).to(15),op(0x12,2).val(0),op(0x71,2).ref(GmsSupplierVerifier.BOX),op(0x0c,2),op(0x11,2)));return x;}
    private static List<Op> reuse(){
        return new ArrayList<>(Arrays.asList(op(0x60,3).ref(INIT),op(0x62,0).ref(ROOT),
                op(0x6e,0).ref(ACCESS),op(0x0c,1),op(0x07,2,1),op(0x72,1).ref(A),op(0x0a,1),
                op(0x39,1).to(11),op(0x72,2).ref(B),op(0x0a,1),op(0x28).to(12),op(0x12,1).val(1),
                op(0x71,1).ref(GmsSupplierVerifier.BOX),op(0x0c,2),op(0x11,2)));
    }
    private static GmsDexFile.Method method(List<Op> ops,int flags,int tries){
        int[] pcs=new int[ops.size()];int units=0;for(int i=0;i<ops.size();i++){pcs[i]=units;units+=ops.get(i).width();}
        List<GmsDexFile.Instruction> xs=new ArrayList<>();
        for(int i=0;i<ops.size();i++){Op o=ops.get(i);int target=o.target<0?-1:o.target<pcs.length?pcs[o.target]:units+99;
            xs.add(new GmsDexFile.Instruction(pcs[i],o.opcode,o.width(),o.regs,o.literal,o.ref,target,new int[0],new int[0]));}
        GmsDexFile.Code code=new GmsDexFile.Code(4,1,1,tries,units,xs,Collections.emptyList());
        return new GmsDexFile.Method("LSupplier;","run","Ljava/lang/Object;",Collections.emptyList(),flags,code);
    }
    private static GmsSupplierVerifier.Result expect(List<Op> ops,String expected){return expect(method(ops,1,0),ROLES,expected);}
    private static GmsSupplierVerifier.Result expect(GmsDexFile.Method method,GmsSupplierVerifier.Roles rules,String expected){
        GmsSupplierVerifier.Result result=GmsSupplierVerifier.verify(method,rules);assertions++;
        if(!result.classification.name().equals(expected))throw new AssertionError(expected+" got "+result.classification+": "+result.reason);
        return result;
    }
    private static void reject(List<Op> ops){expect(ops,"UNSUPPORTED");}
    public static void main(String[] args){
        GmsSupplierVerifier.Result pure=expect(pure(),"PURE_A"),or=expect(or(),"A_OR_B");
        assertions++;if(pure.cases.size()!=4||or.cases.size()!=4)throw new AssertionError("four cases");
        for(GmsSupplierVerifier.Case c:or.cases){assertions++;if(c.getterTrace.size()!=(c.a?1:2))throw new AssertionError("short circuit trace");}
        GmsSupplierVerifier.Result reused=expect(reuse(),"A_OR_B");
        for(GmsSupplierVerifier.Case c:reused.cases){assertions++;if(c.accessorCalls!=1)throw new AssertionError("receiver reuse");}
        List<Op> constants=prefix();constants.addAll(Arrays.asList(op(0x39,1).to(9),
                op(0x62,2).ref("Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;"),op(0x11,2),
                op(0x62,2).ref("Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;"),op(0x11,2)));
        expect(constants,"PURE_A");
        List<Op> paired=prefix();paired.addAll(Arrays.asList(op(0x12,2).val(0),op(0x33,1,2).to(10),
                op(0x62,2).ref("Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;"),op(0x11,2),
                op(0x62,2).ref("Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;"),op(0x11,2)));
        expect(paired,"PURE_A");
        paired.get(7).opcode=0x32;reject(paired); // Reversed comparison remains NOT A.
        List<Op> cast=pure();cast.add(4,op(0x1f,1).ref("LFlags;"));expect(cast,"PURE_A");
        cast.get(4).ref="Ljava/lang/Object;";expect(cast,"PURE_A");
        cast.get(4).ref="LOtherFlags;";reject(cast);
        constants.get(7).ref="Ljava/lang/Boolean;->OTHER:Ljava/lang/Boolean;";reject(constants);
        List<Op> wrongReuse=reuse();wrongReuse.get(8).regs=new int[]{0};reject(wrongReuse);
        List<Op>x=or();x.get(7).opcode=0x38;x.get(7).target=14;reject(x); // AND
        x=or();x.get(7).target=14;reject(x); // Same opcode list, wrong edge.
        x=prefix();x.addAll(Arrays.asList(op(0x38,1).to(9),op(0x12,1).val(0),op(0x28).to(10),op(0x12,1).val(1),op(0x71,1).ref(GmsSupplierVerifier.BOX),op(0x0c,2),op(0x11,2)));reject(x); // NOT
        x=pure();x.add(6,op(0x12,1).val(1));reject(x); // Ignores A.
        x=pure();x.get(6).regs=new int[]{0};reject(x); // Wrong boxing operand.
        x=pure();x.get(6).regs=new int[]{3};reject(x); // Init field is not Boolean.
        x=pure();x.get(4).regs=new int[]{0};reject(x); // Wrong receiver with same opcode/ref.
        x=pure();x.get(2).ref="LHolder;->other()LFlags;";reject(x);
        x=pure();x.get(4).ref="LFlags;->other()Z";reject(x);
        x=pure();x.get(1).ref="LHolder;->other:LHolder;";reject(x);
        x=pure();x.get(0).ref="LService;->other:I";reject(x);
        x=pure();x.get(6).opcode=0x6e;reject(x); // valueOf instance dispatch.
        x=pure();x.get(4).opcode=0x71;reject(x); // getter static dispatch.
        x=pure();x.get(3).opcode=0x0a;reject(x); // Wrong result kind.
        x=pure();x.get(5).opcode=0x0c;reject(x);
        x=pure();x.get(8).regs=new int[]{1};reject(x); // Unboxed return.
        x=pure();x.get(4).regs=new int[]{4};reject(x); // Out-of-frame operand.
        x=pure();x.get(2).regs=new int[]{2};reject(x); // Undefined receiver.
        x=pure();x.add(3,op(0x00));reject(x); // Delayed move-result.
        x=pure();x.add(0,op(0x0a,1));reject(x); // Orphan move-result.
        x=pure();x.add(6,op(0x12,1).val(2));reject(x);
        x=pure();x.add(6,op(0x07,2,1));reject(x); // Primitive through move-object.
        x=pure();x.add(4,op(0x01,2,1));reject(x); // Object through primitive move.
        x=pure();x.add(op(0x00));reject(x); // Unreachable instruction.
        x=pure();x.add(0,op(0x28).to(0));reject(x); // Loop.
        x=pure();x.add(0,op(0x28).to(999));reject(x);
        x=pure();x.add(0,op(0x1d,0));reject(x); // Monitor.
        x=pure();x.add(0,op(0x71).ref("LUnknown;->sideEffect()V"));reject(x);
        x=pure();x.add(0,op(0x28).to(2));x.add(1,op(0x71).ref("LUnknown;->sideEffect()V"));reject(x); // Dead unknown call.
        x=pure();for(int i=0;i<130;i++)x.add(0,op(0x00));reject(x);
        expect(method(pure(),1,1),ROLES,"UNSUPPORTED");
        expect(method(pure(),0x21,0),ROLES,"UNSUPPORTED");
        expect(method(pure(),0x20001,0),ROLES,"UNSUPPORTED");
        expect(method(pure(),9,0),ROLES,"UNSUPPORTED");
        expect(method(pure(),1,0),new GmsSupplierVerifier.Roles(Collections.emptyList(),Arrays.asList(B),Arrays.asList(ACCESS),Arrays.asList(INIT),Arrays.asList(ROOT)),"UNSUPPORTED");
        expect(method(pure(),1,0),new GmsSupplierVerifier.Roles(Arrays.asList(A),Arrays.asList(A),Arrays.asList(ACCESS),Arrays.asList(INIT),Arrays.asList(ROOT)),"UNSUPPORTED");
        expect(method(pure(),1,0),new GmsSupplierVerifier.Roles(Arrays.asList(A),Arrays.asList(B),Arrays.asList(ACCESS),Collections.emptyList(),Arrays.asList(ROOT)),"UNSUPPORTED");
        expect(method(pure(),1,0),new GmsSupplierVerifier.Roles(Arrays.asList(A),Arrays.asList(B),Arrays.asList(ACCESS),Arrays.asList(INIT),Collections.emptyList()),"UNSUPPORTED");
        expect(null,ROLES,"UNSUPPORTED");
        expect(method(pure(),1,0),null,"UNSUPPORTED");
        System.out.println("GmsSupplierVerifierTest: "+assertions+" assertions passed");
    }
}
