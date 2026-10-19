package moseyPLK.client;

import java.io.File;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import org.luckypray.dexkit.DexKitBridge;

/** Mutates decoded DEX data only; no target class is loaded or executed. */
public final class GmsMemoProofTest {
    private static final String FACTORY="Lhudo;->a(Lhudj;)Lhudj;";
    private static final String CONTRACT="Lhudj;";
    private static final String SUPPLIER="Lecyv;->ln()Ljava/lang/Object;";
    private static int assertions;
    private interface Change { void apply(List<GmsDexFile.Instruction> instructions); }

    private static GmsDexFile.Instruction copy(GmsDexFile.Instruction source,int opcode,int[] registers,
            long literal,String reference,int target) {
        return new GmsDexFile.Instruction(source.pc,opcode,source.width,registers,literal,reference,target,
                source.targets,source.payloadWords);
    }

    private static int at(List<GmsDexFile.Instruction> instructions,int pc) {
        for(int i=0;i<instructions.size();i++)if(instructions.get(i).pc==pc)return i;
        throw new AssertionError("fixture PC unavailable: "+pc);
    }

    private static void register(List<GmsDexFile.Instruction> instructions,int pc,int... registers) {
        int index=at(instructions,pc);GmsDexFile.Instruction x=instructions.get(index);
        instructions.set(index,copy(x,x.opcode,registers,x.literal,x.reference,x.target));
    }

    private static void opcode(List<GmsDexFile.Instruction> instructions,int pc,int opcode) {
        int index=at(instructions,pc);GmsDexFile.Instruction x=instructions.get(index);
        instructions.set(index,copy(x,opcode,x.registers,x.literal,x.reference,x.target));
    }

    private static void publishEarly(List<GmsDexFile.Instruction> instructions) {
        int cache=at(instructions,17),constant=at(instructions,19),publish=at(instructions,20);
        GmsDexFile.Instruction cached=instructions.get(cache),number=instructions.get(constant),flag=instructions.get(publish);
        instructions.set(cache,number);instructions.set(constant,flag);instructions.set(publish,cached);
        java.util.Map<Integer,Integer> positions=new java.util.HashMap<>();int pc=0;
        for(GmsDexFile.Instruction x:instructions){positions.put(x.pc,pc);pc+=x.width;}
        for(int i=0;i<instructions.size();i++) {
            GmsDexFile.Instruction x=instructions.get(i);
            instructions.set(i,new GmsDexFile.Instruction(positions.get(x.pc),x.opcode,x.width,x.registers,x.literal,
                    x.reference,x.target<0?x.target:positions.get(x.target),x.targets,x.payloadWords));
        }
    }

    private static void reject(DexKitBridge bridge,GmsDexFile dex,String descriptor,String reason,Change mutation)throws Exception {
        GmsDexFile.Method method=dex.findMethod(descriptor);GmsDexFile.Code baseline=method.code();
        List<GmsDexFile.Instruction> instructions=new ArrayList<>(baseline.instructions);mutation.apply(instructions);
        GmsDexFile.Code changed=new GmsDexFile.Code(baseline.registersSize,baseline.insSize,baseline.outsSize,
                baseline.triesSize,baseline.units,instructions,baseline.tryBlocks);
        Field decoded=GmsDexFile.Method.class.getDeclaredField("decoded");decoded.setAccessible(true);decoded.set(method,changed);
        try {
            try {
                GmsMemoProof.verify(bridge,new GmsAdaptiveResolver.Graph(dex),FACTORY,CONTRACT,SUPPLIER);
                throw new AssertionError("unexpected memo acceptance: "+reason);
            } catch(GmsAdaptiveResolver.Rejected failure) {
                if(!reason.equals(failure.reason))throw new AssertionError("expected "+reason+", got "+failure.reason,failure);
                assertions++;
            }
        } finally {decoded.set(method,baseline);}
    }

    public static void main(String[] args)throws Exception {
        System.load(args[0]);
        try(DexKitBridge bridge=DexKitBridge.create(args[1]);GmsDexFile dex=GmsDexFile.readApk(new File(args[1]))) {
            GmsAdaptiveResolver.Graph baseline=new GmsAdaptiveResolver.Graph(dex);
            GmsMemoProof.verify(bridge,baseline,FACTORY,CONTRACT,SUPPLIER);
            if(!baseline.proofs.contains("memo"))throw new AssertionError("baseline proof missing");assertions++;
            String serial="Lhudl;->ln()Ljava/lang/Object;",ordinary="Lhudm;->ln()Ljava/lang/Object;";
            reject(bridge,dex,ordinary,"memo_read_supplier_operand",xs->register(xs,13,3));
            reject(bridge,dex,ordinary,"memo_cache_value_origin",xs->register(xs,17,3,3));
            reject(bridge,dex,ordinary,"memo_return_not_supplier_result",xs->register(xs,31,0));
            reject(bridge,dex,ordinary,"memo_return_not_supplier_result",xs->opcode(xs,2,0x39));
            reject(bridge,dex,serial,"memo_return_not_supplier_result",xs->opcode(xs,2,0x38));
            reject(bridge,dex,ordinary,"memo_publish_before_result",GmsMemoProofTest::publishEarly);
            reject(bridge,dex,serial,"memo_publish_before_result",GmsMemoProofTest::publishEarly);
            reject(bridge,dex,ordinary,"memo_exception_swallowed",xs->opcode(xs,28,0x11));
            reject(bridge,dex,ordinary,"memo_unbalanced_monitor",xs->register(xs,22,3));
            reject(bridge,dex,"Lhudm;-><init>(Lhudj;)V","parameter_field_missing",xs->register(xs,13,1,1));
            reject(bridge,dex,"Lhudm;-><init>(Lhudj;)V","memo_null_check_operand",xs->register(xs,10,1));
            reject(bridge,dex,FACTORY,"memo_factory_constructor_call",xs->register(xs,21,0,0));
            // Removing cache publication must reject before source is cleared, even
            // though the original supplier call and cache-return path are still present.
            reject(bridge,dex,ordinary,"memo_cache_state_budget",xs->{
                int index=at(xs,17);GmsDexFile.Instruction x=xs.get(index);
                xs.set(index,copy(x,0x00,new int[0],0,null,-1));
            });
            GmsMemoProof.verify(bridge,new GmsAdaptiveResolver.Graph(dex),FACTORY,CONTRACT,SUPPLIER);assertions++;
            System.out.println("PASS "+assertions+" memo supplier/cache/guard/exception mutations with exact rejection reasons");
            System.out.println("LIMIT: mutations affect decoded host data, not ART DEX verification or native Android execution.");
        }
    }
}
