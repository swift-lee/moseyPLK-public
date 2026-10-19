package moseyPLK.client;

import java.io.File;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/** Connection adapter operands are decoded data; no Android/target code executes. */
public final class GmsConnectionProofTest {
    private static final String FACTORY="Lcjxy;->a(Landroid/content/ServiceConnection;)Lcjxy;";
    private static final String CALLBACK="Lcjxy;->onServiceConnected(Landroid/content/ComponentName;Landroid/os/IBinder;)V";
    private interface Change { GmsDexFile.Instruction apply(GmsDexFile.Instruction instruction); }
    private static int assertions;

    private static GmsDexFile.Instruction change(GmsDexFile.Instruction x,int opcode,int[] registers,String reference,int target) {
        return new GmsDexFile.Instruction(x.pc,opcode,x.width,registers,x.literal,reference,target,x.targets,x.payloadWords);
    }

    private static void reject(GmsDexFile dex,String descriptor,int pc,String reason,Change mutation)throws Exception {
        GmsDexFile.Method method=dex.findMethod(descriptor);GmsDexFile.Code baseline=method.code();
        List<GmsDexFile.Instruction> instructions=new ArrayList<>(baseline.instructions);boolean changed=false;
        for(int i=0;i<instructions.size();i++)if(instructions.get(i).pc==pc) {instructions.set(i,mutation.apply(instructions.get(i)));changed=true;}
        if(!changed)throw new AssertionError("missing fixture pc="+pc);
        GmsDexFile.Code code=new GmsDexFile.Code(baseline.registersSize,baseline.insSize,baseline.outsSize,
                baseline.triesSize,baseline.units,instructions,baseline.tryBlocks);
        Field decoded=GmsDexFile.Method.class.getDeclaredField("decoded");decoded.setAccessible(true);decoded.set(method,code);
        try {
            try {GmsConnectionProof.verify(new GmsAdaptiveResolver.Graph(dex),FACTORY);throw new AssertionError("accepted "+reason);}
            catch(GmsAdaptiveResolver.Rejected failure) {
                if(!reason.equals(failure.reason))throw new AssertionError("expected "+reason+", got "+failure.reason,failure);
                assertions++;
            }
        } finally {decoded.set(method,baseline);}
    }

    public static void main(String[] args)throws Exception {
        try(GmsDexFile dex=GmsDexFile.readApk(new File(args[0]))) {
            GmsConnectionProof.verify(new GmsAdaptiveResolver.Graph(dex),FACTORY);assertions++;
            reject(dex,CALLBACK,15,"connection_adapter_callback_argument",x->change(x,x.opcode,new int[]{2,4,3},x.reference,x.target));
            reject(dex,CALLBACK,15,"connection_adapter_callback_receiver",x->change(x,x.opcode,new int[]{0,3,4},x.reference,x.target));
            reject(dex,CALLBACK,15,"connection_adapter_callback_count",x->change(x,0x00,new int[0],null,-1));
            reject(dex,CALLBACK,9,"connection_adapter_callback_skipped",x->change(x,x.opcode,x.registers,x.reference,23));
            reject(dex,CALLBACK,5,"connection_adapter_callback_escape",x->change(x,x.opcode,new int[]{3},x.reference,x.target));
            reject(dex,CALLBACK,11,"connection_adapter_source_writer",x->change(x,x.opcode,x.registers,
                    "Lcjxy;->a:Landroid/content/ServiceConnection;",x.target));
            reject(dex,FACTORY,35,"connection_adapter_input_flow",x->change(x,x.opcode,new int[]{0,1,1,2},x.reference,x.target));
            reject(dex,FACTORY,28,"connection_adapter_critical_escape",x->change(x,x.opcode,new int[]{4},x.reference,x.target));
            GmsConnectionProof.verify(new GmsAdaptiveResolver.Graph(dex),FACTORY);assertions++;
            System.out.println("PASS "+assertions+" ServiceConnection source/callback/escape mutations with exact rejection reasons");
            System.out.println("LIMIT: validates forwarding of implemented callbacks; independent tracing and optional platform defaults remain boundaries.");
        }
    }
}
