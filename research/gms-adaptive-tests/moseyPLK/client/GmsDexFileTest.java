package moseyPLK.client;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;

/** Host-only static reader/semantic checks; no target code is loaded or executed. */
public final class GmsDexFileTest {
    private static int assertions;
    private static void check(boolean condition,String message){assertions++;if(!condition)throw new AssertionError(message);}
    private static GmsSupplierVerifier.Roles roles(String a,String b,String access,String root,String init){
        return new GmsSupplierVerifier.Roles(Collections.singleton(a),b.isEmpty()?Collections.emptyList():Collections.singleton(b),
            Collections.singleton(access),init.isEmpty()?Collections.emptyList():Collections.singleton(init),Collections.singleton(root));
    }
    private static void real(File apk,boolean current) throws Exception {
        GmsDexFile dex=GmsDexFile.readApk(apk);
        String holder=current?"jtlz":"jprz",api=current?"jtma":"jpsa",getter=current?"W":"S";
        String supplier=current?"Lecyv;->ln()Ljava/lang/Object;":"Leabp;->lr()Ljava/lang/Object;";
        GmsDexFile.Method method=dex.findMethod(supplier);
        check(method!=null,"real supplier definition");
        List<String> init=new ArrayList<>();
        for(GmsDexFile.Instruction i:method.code().instructions)if(i.opname.equals("sget"))init.add(i.reference);
        GmsSupplierVerifier.Roles rules=new GmsSupplierVerifier.Roles(Collections.singleton("L"+api+";->"+getter+"()Z"),
            current?Collections.singleton("Ljtma;->U()Z"):Collections.emptyList(),
            Collections.singleton("L"+holder+";->b()L"+api+";"),init,Collections.singleton("L"+holder+";->a:L"+holder+";"));
        GmsSupplierVerifier.Result result=GmsSupplierVerifier.verify(method,rules);
        check(result.classification==(current?GmsSupplierVerifier.Classification.A_OR_B:GmsSupplierVerifier.Classification.PURE_A),result.reason);
        check(result.cases.size()==4,"four actual input traces");
        String service="Lcom/google/android/gms/nearby/sharing/NearbySharingChimeraService;";
        for(String name:new String[]{"<init>","onCreate","ad","bG","aa"}){
            String desc=service+"->"+name+((name.equals("aa")||name.equals("ad"))?"(Z)V":"()V");
            GmsDexFile.Method consumer=dex.findMethod(desc);
            if(consumer==null&&name.equals("bG"))continue;
            check(consumer!=null,"real service method "+desc);
            check(!consumer.code().instructions.isEmpty(),"real consumer operands");
        }
        GmsDexFile.ClassDef provider=dex.findClass("L"+holder+";");
        check(provider!=null&&!provider.fields.isEmpty(),"receiver fields");
        int decoded=0,tries=0;
        for(GmsDexFile.Method m:provider.methods){if(m.code()!=null){decoded++;tries+=m.code().tryBlocks.size();}}
        check(decoded>0,"receiver code");
        System.out.println("real "+(current?"263436035":"263332035")+" dex="+dex.dexCount()+" classes="+dex.classDescriptors().size()+" result="+result.classification+" providerBodies="+decoded+" providerTries="+tries);
        dex.close();
    }
    private static void fixture(File root,String id,String expected) throws Exception {
        GmsDexFile dex=GmsDexFile.readApk(new File(root,id+"/dex.zip"));boolean renamed=id.equals("pure_a_renamed");
        String supplier=renamed?"Ltc;->xx()Ljava/lang/Object;":"Lfs;->ln()Ljava/lang/Object;";
        GmsSupplierVerifier.Result result=GmsSupplierVerifier.verify(dex.findMethod(supplier),renamed?
            roles("Lqk;->r()Z","Lqk;->s()Z","Lsb;->c()Lqk;","Lsb;->x:Lsb;",""):
            roles("Lfk;->a()Z","Lfk;->b()Z","Lfp;->b()Lfk;","Lfp;->x:Lfp;",""));
        check(result.classification.name().equals(expected),id+": "+result.reason);
        for(GmsDexFile.Method m:dex.methods())if(m.codeOffset!=0)check(!m.code().instructions.isEmpty(),id+" method parsed");
        System.out.println("fixture "+id+" local="+result.classification);
        dex.close();
    }
    private static void malformed(File fixture) throws Exception {
        byte[] valid=Files.readAllBytes(fixture.toPath());
        for(int index:new int[]{0,7,32,36,40,60,68,76,84,92,100,108}){
            byte[] bytes=valid.clone();bytes[index]=(byte)255;
            boolean rejected=false;try{GmsDexFile dex=GmsDexFile.readDex(bytes);dex.methods();}catch(IOException expected){rejected=true;}
            check(rejected,"malformed header/index "+index);
        }
        for(int version=35;version<=40;version++){
            byte[] bytes=valid.clone();bytes[4]='0';bytes[5]=(byte)('0'+version/10);bytes[6]=(byte)('0'+version%10);
            check(!GmsDexFile.readDex(bytes).classDescriptors().isEmpty(),"DEX version "+version);
        }
        for(int version:new int[]{34,41}){byte[] bytes=valid.clone();bytes[5]=(byte)('0'+version/10);bytes[6]=(byte)('0'+version%10);
            boolean rejected=false;try{GmsDexFile.readDex(bytes);}catch(IOException expected){rejected=true;}check(rejected,"unsupported DEX version");}
        byte[] truncated=Arrays.copyOf(valid,100);boolean rejected=false;try{GmsDexFile.readDex(truncated);}catch(IOException expected){rejected=true;}check(rejected,"truncated header");
    }
    private static void put2(byte[] b,int at,int value){b[at]=(byte)value;b[at+1]=(byte)(value>>>8);}
    private static void put4(byte[] b,int at,int value){put2(b,at,value);put2(b,at+2,value>>>16);}
    private static void rejectCode(byte[] bytes,String descriptor,String label) throws Exception {
        boolean rejected=false;
        try(GmsDexFile dex=GmsDexFile.readDex(bytes)){dex.findMethod(descriptor).code();}catch(IOException expected){rejected=true;}
        check(rejected,label);
    }
    private static void operands(File file,File fixture) throws Exception {
        byte[] bytes=Files.readAllBytes(file.toPath());
        try(GmsDexFile dex=GmsDexFile.readDex(bytes)){
            GmsDexFile.Method caught=dex.findMethod("LDexOperands;->caught(Ljava/lang/Object;)I");
            GmsDexFile.Code c=caught.code();
            check(c.triesSize>0&&!c.tryBlocks.isEmpty(),"typed exception table");
            check(c.tryBlocks.get(0).handlers.get(0).type.equals("Ljava/lang/NullPointerException;"),"handler type and order");
            boolean catchAll=false;
            for(GmsDexFile.TryBlock t:dex.findMethod("LDexOperands;->monitored(Ljava/lang/Object;)Ljava/lang/Object;").code().tryBlocks)
                for(GmsDexFile.Handler h:t.handlers)catchAll|=h.type==null;
            check(catchAll,"monitor catch-all handler retained");
            for(String name:new String[]{"packed","sparse"}){
                GmsDexFile.Method method=dex.findMethod("LDexOperands;->"+name+"(I)I");boolean payload=false;
                for(GmsDexFile.Instruction i:method.code().instructions){
                    if(i.opname.endsWith("switch")&&i.opcode<256){check(i.targets.length==3,"actual switch targets");
                        byte[] changed=bytes.clone();put4(changed,method.codeOffset+16+2*i.pc+2,1);rejectCode(changed,method.descriptor,"branch into non-payload");}
                    payload|=i.opcode>255&&i.payloadWords.length>0;
                }
                check(payload,"actual "+name+" payload operands");
            }
            boolean array=false,wide=false,string=false,cast=false,iput=false,iget=false;
            for(GmsDexFile.Method method:dex.methods())if(method.code()!=null)for(GmsDexFile.Instruction i:method.code().instructions){
                array|=i.opcode==0x300&&i.payloadWords.length>0;
                wide|=i.opname.equals("const-wide")&&i.literal==0xf123456789abcdefL;
                string|=i.opname.equals("const-string")&&"a\u0000\u07ff\u0800\ud83d\ude00".equals(i.reference);
                cast|=i.opname.equals("check-cast")&&"Ljava/lang/String;".equals(i.reference);
                iput|=i.opname.equals("iput-object")&&"LDexOperands;->value:Ljava/lang/Object;".equals(i.reference);
                iget|=i.opname.equals("iget-object")&&"LDexOperands;->value:Ljava/lang/Object;".equals(i.reference);
            }
            check(array&&wide&&string&&cast&&iput&&iget,"array/wide/MUTF8/cast/field operand decoding");
            byte[] changed=bytes.clone();int tries=caught.codeOffset+16+c.units*2+(c.units%2)*2;
            put2(changed,tries+6,65535);rejectCode(changed,caught.descriptor,"invalid handler offset");
            changed=bytes.clone();put4(changed,tries,c.units+1);rejectCode(changed,caught.descriptor,"invalid try range");
        }
        byte[] pure=Files.readAllBytes(fixture.toPath());String desc="Lfs;->ln()Ljava/lang/Object;";
        try(GmsDexFile dex=GmsDexFile.readDex(pure)){
            GmsDexFile.Method method=dex.findMethod(desc);GmsDexFile.Code code=method.code();int base=method.codeOffset+16;
            byte[] changed=pure.clone();changed[base]=(byte)0xff;rejectCode(changed,desc,"unknown opcode refuses decoding");
            changed=pure.clone();changed[base+1]=(byte)255;rejectCode(changed,desc,"register outside frame");
            changed=pure.clone();put4(changed,method.codeOffset+12,65537);rejectCode(changed,desc,"body size bound");
            for(GmsDexFile.Instruction i:code.instructions)if(i.opname.startsWith("invoke-")){
                changed=pure.clone();changed[base+2*i.pc+1]=(byte)0x60;rejectCode(changed,desc,"invoke arity exceeds encoded register slots");
                changed=pure.clone();put2(changed,base+2*i.pc+2,65535);rejectCode(changed,desc,"invalid method reference");break;
            }
            GmsDexFile.Method stored=method;dex.close();boolean closed=false;
            try{dex.findMethod(stored.descriptor);}catch(IOException expected){closed=true;}
            check(closed,"closed reader refuses lookup");
        }
    }
    public static void main(String[] args) throws Exception {
        File fixtures=new File(args[0]);
        for(String id:new String[]{"pure_a","pure_a_renamed","or_ab","and_ab","not_a","duplicate_other_namespace","duplicate_same_namespace","supplier_side_effect","getter_side_effect","constant_false","constant_true","discard_a_constant_false"}){
            String expected=id.equals("or_ab")?"A_OR_B":Arrays.asList("pure_a","pure_a_renamed","duplicate_other_namespace","duplicate_same_namespace","getter_side_effect").contains(id)?"PURE_A":"UNSUPPORTED";
            // Duplicate declarations/getter side effects remain caller role-proof obligations.
            fixture(fixtures,id,expected);
        }
        malformed(new File(fixtures,"pure_a/dex/classes.dex"));
        operands(new File(args[3]),new File(fixtures,"pure_a/dex/classes.dex"));
        real(new File(args[1]),false);real(new File(args[2]),true);
        System.out.println("GmsDexFileTest: "+assertions+" assertions passed");
    }
}
