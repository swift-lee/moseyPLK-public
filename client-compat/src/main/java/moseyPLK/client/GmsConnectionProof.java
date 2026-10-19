package moseyPLK.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import static moseyPLK.client.GmsAdaptiveResolver.*;
import static moseyPLK.client.GmsSemanticProof.*;

/** Bounded ServiceConnection identity and callback forwarding proof.
 * Independent tracing resources remain an opaque boundary: they receive neither
 * the original connection, adapter nor callback arguments. Optional callbacks
 * absent from the adapter retain the platform default; no full equivalence claim.
 */
final class GmsConnectionProof {
    private static final String CONNECTION="Landroid/content/ServiceConnection;";
    private static final String OBJECT_INIT="Ljava/lang/Object;-><init>()V";
    private static final String SUPPRESSED="Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V";
    private static final String[] CALLBACKS={
        "onServiceConnected(Landroid/content/ComponentName;Landroid/os/IBinder;)V",
        "onServiceDisconnected(Landroid/content/ComponentName;)V",
        "onNullBinding(Landroid/content/ComponentName;)V",
        "onBindingDied(Landroid/content/ComponentName;)V"
    };

    static void verify(Graph graph,String descriptor)throws Exception {
        String role="connectionAdapter"+graph.identities.size();
        GmsDexFile.Method factory=graph.add(role+"Factory",descriptor);Flow flow=new Flow(factory);
        require((factory.accessFlags&8)!=0&&factory.parameterTypes.equals(Arrays.asList(CONNECTION))
                &&flow.code.triesSize==0,"connection_adapter_factory_signature");
        String adapter=null,constructor=null;Value constructorCall=null;int returns=0;
        for(int i=0;i<flow.ins.size();i++)if(flow.ins.get(i).opname.equals("return-object")) {
            Value value=flow.at(i,flow.ins.get(i).registers[0]);returns++;
            if(value.param(0))continue;
            require(value.kind.equals("new-instance"),"connection_adapter_return_origin");
            Value created=GmsFlagProof.constructor(flow,value);
            require(created.reference.startsWith(value.reference+"-><init>(")&&flow.dominates(created.site,i),"connection_adapter_uninitialized");
            require(adapter==null||adapter.equals(value.reference),"connection_adapter_multiple_types");
            require(constructor==null||constructor.equals(created.reference),"connection_adapter_multiple_constructors");
            adapter=value.reference;constructor=created.reference;constructorCall=created;
        }
        require(returns>0&&adapter!=null&&implementsConnection(graph,adapter,0),"connection_adapter_type");
        GmsDexFile.ClassDef type=graph.dex.findClass(adapter);
        require(type!=null&&"Ljava/lang/Object;".equals(type.superclass),"connection_adapter_superclass");
        GmsDexFile.Method init=graph.add(role+"Constructor",constructor);Flow ctor=new Flow(init);
        require((init.accessFlags&8)==0&&ctor.code.triesSize==0,"connection_adapter_constructor_signature");
        int sourceParameter=-1,slot=1;
        for(String parameter:init.parameterTypes) {
            if(parameter.equals(CONNECTION)){require(sourceParameter<0,"connection_adapter_source_ambiguity");sourceParameter=slot;}
            slot+=parameter.equals("J")||parameter.equals("D")?2:1;
        }
        require(sourceParameter>0&&constructorCall.arg(sourceParameter).param(0),"connection_adapter_input_flow");
        String source=GmsFlagProof.parameterField(ctor,sourceParameter);
        GmsDexFile.Field field=field(graph.dex,source);
        require(field.owner.equals(adapter)&&field.type.equals(CONNECTION)&&(field.accessFlags&(8|16))==16,"connection_adapter_mutable_source");
        Set<String> traceFields=new LinkedHashSet<>();int superCalls=0,ctorReturns=0;
        for(int i=0;i<ctor.ins.size();i++) {
            GmsDexFile.Instruction x=ctor.ins.get(i);String op=normalOp(x.opname);
            if(op.equals("invoke-direct")) {
                Value call=ctor.call(i);require(x.reference.equals(OBJECT_INIT)&&call.args.size()==1&&call.arg(0).param(0),"connection_adapter_constructor_call");superCalls++;
            } else if(op.equals("iput-object")) {
                require(ctor.at(i,x.registers[1]).param(0)&&owner(x.reference).equals(adapter),"connection_adapter_field_receiver");
                Value value=GmsFlagProof.stored(ctor,x.reference,null);
                if(x.reference.equals(source))require(value.param(sourceParameter),"connection_adapter_source_overwrite");
                else {
                    require(value.kind.equals("param")&&value.literal>0&&value.literal!=sourceParameter
                            &&unrelated(constructorCall.arg((int)value.literal),adapter),"connection_adapter_trace_input");
                    require((field(graph.dex,x.reference).accessFlags&2)!=0,"connection_adapter_trace_exposed");traceFields.add(x.reference);
                }
            } else if(op.equals("return-void"))ctorReturns++;
            else require(op.equals("nop")||op.equals("move-object"),"connection_adapter_constructor_effect");
        }
        require(superCalls==1&&ctorReturns==1,"connection_adapter_constructor_shape");
        for(int i=0;i<flow.ins.size();i++) {
            GmsDexFile.Instruction x=flow.ins.get(i);String op=normalOp(x.opname);
            require(!op.startsWith("iput")&&!op.startsWith("sput")&&!op.startsWith("aput"),"connection_adapter_factory_write");
            if(op.startsWith("invoke-")) {
                Value call=flow.call(i);
                if(x.reference.equals(constructor)) {
                    require(same(call,constructorCall),"connection_adapter_extra_construction");
                    for(int a=1;a<call.args.size();a++)if(a!=sourceParameter)require(unrelated(call.arg(a),adapter),"connection_adapter_trace_escape");
                } else for(Value argument:call.args)require(unrelated(argument,adapter),"connection_adapter_critical_escape");
            }
        }
        GmsDexFile.Method clinit=graph.dex.findMethod(adapter+"-><clinit>()V");
        if(clinit!=null) {
            graph.add(role+"Initializer",clinit.descriptor);
            for(GmsDexFile.Instruction x:code(clinit).instructions)require(x.opname.equals("nop")||x.opname.equals("return-void"),"connection_adapter_class_effect");
        }
        for(GmsDexFile.Method method:type.methods)if(method.codeOffset!=0&&!method.descriptor.equals(constructor))
            for(GmsDexFile.Instruction x:code(method).instructions)if(x.opname.startsWith("iput")&&x.reference.equals(source))
                throw new Rejected("connection_adapter_source_writer");
        for(int callback=0;callback<CALLBACKS.length;callback++) {
            GmsDexFile.Method method=graph.dex.findMethod(adapter+"->"+CALLBACKS[callback]);
            require(callback>=2||method!=null,"connection_adapter_required_callback");
            if(method!=null)verifyCallback(graph,graph.add(role+"Callback"+callback,method.descriptor),source,traceFields,CALLBACKS[callback]);
        }
        graph.identity(role+"Source",source);
    }

    private static void verifyCallback(Graph graph,GmsDexFile.Method method,String source,Set<String> traceFields,String callback)throws Exception {
        Flow flow=new Flow(method);require((method.accessFlags&8)==0&&flow.ins.size()<=128,"connection_adapter_callback_signature");
        List<Integer> forwards=flow.calls(CONNECTION+"->"+callback);require(forwards.size()==1,"connection_adapter_callback_count");
        int forward=forwards.get(0);Value call=flow.call(forward);
        require(call.arg(0).is("field",source)&&call.arg(0).arg(0).param(0)
                &&call.args.size()==method.parameterTypes.size()+1,"connection_adapter_callback_receiver");
        for(int a=1;a<call.args.size();a++)require(call.arg(a).param(a),"connection_adapter_callback_argument");
        Set<Integer> resources=new LinkedHashSet<>();
        for(int i=0;i<flow.ins.size();i++) {
            GmsDexFile.Instruction x=flow.ins.get(i);String op=normalOp(x.opname);
            if(op.startsWith("invoke-")&&i!=forward&&!x.reference.equals(SUPPRESSED)) {
                Value extra=flow.call(i);
                if(extra.args.size()==1&&extra.arg(0).kind.equals("field")&&traceFields.contains(extra.arg(0).reference)
                        &&extra.arg(0).arg(0).param(0)&&fieldType(extra.arg(0).reference).equals(owner(x.reference))
                        &&closeable(graph,returnType(x.reference),0))resources.add(i);
            }
        }
        int returns=0;
        for(int i=0;i<flow.ins.size();i++) {
            GmsDexFile.Instruction x=flow.ins.get(i);String op=normalOp(x.opname);
            require(op.equals("nop")||op.equals("move-object")||op.equals("move-result-object")||op.equals("move-exception")
                    ||op.equals("iget-object")||op.equals("iput-object")||op.equals("const")||op.equals("check-cast")
                    ||op.equals("if-eqz")||op.equals("if-nez")||op.equals("goto")||op.startsWith("invoke-")
                    ||op.equals("return-void")||op.equals("throw"),"connection_adapter_callback_operation");
            if(op.equals("return-void")){require(flow.dominates(forward,i),"connection_adapter_callback_skipped");returns++;}
            if(op.equals("iget-object"))require(flow.at(i,x.registers[1]).param(0)
                    &&(x.reference.equals(source)||traceFields.contains(x.reference)),"connection_adapter_unknown_field");
            if(op.equals("iput-object"))require(traceFields.contains(x.reference)&&flow.at(i,x.registers[1]).param(0)
                    &&flow.at(i,x.registers[0]).number(0),"connection_adapter_callback_write");
            if(op.startsWith("invoke-")&&i!=forward&&!resources.contains(i)) {
                if(x.reference.equals(SUPPRESSED))require(x.registers.length==2
                        &&exceptionValue(flow,i,x.registers[0],new HashSet<String>(),0)
                        &&exceptionValue(flow,i,x.registers[1],new HashSet<String>(),0),"connection_adapter_suppression_operand");
                else require(suffix(x.reference).equals("close()V")&&closeable(graph,owner(x.reference),0)
                        &&x.registers.length==1&&resourceValue(flow,i,x.registers[0],resources,new HashSet<String>(),0),"connection_adapter_callback_escape");
            }
            if(op.equals("throw"))require(exceptionValue(flow,i,x.registers[0],new HashSet<String>(),0),"connection_adapter_exception_replaced");
        }
        require(returns>0,"connection_adapter_callback_return");
    }

    private static boolean resourceValue(Flow flow,int site,int register,Set<Integer> resources,Set<String> seen,int depth)throws Exception {
        if(depth>32)return false;String key=site+":"+register;if(!seen.add(key))return false;
        Set<Integer> defs=flow.incoming[site][register];if(defs==null||defs.isEmpty())return false;
        for(int def:defs) {
            if(def<0)return false;GmsDexFile.Instruction x=flow.ins.get(def);String op=normalOp(x.opname);
            if(op.equals("const")){if(x.literal!=0)return false;}
            else if(op.equals("move-object")||op.equals("check-cast")) {
                if(!resourceValue(flow,def,x.registers[op.equals("check-cast")?0:1],resources,new HashSet<>(seen),depth+1))return false;
            } else if(op.equals("move-result-object")){if(def==0||!resources.contains(def-1))return false;}
            else return false;
        }
        return true;
    }

    private static boolean exceptionValue(Flow flow,int site,int register,Set<String> seen,int depth)throws Exception {
        if(depth>32)return false;String key=site+":"+register;if(!seen.add(key))return false;
        Set<Integer> defs=flow.incoming[site][register];if(defs==null||defs.isEmpty())return false;
        for(int def:defs) {
            if(def<0)return false;GmsDexFile.Instruction x=flow.ins.get(def);String op=normalOp(x.opname);
            if(op.equals("move-exception"))continue;
            if(!op.equals("move-object")||!exceptionValue(flow,def,x.registers[1],new HashSet<>(seen),depth+1))return false;
        }
        return true;
    }

    private static boolean unrelated(Value value,String adapter) {
        if(value==UNKNOWN||value.kind.equals("unknown")||value.kind.equals("param")||value.is("new-instance",adapter))return false;
        for(Value argument:value.args)if(!unrelated(argument,adapter))return false;
        return true;
    }

    private static boolean implementsConnection(Graph graph,String type,int depth)throws Exception {
        if(type.equals(CONNECTION))return true;if(depth>MAX_DEPTH)return false;GmsDexFile.ClassDef cls=graph.dex.findClass(type);if(cls==null)return false;
        for(String contract:cls.interfaces)if(implementsConnection(graph,contract,depth+1))return true;
        return cls.superclass!=null&&implementsConnection(graph,cls.superclass,depth+1);
    }

    private static boolean closeable(Graph graph,String type,int depth)throws Exception {
        if(type.equals("Ljava/io/Closeable;")||type.equals("Ljava/lang/AutoCloseable;"))return true;
        if(depth>MAX_DEPTH||!type.startsWith("L"))return false;GmsDexFile.ClassDef cls=graph.dex.findClass(type);if(cls==null)return false;
        for(String contract:cls.interfaces)if(closeable(graph,contract,depth+1))return true;
        return cls.superclass!=null&&closeable(graph,cls.superclass,depth+1);
    }

    private GmsConnectionProof(){}
}
