package moseyPLK.client;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.result.FieldData;
import org.luckypray.dexkit.result.MethodData;
import static moseyPLK.client.GmsAdaptiveResolver.*;
import static moseyPLK.client.GmsSemanticProof.*;

/** Proves the supplier operand and every normal memo return, not a method fingerprint. */
final class GmsMemoProof {
    private static final Object SELF=new Object(), SOURCE=new Object(), RESULT=new Object();
    private static final class Lock { }
    private static final Long ZERO=Long.valueOf(0), ONE=Long.valueOf(1);
    private static final String OBJECT_INIT="Ljava/lang/Object;-><init>()V";
    private static final String NULL_CHECK="Ljava/lang/Object;->getClass()Ljava/lang/Class;";

    static void verify(DexKitBridge bridge,Graph graph,String factory,String contract,String supplier)throws Exception {
        if(!contract.contains("->"))contract=contract+"->"+suffix(supplier);
        GmsDexFile.Method method=graph.add("memoFactory",factory);
        require((method.accessFlags&8)!=0&&method.parameterTypes.size()==1
                &&method.returnType.equals(method.parameterTypes.get(0)),"memo_factory_signature");
        require(owner(contract).equals(method.returnType)&&suffix(contract).equals(suffix(supplier)),"memo_supplier_contract");
        require(assignable(graph,owner(supplier),owner(contract),0),"memo_supplier_implementation");
        Flow flow=new Flow(method);require(flow.code.triesSize==0,"memo_factory_handlers");
        Set<String> constructors=new LinkedHashSet<>();int returns=0;
        for(int i=0;i<flow.ins.size();i++) {
            GmsDexFile.Instruction x=flow.ins.get(i);String op=normalOp(x.opname);
            require(op.equals("nop")||op.equals("move-object")||op.equals("instance-of")||op.equals("check-cast")
                    ||op.equals("new-instance")||op.equals("invoke-direct")||op.startsWith("if-")
                    ||op.equals("goto")||op.equals("return-object"),"memo_factory_unknown_operation");
            if(op.equals("return-object")) {
                Value result=flow.at(i,x.registers[0]);returns++;
                if(result.param(0))continue;
                require(result.kind.equals("new-instance")&&assignable(graph,result.reference,owner(contract),0),"memo_factory_return_origin");
                Value constructor=GmsFlagProof.constructor(flow,result);
                require(owner(constructor.reference).equals(result.reference)&&constructor.args.size()==2
                        &&constructor.arg(1).param(0)&&dominates(flow,constructor.site,i),"memo_factory_supplier_flow");
                constructors.add(constructor.reference);
            }
            if(op.equals("invoke-direct")) {
                Value call=flow.call(i);
                require(suffix(x.reference).equals("<init>("+method.returnType+")V")
                        &&call.arg(0).kind.equals("new-instance")&&call.arg(1).param(0),"memo_factory_constructor_call");
                constructors.add(x.reference);
            }
            if(op.equals("check-cast")) {
                Value value=flow.at(i,x.registers[0]);
                String type=value.param(0)?owner(supplier):value.kind.equals("new-instance")?value.reference:null;
                require(type!=null&&assignable(graph,type,x.reference,0),"memo_factory_cast");
            }
        }
        require(returns>0&&constructors.size()<=4,"memo_factory_return_budget");
        int index=0;
        for(String constructor:constructors)verifyWrapper(bridge,graph,constructor,contract,index++);
        graph.proofs.add("memo");
    }

    private static void verifyWrapper(DexKitBridge bridge,Graph graph,String constructor,String contract,int index)throws Exception {
        String role="memo"+index;
        GmsDexFile.Method ctor=graph.add(role+"Constructor",constructor);
        require((ctor.accessFlags&8)==0&&ctor.name.equals("<init>")
                &&ctor.parameterTypes.equals(Arrays.asList(owner(contract))),"memo_constructor_signature");
        Flow construction=new Flow(ctor);require(construction.code.triesSize==0,"memo_constructor_handlers");
        String source=GmsFlagProof.parameterField(construction,1);
        require(field(graph.dex,source).type.equals(owner(contract)),"memo_source_field_type");
        Map<String,Object> initial=new LinkedHashMap<>();Set<String> locks=new LinkedHashSet<>();
        Map<Value,Lock> lockValues=new HashMap<>();
        int objectInitializers=0,returns=0;
        for(int i=0;i<construction.ins.size();i++) {
            GmsDexFile.Instruction x=construction.ins.get(i);String op=normalOp(x.opname);
            require(op.equals("nop")||op.equals("move-object")||op.equals("move")||op.equals("const")
                    ||op.equals("new-instance")||op.equals("invoke-direct")||op.equals("invoke-static")
                    ||op.equals("invoke-virtual")||op.equals("iput-object")||op.equals("iput-boolean")
                    ||op.equals("return-void"),"memo_constructor_unknown_operation");
            if(op.startsWith("iput")) {
                require(construction.at(i,x.registers[1]).param(0)&&owner(x.reference).equals(ctor.owner),"memo_constructor_field_receiver");
                Value value=construction.at(i,x.registers[0]);Object tracked;
                if(value.param(1))tracked=SOURCE;
                else if(value.number(0)||value.number(1))tracked=Long.valueOf(value.literal);
                else if(value.kind.equals("new-instance")) {
                    Value lockCtor=GmsFlagProof.constructor(construction,value);
                    require(owner(lockCtor.reference).equals(value.reference)&&lockCtor.args.size()==1
                            &&dominates(construction,lockCtor.site,i),"memo_lock_construction");
                    verifyLock(graph,lockCtor.reference,role+"Lock");locks.add(x.reference);
                    if(!lockValues.containsKey(value))lockValues.put(value,new Lock());
                    tracked=lockValues.get(value);
                } else throw new Rejected("memo_constructor_field_value");
                require(initial.put(x.reference,tracked)==null,"memo_constructor_field_reassigned");
            }
            if(op.startsWith("invoke-")) {
                Value call=construction.call(i);
                if(OBJECT_INIT.equals(x.reference)) {
                    require(op.equals("invoke-direct")&&call.args.size()==1&&call.arg(0).param(0),"memo_super_constructor");
                    objectInitializers++;
                } else if(NULL_CHECK.equals(x.reference)) {
                    require(op.equals("invoke-virtual")&&call.args.size()==1&&call.arg(0).param(1),"memo_null_check_operand");
                } else if(op.equals("invoke-static")) {
                    require(call.args.size()==1&&call.arg(0).param(1),"memo_null_check_operand");
                    GmsFlagProof.verifyNullHelper(graph,x.reference,role+"NullHelper");
                } else {
                    require(op.equals("invoke-direct")&&call.arg(0).kind.equals("new-instance")
                            &&owner(x.reference).equals(call.arg(0).reference)&&call.args.size()==1,"memo_constructor_call");
                    verifyLock(graph,x.reference,role+"Lock");
                }
            }
            if(op.equals("return-void"))returns++;
        }
        require(objectInitializers==1&&returns==1&&initial.get(source)==SOURCE,"memo_constructor_initial_state");
        verifyNoInitializer(graph,ctor.owner,role+"Initializer");
        String readDescriptor=ctor.owner+"->"+suffix(contract);
        GmsDexFile.Method reader=graph.add(role+"Read",readDescriptor);
        require((reader.accessFlags&8)==0&&reader.parameterTypes.isEmpty()
                &&reader.returnType.equals("Ljava/lang/Object;"),"memo_read_signature");
        Flow read=new Flow(reader);require(read.ins.size()<=256,"memo_read_instruction_budget");
        Set<String> caches=new LinkedHashSet<>(),ready=new LinkedHashSet<>();boolean clears=false;
        for(int i=0;i<read.ins.size();i++) {
            GmsDexFile.Instruction x=read.ins.get(i);String op=normalOp(x.opname);
            require(op.equals("nop")||op.equals("move")||op.equals("move-object")||op.equals("move-result-object")
                    ||op.equals("move-exception")||op.equals("const")||op.equals("iget-object")||op.equals("iget-boolean")
                    ||op.equals("iput-object")||op.equals("iput-boolean")||op.equals("invoke-interface")||op.equals("invoke-virtual")
                    ||op.equals("monitor-enter")||op.equals("monitor-exit")||op.equals("if-eqz")||op.equals("if-nez")
                    ||op.equals("goto")||op.equals("return-object")||op.equals("throw"),"memo_read_unknown_operation");
            if(op.startsWith("invoke-")) {
                Value call=read.call(i);
                require(x.reference.equals(contract)&&call.args.size()==1&&call.arg(0).is("field",source)
                        &&call.arg(0).arg(0).param(0),"memo_read_supplier_operand");
            }
            if(op.startsWith("iput")) {
                require(read.at(i,x.registers[1]).param(0)&&owner(x.reference).equals(reader.owner),"memo_read_field_receiver");
                Value value=read.at(i,x.registers[0]);
                if(x.reference.equals(source)) {require(value.number(0),"memo_supplier_overwrite");clears=true;}
                else if(op.equals("iput-boolean")) {require(value.number(1),"memo_ready_value");ready.add(x.reference);}
                else {
                    require(value.is("call",contract)&&value.arg(0).is("field",source)
                            &&value.arg(0).arg(0).param(0),"memo_cache_value_origin");caches.add(x.reference);
                }
            }
        }
        require(caches.size()<=1&&ready.size()<=1&&(!clears||!caches.isEmpty()),"memo_cache_state_budget");
        Set<String> critical=new LinkedHashSet<>(caches);critical.add(source);critical.addAll(ready);
        for(String member:critical) {
            FieldData data=bridge.getFieldData(member);require(data!=null,"memo_field_unavailable");
            for(MethodData writer:data.getWriters())require(writer.getDescriptor().equals(constructor)
                    ||writer.getDescriptor().equals(readDescriptor),"memo_field_unexplained_writer");
            if(!initial.containsKey(member))initial.put(member,ZERO);
        }
        if(!caches.isEmpty()) {
            require(clears||!ready.isEmpty(),"memo_cache_publication_guard");
            for(String member:ready)require((field(graph.dex,member).accessFlags&0x40)!=0,"memo_ready_not_volatile");
            if(clears)require((field(graph.dex,source).accessFlags&0x40)!=0,"memo_source_not_volatile");
        }
        validateHandlers(read,locks);
        executeRead(read,contract,source,initial,caches,ready,locks,clears,-1,false);
        if(!caches.isEmpty()) {
            executeRead(read,contract,source,initial,caches,ready,locks,clears,-1,true);
            // A competing call may publish between any two reads. Keep local registers
            // unchanged so an early cache read cannot be validated by a later guard.
            for(int i=0;i<read.ins.size();i++)if(read.ins.get(i).opname.startsWith("iget"))
                executeRead(read,contract,source,initial,caches,ready,locks,clears,i,false);
        }
    }

    private static void executeRead(Flow flow,String contract,String source,Map<String,Object> initial,
            Set<String> caches,Set<String> ready,Set<String> locks,boolean clears,int transition,boolean hot)throws Exception {
        Map<String,Object> fields=new HashMap<>(initial);Map<Integer,Object> registers=new HashMap<>();
        registers.put(flow.code.registersSize-flow.code.insSize,SELF);Object pending=null;
        if(hot)publish(fields,caches,ready,source,clears);
        ArrayDeque<Object> monitors=new ArrayDeque<>();int at=0;
        for(int steps=0;steps<512;steps++) {
            require(at>=0&&at<flow.ins.size(),"memo_read_invalid_flow");
            if(at==transition) {
                if(monitors.isEmpty())publish(fields,caches,ready,source,clears);
                transition=-1;
            }
            GmsDexFile.Instruction x=flow.ins.get(at);String op=normalOp(x.opname);int[] r=x.registers;int next=at+1;
            if(!op.equals("move-result-object"))pending=null;
            if(op.equals("nop")) { /* no effect */ }
            else if(op.equals("move-object")||op.equals("move"))registers.put(r[0],known(registers,r[1]));
            else if(op.equals("const")) {require(x.literal==0||x.literal==1,"memo_read_constant");registers.put(r[0],Long.valueOf(x.literal));}
            else if(op.startsWith("iget")) {
                require(known(registers,r[1])==SELF,"memo_read_foreign_receiver");
                Object value=fields.get(x.reference);require(value!=null,"memo_read_unknown_field");registers.put(r[0],value);
            } else if(op.startsWith("iput")) {
                require(known(registers,r[1])==SELF,"memo_write_foreign_receiver");Object value=known(registers,r[0]);
                if(caches.contains(x.reference))require(value==RESULT,"memo_cache_not_supplier_result");
                else if(ready.contains(x.reference)||source.equals(x.reference)) {
                    require(!caches.isEmpty()&&fields.get(caches.iterator().next())==RESULT,"memo_publish_before_result");
                    require(ready.contains(x.reference)?ONE.equals(value):ZERO.equals(value),"memo_state_write");
                } else throw new Rejected("memo_unreviewed_field_write");
                fields.put(x.reference,value);
            } else if(op.startsWith("invoke-")) {
                require(x.reference.equals(contract)&&r.length==1&&known(registers,r[0])==SOURCE,"memo_read_not_original_supplier");pending=RESULT;
            } else if(op.equals("move-result-object")) {
                require(pending==RESULT,"memo_missing_supplier_result");registers.put(r[0],pending);pending=null;
            } else if(op.equals("monitor-enter")) {
                Object value=known(registers,r[0]);require(value instanceof Lock||value==SELF,"memo_unknown_monitor");monitors.push(value);
            } else if(op.equals("monitor-exit")) {
                require(!monitors.isEmpty()&&monitors.pop()==known(registers,r[0]),"memo_unbalanced_monitor");
            } else if(op.equals("if-eqz")||op.equals("if-nez")) {
                Object value=known(registers,r[0]);boolean zero=ZERO.equals(value);
                require(zero||ONE.equals(value)||value==SOURCE,"memo_unknown_guard");
                if(op.equals("if-eqz")==zero)next=flow.index(x.target);
            } else if(op.equals("goto"))next=flow.index(x.target);
            else if(op.equals("return-object")) {
                require(known(registers,r[0])==RESULT&&monitors.isEmpty(),"memo_return_not_supplier_result");return;
            } else throw new Rejected("memo_exception_path_on_normal_flow");
            at=next;
        }
        throw new Rejected("memo_read_flow_budget");
    }

    private static void publish(Map<String,Object> fields,Set<String> caches,Set<String> ready,String source,boolean clears) {
        for(String member:caches)fields.put(member,RESULT);
        for(String member:ready)fields.put(member,ONE);
        if(clears)fields.put(source,ZERO);
    }

    private static void validateHandlers(Flow flow,Set<String> locks)throws Exception {
        for(GmsDexFile.TryBlock block:flow.code.tryBlocks)for(GmsDexFile.Handler handler:block.handlers) {
            require(handler.type==null,"memo_typed_exception_handler");
            Set<Integer> exceptionAliases=new HashSet<>();boolean thrown=false;
            for(int at=flow.index(handler.target),steps=0;at<flow.ins.size()&&steps++<16;at++) {
                GmsDexFile.Instruction x=flow.ins.get(at);String op=normalOp(x.opname);int[] r=x.registers;
                if(op.equals("move-exception")){require(exceptionAliases.isEmpty(),"memo_handler_exception_overwrite");exceptionAliases.add(r[0]);}
                else if(op.equals("move-object")){require(exceptionAliases.contains(r[1]),"memo_handler_unknown_move");exceptionAliases.add(r[0]);}
                else if(op.equals("monitor-exit")) {
                    Value lock=flow.at(at,r[0]);require(lock.param(0)||lock.kind.equals("field")
                            &&locks.contains(lock.reference)&&lock.arg(0).param(0),"memo_handler_unknown_monitor");
                } else if(op.equals("throw")){require(exceptionAliases.contains(r[0]),"memo_exception_replaced");thrown=true;break;}
                else require(op.equals("nop"),"memo_exception_swallowed");
            }
            require(thrown,"memo_handler_missing_rethrow");
        }
    }

    private static void verifyLock(Graph graph,String descriptor,String role)throws Exception {
        GmsDexFile.Method method=graph.add(role,descriptor);Flow flow=new Flow(method);
        require(method.parameterTypes.isEmpty()&&flow.code.triesSize==0,"memo_lock_signature");int calls=0,returns=0;
        for(int i=0;i<flow.ins.size();i++) {
            GmsDexFile.Instruction x=flow.ins.get(i);String op=normalOp(x.opname);
            if(op.equals("invoke-direct")) {Value call=flow.call(i);require(x.reference.equals(OBJECT_INIT)
                    &&call.args.size()==1&&call.arg(0).param(0),"memo_lock_constructor");calls++;}
            else if(op.equals("return-void"))returns++;
            else require(op.equals("nop")||op.equals("move-object"),"memo_lock_side_effect");
        }
        require(calls==1&&returns==1,"memo_lock_constructor_shape");verifyNoInitializer(graph,method.owner,role+"Initializer");
    }

    private static void verifyNoInitializer(Graph graph,String type,String role)throws Exception {
        GmsDexFile.Method init=graph.dex.findMethod(type+"-><clinit>()V");if(init==null)return;
        graph.add(role,init.descriptor);
        for(GmsDexFile.Instruction x:code(init).instructions)require(x.opname.equals("nop")||x.opname.equals("return-void"),"memo_class_initializer_effect");
    }

    private static boolean dominates(Flow flow,int required,int sink) {
        Set<Integer> seen=new HashSet<>();ArrayDeque<Integer> queue=new ArrayDeque<>();queue.add(0);
        while(!queue.isEmpty()){int at=queue.remove();if(at==required||!seen.add(at))continue;if(at==sink)return false;queue.addAll(flow.next.get(at));}
        return true;
    }

    private static boolean assignable(Graph graph,String type,String target,int depth)throws Exception {
        if(type.equals(target)||target.equals("Ljava/lang/Object;"))return true;if(depth>MAX_DEPTH)return false;
        GmsDexFile.ClassDef definition=graph.dex.findClass(type);if(definition==null)return false;
        for(String contract:definition.interfaces)if(assignable(graph,contract,target,depth+1))return true;
        return definition.superclass!=null&&assignable(graph,definition.superclass,target,depth+1);
    }

    private static Object known(Map<Integer,Object> values,int register)throws Exception {
        Object value=values.get(register);require(value!=null,"memo_undefined_register");return value;
    }

    private GmsMemoProof(){}
}
