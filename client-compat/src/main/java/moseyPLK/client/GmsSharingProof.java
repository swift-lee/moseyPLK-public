package moseyPLK.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.FieldData;
import org.luckypray.dexkit.result.MethodData;
import static moseyPLK.client.GmsAdaptiveResolver.*;
import static moseyPLK.client.GmsSemanticProof.*;

/** Connections are proven on the used objects and branch edges, not caller counts. */
final class GmsSharingProof {
    static void verify(DexKitBridge bridge,Graph graph,Gate gate)throws Exception {
        GmsDexFile.Method serviceCtor=graph.add("serviceConstructor",SERVICE+"-><init>()V");Flow ctor=new Flow(serviceCtor);
        String contract=null;GmsDexFile.ClassDef supplierClass=graph.dex.findClass(owner(graph.supplier));
        for(String iface:supplierClass.interfaces)if(graph.dex.findMethod(iface+"->"+suffix(graph.supplier))!=null){require(contract==null,"supplier_contract_ambiguity");contract=iface;}
        require(contract!=null,"supplier_contract_missing");graph.identity("supplierContract",contract);graph.add("supplierInterface",contract+"->"+suffix(graph.supplier));
        String memoField=null,memoFactory=null;
        for(int i=0;i<ctor.ins.size();i++){GmsDexFile.Instruction x=ctor.ins.get(i);if(x.opname.equals("iput-object")&&ctor.at(i,x.registers[1]).param(0)){
            Value v=ctor.at(i,x.registers[0]);if(v.kind.equals("call")&&v.args.size()==1&&v.arg(0).is("new-instance",supplierClass.descriptor)){
                require(memoField==null,"supplier_to_memo_ambiguity");Value created=GmsFlagProof.constructor(ctor,v.arg(0));
                require(created.reference.equals(supplierClass.descriptor+"-><init>()V")&&v.reference.endsWith("("+contract+")"+contract)&&fieldType(x.reference).equals(contract),"supplier_to_memo_field_flow");
                memoField=x.reference;memoFactory=v.reference;
            }
        }}require(memoField!=null,"supplier_to_memo_field_missing");graph.identity("memoField",memoField);GmsFlagProof.stored(ctor,memoField,null);
        FieldData field=bridge.getFieldData(memoField);require(field!=null&&descriptors(field.getWriters()).equals(new LinkedHashSet<String>(Arrays.asList(serviceCtor.descriptor))),"memo_field_writers");
        GmsMemoProof.verify(bridge,graph,memoFactory,contract,graph.supplier);
        GmsDexFile.Method onCreate=graph.add("onCreate",SERVICE+"->onCreate()V");Flow startup=new Flow(onCreate);
        List<MethodData> stopCandidates=bridge.findMethod(FindMethod.create().matcher(MethodMatcher.create().usingEqStrings("Shutting down")));
        require(stopCandidates.size()<=64&&field.getReaders().size()<=128,"registry_candidate_budget");
        List<String> proven=new ArrayList<>();Rejected last=null;
        for(MethodData stop:stopCandidates){if(stop.getParamCount()!=0||!stop.getReturnTypeName().equals("void"))continue;
            for(MethodData reader:field.getReaders())if(owner(reader.getDescriptor()).equals(SERVICE)){
                if(!descriptors(reader.getInvokes()).contains(stop.getDescriptor()))continue;
                GmsDexFile.Method lifecycle=graph.dex.findMethod(reader.getDescriptor());if(lifecycle==null||lifecycle.codeOffset==0)continue;
                graph.decode(lifecycle);Flow lf=new Flow(lifecycle);if(lf.calls(stop.getDescriptor()).isEmpty())continue;
                for(int i=0;i<startup.ins.size();i++){GmsDexFile.Instruction x=startup.ins.get(i);if(x.opname.startsWith("invoke-")&&owner(x.reference).equals(owner(stop.getDescriptor()))&&x.reference.endsWith("()V")&&!x.reference.equals(stop.getDescriptor())&&!lf.calls(x.reference).isEmpty()){
                    try {verifyServiceGate(graph,startup,lf,gate,memoField,contract,stop.getDescriptor(),x.reference);proven.add(lifecycle.descriptor+"|"+stop.getDescriptor()+"|"+x.reference);}
                    catch(Rejected failure){last=failure;}
                }}
            }
        }
        require(proven.size()<=1,"registry_gate_ambiguity");if(proven.isEmpty()){if(last!=null)throw last;throw new Rejected("registry_gate_missing");}
        String[]parts=proven.get(0).split("\\|");graph.add("memoConsumer",parts[0]);GmsDexFile.Method stop=graph.add("registryStop",parts[1]),start=graph.add("registryStart",parts[2]);
        verifyRegistry(bridge,graph,start,stop);
        graph.proofs.add("sharing");
    }
    private static void verifyServiceGate(Graph graph,Flow startup,Flow lifecycle,Gate gate,String memo,String contract,String stop,String start)throws Exception {
        List<Integer>starts=startup.calls(start);require(starts.size()==1,"registry_start_site_ambiguity");int startAt=starts.get(0);Value registry=startup.call(startAt).arg(0);
        String registryPath=servicePath(registry);require(registryPath!=null,"registry_receiver_origin");boolean gated=false;
        for(String getter:gate.contracts)for(int call:startup.calls(getter)){
            Value receiver=startup.call(call).arg(0);require(receiver.kind.equals("call")&&receiver.args.size()==1&&receiver.arg(0).kind.equals("sget-object"),"startup_getter_receiver");
            GmsReceiverProof.verify(graph,gate,receiver.reference,receiver.arg(0).reference,"startupReceiver");
            if(startup.gated(startAt,call,true))gated=true;
        }require(gated,"startup_gate_control");
        List<Integer>lifeStarts=lifecycle.calls(start),lifeStops=lifecycle.calls(stop);
        for(int call:lifeStarts)require(registryPath.equals(servicePath(lifecycle.call(call).arg(0))),"registry_receiver_mismatch");
        for(int call:lifeStops)require(registryPath.equals(servicePath(lifecycle.call(call).arg(0))),"registry_receiver_mismatch");
        boolean connected=false;
        for(int call:lifecycle.calls(contract+"->"+suffix(gateSupplierContract(lifecycle,contract)))){
            Value read=lifecycle.call(call);if(!read.arg(0).is("field",memo)||!read.arg(0).arg(0).param(0))continue;
            for(int i=0;i<lifecycle.ins.size();i++){GmsDexFile.Instruction x=lifecycle.ins.get(i);if(!(x.opname.equals("if-eqz")||x.opname.equals("if-nez"))||!lifecycle.originCall(lifecycle.at(i,x.registers[0]),call))continue;
                int yes=x.opname.equals("if-nez")?lifecycle.index(x.target):i+1,no=x.opname.equals("if-eqz")?lifecycle.index(x.target):i+1;
                for(int sink:lifeStarts)if(lifecycle.reachable(yes,sink,-999,true)&&!lifecycle.reachable(no,sink,-999,true))connected=true;
            }
        }
        require(connected,"memo_gate_control");
    }
    private static String gateSupplierContract(Flow flow,String contract)throws Exception {
        String found=null;for(GmsDexFile.Instruction x:flow.ins)if(x.opname.startsWith("invoke-interface")&&owner(x.reference).equals(contract)&&x.reference.endsWith("()Ljava/lang/Object;")){
            if(found==null)found=x.reference;else require(found.equals(x.reference),"memo_read_contract_ambiguity");}
        require(found!=null,"memo_read_contract_missing");return found;
    }
    private static String servicePath(Value value){
        if(value.kind.equals("field")&&value.arg(0).param(0)&&owner(value.reference).equals(SERVICE))return value.reference;
        if(value.kind.equals("call")&&value.args.size()==1&&value.reference.equals("Ldagger/Lazy;->get()Ljava/lang/Object;"))return servicePath(value.arg(0));
        return null;
    }
    private static void verifyRegistry(DexKitBridge bridge,Graph graph,GmsDexFile.Method start,GmsDexFile.Method stop)throws Exception {
        Flow sf=new Flow(start);Value command=null;String send=null;
        for(int i=0;i<sf.ins.size();i++){GmsDexFile.Instruction x=sf.ins.get(i);if(x.opname.startsWith("invoke-")&&owner(x.reference).equals(start.owner)&&!suffix(x.reference).startsWith("<")&&sf.call(i).args.size()==2&&sf.call(i).arg(0).param(0)&&sf.call(i).arg(1).kind.equals("new-instance")){
            require(send==null,"registry_command_dispatch_ambiguity");send=x.reference;command=sf.call(i).arg(1);
        }}require(send!=null,"registry_command_dispatch");Value commandCtor=GmsFlagProof.constructor(sf,command);graph.add("registryCommandConstructor",commandCtor.reference);
        GmsDexFile.Method sender=graph.add("registrySend",send);List<GmsDexFile.Method>ctors=new ArrayList<>();for(GmsDexFile.Method m:graph.dex.findClass(start.owner).methods)if(m.name.equals("<init>"))ctors.add(m);
        require(ctors.size()==1,"registry_constructor_ambiguity");GmsDexFile.Method ctor=graph.add("registryConstructor",ctors.get(0).descriptor);Flow cf=new Flow(ctor);
        List<MethodData>reducers=bridge.findMethod(FindMethod.create().matcher(MethodMatcher.create().usingEqStrings("com.google.android.nearby.SHARING_PROVIDER","ExternalProviderRegistryBroadcastReceiver")));
        require(reducers.size()<=16,"registry_reducer_candidate_budget");
        List<MethodData>matches=new ArrayList<>();String root=null;
        for(MethodData m:reducers)for(GmsDexFile.Instruction x:cf.ins)if(x.opname.equals("sget-object")&&fieldType(x.reference).equals(owner(m.getDescriptor()))){matches.add(m);root=x.reference;}
        require(matches.size()==1,"registry_provider_reducer_ambiguity");GmsDexFile.Method reducer=graph.add("registryProviderReducer",matches.get(0).getDescriptor());graph.identity("registryInitialState",root);
        verifyStateDispatch(bridge,graph,cf,new Flow(sender),reducer,root);
        Flow rf=new Flow(reducer);List<Integer>query=rf.calls("Landroid/content/pm/PackageManager;->queryIntentServices(Landroid/content/Intent;I)Ljava/util/List;");require(query.size()==1,"provider_query_missing");
        Value intent=rf.call(query.get(0)).arg(1);require(intent.is("new-instance","Landroid/content/Intent;"),"provider_intent_origin");
        Value ic=GmsFlagProof.constructor(rf,intent);require(ic.reference.equals("Landroid/content/Intent;-><init>(Ljava/lang/String;)V")&&ic.arg(1).is("const-string","com.google.android.nearby.SHARING_PROVIDER"),"provider_query_action");
        boolean gated=false;for(int i=0;i<rf.ins.size();i++){GmsDexFile.Instruction x=rf.ins.get(i);if(x.opname.equals("instance-of")&&command.reference.equals(x.reference)){
            Value v=rf.at(i,x.registers[1]);require(v.kind.equals("param")&&v.literal>0,"reducer_command_origin");
            for(int j=0;j<rf.ins.size();j++){GmsDexFile.Instruction branch=rf.ins.get(j);Value cond=branch.registers.length==0?UNKNOWN:rf.at(j,branch.registers[0]);
                if((branch.opname.equals("if-eqz")||branch.opname.equals("if-nez"))&&cond.kind.equals("instance-of")&&cond.site==i){int yes=branch.opname.equals("if-nez")?rf.index(branch.target):j+1,no=branch.opname.equals("if-eqz")?rf.index(branch.target):j+1;
                    if(rf.reachable(yes,query.get(0),-999,true)&&!rf.reachable(no,query.get(0),-999,true))gated=true;}
            }
        }}require(gated,"registry_command_to_query_control");
        List<MethodData>binders=bridge.findMethod(FindMethod.create().matcher(MethodMatcher.create().usingEqStrings("NearbyExternalProviderRegistry","Bound to provider %s","Failed to bind to provider %s")));
        require(binders.size()<=16,"registry_bind_candidate_budget");
        MethodData bound=null;int bindAt=-1;
        for(MethodData m:binders)for(int i:rf.calls(m.getDescriptor())){require(bound==null,"registry_bind_anchor_ambiguity");bound=m;bindAt=i;}
        require(bound!=null,"registry_bind_connection_missing");Value service=rf.call(bindAt).arg(0);
        require(service.is("field","Landroid/content/pm/ResolveInfo;->serviceInfo:Landroid/content/pm/ServiceInfo;"),"provider_service_origin");
        require(queryCollectionFlow(rf,service.arg(0),query.get(0),new HashSet<String>(),0),"provider_query_to_binding_flow");
        GmsDexFile.Method binder=graph.add("registryProviderBind",bound.getDescriptor());verifyBind(graph,binder);
    }
    private static boolean queryCollectionFlow(Flow flow,Value value,int query,Set<String>visited,int depth)throws Exception {
        if(depth>12)return false;if(value.kind.equals("call")&&value.site==query)return true;
        if(value.kind.equals("call")&&(value.reference.equals("Ljava/util/Iterator;->next()Ljava/lang/Object;")||value.reference.endsWith("->iterator()Ljava/util/Iterator;")))return queryCollectionFlow(flow,value.arg(0),query,visited,depth+1);
        if(value.kind.equals("new-instance")&&(value.reference.equals("Ljava/util/ArrayList;")||value.reference.equals("Ljava/util/LinkedList;"))){
            if(!visited.add(value.reference+value.site))return false;boolean found=false;
            for(int i:flow.calls("Ljava/util/Collection;->add(Ljava/lang/Object;)Z"))if(same(flow.call(i).arg(0),value)){
                if(!queryCollectionFlow(flow,flow.call(i).arg(1),query,visited,depth+1))return false;found=true;
            }return found;
        }return false;
    }
    private static void verifyStateDispatch(DexKitBridge bridge,Graph graph,Flow constructor,Flow send,GmsDexFile.Method reducer,String root)throws Exception {
        // Direct dispatch (also used by the complete test fixture).
        for(int i=0;i<send.ins.size();i++)if(send.ins.get(i).opname.startsWith("invoke-")&&suffix(send.ins.get(i).reference).equals(suffix(reducer.descriptor))){
            Value call=send.call(i);for(int a=1;a<call.args.size();a++)if(call.arg(a).param(1)&&call.arg(0).kind.equals("field")&&call.arg(0).arg(0).param(0)){
                Value state=GmsFlagProof.stored(constructor,call.arg(0).reference,null);require(state.is("sget-object",root),"registry_state_receiver");return;
            }
        }
        // Coroutine actor: command send and actor receive must share the exact
        // constructor value, and the reducer receiver must come from the state
        // container initialized with this root. Framework scheduling is a boundary.
        String channel=null;for(int i=0;i<send.ins.size();i++)if(send.ins.get(i).opname.startsWith("invoke-interface")){
            Value call=send.call(i);if(call.args.size()==2&&call.arg(1).param(1)&&call.arg(0).kind.equals("field")&&call.arg(0).arg(0).param(0)){require(channel==null,"registry_channel_ambiguity");channel=call.arg(0).reference;}
        }require(channel!=null,"registry_command_not_forwarded");Value channelOrigin=GmsFlagProof.stored(constructor,channel,null);Set<String>channelFields=new LinkedHashSet<>(),stateFields=new LinkedHashSet<>();
        for(int i=0;i<constructor.ins.size();i++){GmsDexFile.Instruction x=constructor.ins.get(i);if(!x.opname.equals("iput-object")||!constructor.at(i,x.registers[1]).param(0))continue;Value value=constructor.at(i,x.registers[0]);
            if(same(value,channelOrigin))channelFields.add(x.reference);
            if(value.kind.equals("new-instance")){Value init=GmsFlagProof.constructor(constructor,value);for(Value arg:init.args)if(arg.is("sget-object",root))stateFields.add(x.reference);}
        }require(!stateFields.isEmpty(),"registry_initial_state_flow");
        Set<String>classes=new LinkedHashSet<>();for(int i=0;i<constructor.ins.size();i++){GmsDexFile.Instruction x=constructor.ins.get(i);if(x.opname.startsWith("invoke-direct")&&suffix(x.reference).startsWith("<init>(")){Value call=constructor.call(i);for(int a=1;a<call.args.size();a++)if(call.arg(a).param(0)){recordCapture(graph,call,a,"registryActorCapture");classes.add(owner(x.reference));}}}
        boolean matched=false;Set<String>seen=new LinkedHashSet<>();
        for(int depth=0;depth<3&&!classes.isEmpty();depth++){
            Set<String>next=new LinkedHashSet<>();for(String cls:classes){if(!seen.add(cls))continue;require(seen.size()<=12,"registry_actor_budget");GmsDexFile.ClassDef def=graph.dex.findClass(cls);if(def==null)continue;
                for(GmsDexFile.Method method:def.methods){if(!method.name.equals("invokeSuspend"))continue;Flow flow=new Flow(method);boolean state=false,receive=false,reduces=false;
                    for(int i=0;i<flow.ins.size();i++){GmsDexFile.Instruction x=flow.ins.get(i);
                        if(x.opname.startsWith("iget")&&stateFields.contains(x.reference)&&registryCapture(graph,flow.at(i,x.registers[1]),constructor.method.owner))state=true;
                        if(x.opname.startsWith("iget")&&channelFields.contains(x.reference)&&registryCapture(graph,flow.at(i,x.registers[1]),constructor.method.owner))receive=true;
                        if(x.opname.startsWith("invoke-interface")&&suffix(x.reference).equals(suffix(reducer.descriptor))){Value call=flow.call(i);
                            require(call.arg(0).kind.equals("call")&&call.arg(0).arg(0).kind.equals("field")&&stateFields.contains(call.arg(0).arg(0).reference),"registry_actor_state_flow");
                            Value stateValue=GmsFlagProof.stored(constructor,call.arg(0).arg(0).reference,null);
                            verifyInitialStateGetter(graph,constructor,stateValue,call.arg(0).reference,root);
                            require(call.arg(1).kind.equals("call")&&call.arg(1).reference.endsWith("()Ljava/lang/Object;"),"registry_actor_command_flow");
                            int nextSite=call.arg(1).site;GmsDexFile.Instruction nextCall=flow.ins.get(nextSite);boolean[]rootSeen={false};
                            require(iteratorOrigin(bridge,graph,flow,nextSite,nextCall.registers[0],channelFields,constructor.method.owner,new HashSet<String>(),rootSeen,0)&&rootSeen[0],"registry_actor_iterator_flow");reduces=true;
                        }
                        if(x.opname.startsWith("invoke-direct")&&suffix(x.reference).startsWith("<init>(")){Value call=flow.call(i);for(int a=1;a<call.args.size();a++)if(registryCapture(graph,call.arg(a),constructor.method.owner)){recordCapture(graph,call,a,"registryNestedCapture");next.add(owner(x.reference));}}
                    }
                    graph.add("registryActor"+seen.size()+"_"+method.name,method.descriptor);
                    if(state&&receive&&reduces)matched=true;
                }
            }classes=next;
        }require(matched,"registry_actor_connection");
    }
    private static final class InitialObject {
        final Flow constructor;final List<Object> arguments;
        InitialObject(Flow constructor,List<Object> arguments){this.constructor=constructor;this.arguments=arguments;}
    }
    private static final class StaticObject {
        final String field;StaticObject(String field){this.field=field;}
        @Override public boolean equals(Object other){return other instanceof StaticObject&&field.equals(((StaticObject)other).field);}
        @Override public int hashCode(){return field.hashCode();}
    }
    private static Object initialValue(Graph graph,Flow flow,List<Object>arguments,Value value,int depth)throws Exception {
        require(depth<8,"registry_state_constructor_depth");
        if(value.kind.equals("param")){require(value.literal>=0&&value.literal<arguments.size(),"registry_state_parameter");return arguments.get((int)value.literal);}
        if(value.kind.equals("sget-object"))return new StaticObject(value.reference);
        if(value.kind.equals("const"))return Long.valueOf(value.literal);
        if(value.kind.equals("new-instance")){
            Value call=GmsFlagProof.constructor(flow,value);GmsDexFile.Method method=graph.add("registryStateConstructor"+depth+"_"+value.reference,call.reference);
            List<Object>args=new ArrayList<>();args.add(null);for(int i=1;i<call.args.size();i++)args.add(initialValue(graph,flow,arguments,call.arg(i),depth+1));
            InitialObject object=new InitialObject(new Flow(method),args);args.set(0,object);return object;
        }
        if(value.kind.equals("field")){Object object=initialValue(graph,flow,arguments,value.arg(0),depth+1);require(object instanceof InitialObject,"registry_state_field_owner");InitialObject initial=(InitialObject)object;
            Value stored=GmsFlagProof.stored(initial.constructor,value.reference,null);return initialValue(graph,initial.constructor,initial.arguments,stored,depth+1);}
        throw new Rejected("registry_state_initial_value");
    }
    private static void verifyInitialStateGetter(Graph graph,Flow constructor,Value state,String getter,String root)throws Exception {
        // A state-flow getter may decode its private null sentinel. Evaluate only
        // the initial object graph, proving its nonnull initial reducer is returned.
        List<Object>parameters=new ArrayList<>();for(int i=0;i<constructor.code.insSize;i++)parameters.add("external"+i);
        Object initial=initialValue(graph,constructor,parameters,state,0);GmsDexFile.Method method=graph.add("registryStateGetter",getter);GmsDexFile.Code code=GmsAdaptiveResolver.code(method);
        require(code.triesSize==0&&code.insSize==1,"registry_state_getter_contract");Object[]registers=new Object[code.registersSize];registers[code.registersSize-1]=initial;int position=0,steps=0;
        while(position<code.instructions.size()){
            require(++steps<=128,"registry_state_getter_budget");GmsDexFile.Instruction x=code.instructions.get(position);String op=normalOp(x.opname);int[]r=x.registers;
            if(op.equals("iget-object")){require(registers[r[1]] instanceof InitialObject,"registry_state_getter_receiver");InitialObject object=(InitialObject)registers[r[1]];
                Value stored=GmsFlagProof.stored(object.constructor,x.reference,null);registers[r[0]]=initialValue(graph,object.constructor,object.arguments,stored,0);
            }else if(op.equals("sget-object"))registers[r[0]]=new StaticObject(x.reference);
            else if(op.startsWith("move-object"))registers[r[0]]=registers[r[1]];
            else if(op.equals("const"))registers[r[0]]=Long.valueOf(x.literal);
            else if(op.equals("check-cast")||op.equals("nop")){}
            else if(op.equals("if-eq")||op.equals("if-ne")){
                Object left=registers[r[0]],right=registers[r[1]];boolean equal=java.util.Objects.equals(left,right);
                if(!equal&&left instanceof StaticObject&&right instanceof StaticObject)require(!fieldType(((StaticObject)left).field).equals(fieldType(((StaticObject)right).field)),"registry_state_sentinel_alias");
                if(equal==op.equals("if-eq")){position=instructionIndex(code,x.target);continue;}
            }else if(op.equals("goto")){position=instructionIndex(code,x.target);continue;}
            else if(op.equals("return-object")){require(new StaticObject(root).equals(registers[r[0]]),"registry_state_getter_changed");return;}
            else throw new Rejected("registry_state_getter_operation");position++;
        }throw new Rejected("registry_state_getter_return");
    }
    private static int instructionIndex(GmsDexFile.Code code,int pc)throws Exception{for(int i=0;i<code.instructions.size();i++)if(code.instructions.get(i).pc==pc)return i;throw new Rejected("registry_state_getter_target");}
    private static boolean iteratorOrigin(DexKitBridge bridge,Graph graph,Flow flow,int site,int register,Set<String>channelFields,String registry,Set<String>seen,boolean[]rootSeen,int depth)throws Exception {
        require(depth<=96,"registry_actor_origin_budget");String key=flow.method.descriptor+":"+site+":"+register;if(!seen.add(key))return true;
        Set<Integer>defs=flow.incoming[site][register];if(defs==null||defs.isEmpty())return false;
        for(int def:defs){if(def<0)return false;GmsDexFile.Instruction x=flow.ins.get(def);String op=normalOp(x.opname);
            if(op.equals("check-cast")){if(!iteratorOrigin(bridge,graph,flow,def,x.registers[0],channelFields,registry,seen,rootSeen,depth+1))return false;}
            else if(op.startsWith("move-object")){if(!iteratorOrigin(bridge,graph,flow,def,x.registers[1],channelFields,registry,seen,rootSeen,depth+1))return false;}
            else if(op.equals("move-result-object")){
                Value call=flow.call(def-1);if(!call.arg(0).kind.equals("field")||!channelFields.contains(call.arg(0).reference)||!registryCapture(graph,call.arg(0).arg(0),registry)||call.args.size()!=1)return false;rootSeen[0]=true;
            }else if(op.equals("iget-object")&&flow.at(def,x.registers[1]).param(0)&&owner(x.reference).equals(flow.method.owner)){
                FieldData field=bridge.getFieldData(x.reference);if(field==null)return false;Set<String>writers=descriptors(field.getWriters());if(!writers.equals(new LinkedHashSet<String>(Arrays.asList(flow.method.descriptor))))return false;
                boolean wrote=false;for(int i=0;i<flow.ins.size();i++){GmsDexFile.Instruction store=flow.ins.get(i);if(store.opname.equals("iput-object")&&x.reference.equals(store.reference)){
                    if(!flow.at(i,store.registers[1]).param(0)||!iteratorOrigin(bridge,graph,flow,i,store.registers[0],channelFields,registry,seen,rootSeen,depth+1))return false;wrote=true;
                }}if(!wrote)return false;
            }else return false;
        }return true;
    }
    private static boolean registryCapture(Graph graph,Value value,String registry){return value.kind.equals("field")&&fieldType(value.reference).equals(registry)&&value.arg(0).param(0)&&graph.identities.containsValue(value.reference);}
    private static void recordCapture(Graph graph,Value call,int parameter,String role)throws Exception {
        GmsDexFile.Method constructor=graph.add(role+owner(call.reference),call.reference);Flow flow=new Flow(constructor);
        String field=GmsFlagProof.parameterField(flow,parameter);require((field(graph.dex,field).accessFlags&16)!=0,"registry_mutable_capture");
        GmsFlagProof.stored(flow,field,null);graph.identity("registryCapture"+field,field);
    }
    private static void verifyBind(Graph graph,GmsDexFile.Method bind)throws Exception {
        Flow flow=new Flow(bind);List<Integer>filters=flow.callsSuffix("(Landroid/content/pm/ServiceInfo;Landroid/content/Context;)Z");require(filters.size()==1,"registry_provider_filter_ambiguity");int filter=filters.get(0);
        Value filterCall=flow.call(filter);require(filterCall.arg(0).param(0)&&filterCall.arg(1).param(parameterSlot(bind,"Landroid/content/Context;")),"provider_filter_service_origin");graph.add("registryProviderFilter",filterCall.reference);
        boolean found=false;for(int i=0;i<flow.ins.size();i++){GmsDexFile.Instruction x=flow.ins.get(i);if(!x.opname.startsWith("invoke-")||!x.reference.contains("Landroid/content/Intent;Landroid/content/ServiceConnection;"))continue;
            Value call=flow.call(i);int contextArgument=argumentSlot(x,"Landroid/content/Context;");if(owner(x.reference).equals("Landroid/content/Context;"))contextArgument=0;
            require(contextArgument>=0&&call.arg(contextArgument).param(parameterSlot(bind,"Landroid/content/Context;")),"provider_bind_context_origin");
            int connectionArgument=argumentSlot(x,"Landroid/content/ServiceConnection;");Value connection=call.arg(connectionArgument);
            require(connection.kind.equals("new-instance")&&assignable(graph,connection.reference,"Landroid/content/ServiceConnection;",new HashSet<String>(),0),"provider_connection_origin");
            Value connectionCtor=GmsFlagProof.constructor(flow,connection);GmsDexFile.Method connectionConstructor=graph.add("providerConnectionConstructor",connectionCtor.reference);
            int infoArgument=parameterSlot(connectionConstructor,"Landroid/content/pm/ServiceInfo;");if(infoArgument>=0)require(connectionCtor.arg(infoArgument).param(0),"provider_connection_service_origin");
            int intent=-1;for(int a=0;a<call.args.size();a++)if(call.arg(a).is("new-instance","Landroid/content/Intent;"))intent=a;if(intent<0)continue;
            require(flow.gated(i,filter,true),"provider_filter_control");Value object=call.arg(intent);boolean component=false;
            for(int j=0;j<flow.ins.size();j++){GmsDexFile.Instruction set=flow.ins.get(j);if(!set.opname.startsWith("invoke-"))continue;Value sc=flow.call(j);if(!same(sc.arg(0),object))continue;
                if(set.reference.equals("Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;"))component=sc.arg(1).is("field","Landroid/content/pm/ServiceInfo;->packageName:Ljava/lang/String;")&&sc.arg(1).arg(0).param(0)&&sc.arg(2).is("field","Landroid/content/pm/ServiceInfo;->name:Ljava/lang/String;")&&sc.arg(2).arg(0).param(0);
                if(set.reference.equals("Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;")){
                    Value source=sc.arg(1);require(source.kind.equals("call")&&source.arg(0).param(0),"provider_component_source");verifyComponent(graph,source.reference);component=true;
                }
                            if(set.reference.equals("Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;")||set.reference.equals("Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;"))require(component&&flow.dominates(j,i),"provider_component_control");
                if(owner(set.reference).equals("Landroid/content/Intent;"))require(suffix(set.reference).startsWith("<init>(")||suffix(set.reference).startsWith("setClassName(")||suffix(set.reference).startsWith("setComponent(")||suffix(set.reference).equals("putExtras(Landroid/content/Intent;)Landroid/content/Intent;"),"provider_component_mutation");
            }require(component,"provider_component_flow");
            for(int j=0;j<flow.ins.size();j++){GmsDexFile.Instruction use=flow.ins.get(j);if(!use.opname.startsWith("invoke-")||j==i)continue;Value used=flow.call(j);boolean escapes=false;for(Value arg:used.args)if(same(arg,object))escapes=true;
                if(escapes)require(owner(use.reference).equals("Landroid/content/Intent;")&&same(used.arg(0),object),"provider_intent_escape");
            }
            if(owner(x.reference).equals("Landroid/content/Context;"))require(suffix(x.reference).startsWith("bindService("),"provider_bind_terminal");
            else require(reachesBindService(graph,x.reference,0,new HashSet<String>()),"provider_bind_terminal");
            found=true;
        }require(found,"provider_bind_terminal");
    }
    private static void verifyComponent(Graph graph,String method)throws Exception {
        GmsDexFile.Method m=graph.add("providerComponent",method);Flow flow=new Flow(m);Value value=GmsFlagProof.onlyReturn(flow,"return-object");require(value.is("new-instance","Landroid/content/ComponentName;"),"provider_component_return");Value init=GmsFlagProof.constructor(flow,value);
        require(init.arg(1).is("field","Landroid/content/pm/ServiceInfo;->packageName:Ljava/lang/String;")&&init.arg(1).arg(0).param(0)&&init.arg(2).is("field","Landroid/content/pm/ServiceInfo;->name:Ljava/lang/String;")&&init.arg(2).arg(0).param(0),"provider_component_arguments");
    }
    private static boolean assignable(Graph graph,String type,String target,Set<String>seen,int depth)throws Exception {
        if(type.equals(target))return true;if(depth>6||!seen.add(type))return false;GmsDexFile.ClassDef definition=graph.dex.findClass(type);if(definition==null)return false;
        for(String iface:definition.interfaces)if(assignable(graph,iface,target,seen,depth+1))return true;
        return definition.superclass!=null&&assignable(graph,definition.superclass,target,seen,depth+1);
    }
    private static int parameterSlot(GmsDexFile.Method method,String type){int slot=(method.accessFlags&8)==0?1:0;for(String parameter:method.parameterTypes){if(parameter.equals(type))return slot;slot+=parameter.equals("J")||parameter.equals("D")?2:1;}return -1;}
    private static int argumentSlot(GmsDexFile.Instruction instruction,String type)throws Exception {
        String descriptor=instruction.reference;int slot=instruction.opname.startsWith("invoke-static")?0:1;
        String parameters=descriptor.substring(descriptor.indexOf('(')+1,descriptor.indexOf(')'));
        for(int i=0;i<parameters.length();){int end=i+1;if(parameters.charAt(i)=='L')end=parameters.indexOf(';',i)+1;else if(parameters.charAt(i)=='['){while(parameters.charAt(end)=='[')end++;end=parameters.charAt(end)=='L'?parameters.indexOf(';',end)+1:end+1;}
            String parameter=parameters.substring(i,end);if(parameter.equals(type))return slot;slot+=parameter.equals("J")||parameter.equals("D")?2:1;i=end;
        }return -1;
    }
    private static boolean connectionOrigin(Graph graph,Flow flow,int site,int register,int parameter,Set<String>seen,boolean[]rootSeen,int depth)throws Exception {
        require(depth<64,"provider_connection_origin_budget");String key=site+":"+register;if(!seen.add(key))return true;
        Set<Integer>defs=flow.incoming[site][register];if(defs==null||defs.isEmpty())return false;
        for(int def:defs){
            if(def<0){if(def==Integer.MIN_VALUE||-1-def-(flow.code.registersSize-flow.code.insSize)!=parameter)return false;rootSeen[0]=true;continue;}
            GmsDexFile.Instruction x=flow.ins.get(def);String op=normalOp(x.opname);
            if(op.startsWith("move-object")){if(!connectionOrigin(graph,flow,def,x.registers[1],parameter,seen,rootSeen,depth+1))return false;}
            else if(op.equals("check-cast")){require(x.reference.equals("Landroid/content/ServiceConnection;"),"provider_connection_cast");if(!connectionOrigin(graph,flow,def,x.registers[0],parameter,seen,rootSeen,depth+1))return false;}
            else if(op.equals("move-result-object")&&def>0){GmsDexFile.Instruction factory=flow.ins.get(def-1);
                if(!factory.opname.startsWith("invoke-static")||factory.registers.length!=1||!connectionOrigin(graph,flow,def-1,factory.registers[0],parameter,seen,rootSeen,depth+1))return false;
                String proof="connection:"+factory.reference;if(!graph.proofs.contains(proof)){GmsConnectionProof.verify(graph,factory.reference);graph.proofs.add(proof);}
            }else return false;
        }return true;
    }
    private static boolean intentGetter(String descriptor){String name=suffix(descriptor);return name.equals("getAction()Ljava/lang/String;")||name.equals("getComponent()Landroid/content/ComponentName;");}
    private static boolean readOnlyIntent(Graph graph,String descriptor,int depth,Set<String>seen)throws Exception {
        if(depth>4||!seen.add(descriptor))return false;GmsDexFile.Method method=graph.dex.findMethod(descriptor);if(method==null||method.codeOffset==0)return false;
        graph.add("providerIntentObserver"+descriptor,descriptor);Flow flow=new Flow(method);int parameter=parameterSlot(method,"Landroid/content/Intent;");if(parameter<0)return false;
        for(int i=0;i<flow.ins.size();i++){GmsDexFile.Instruction x=flow.ins.get(i);if(x.opname.startsWith("iput")||x.opname.startsWith("sput")||x.opname.startsWith("aput"))if(flow.mayBeParameter(i,x.registers[0],parameter))return false;
            if(!x.opname.startsWith("invoke-"))continue;Value call=flow.call(i);boolean used=false;for(int register:x.registers)if(flow.mayBeParameter(i,register,parameter))used=true;if(!used)continue;
            if(owner(x.reference).equals("Landroid/content/Intent;")&&call.arg(0).param(parameter)){if(!intentGetter(x.reference))return false;}
            else {int slot=argumentSlot(x,"Landroid/content/Intent;");if(slot<0||!call.arg(slot).param(parameter)||!readOnlyIntent(graph,x.reference,depth+1,seen))return false;}
        }return true;
    }
    private static boolean reachesBindService(Graph graph,String descriptor,int depth,Set<String>seen)throws Exception {
        if(depth>4||seen.size()>12)return false;
        if(seen.contains(descriptor))return false;
        seen.add(descriptor);GmsDexFile.Method method=graph.dex.findMethod(descriptor);if(method==null||method.codeOffset==0)return false;
        graph.add("providerBindForward"+seen.size(),descriptor);Flow f=new Flow(method);
        int intentParameter=parameterSlot(method,"Landroid/content/Intent;"),contextParameter=parameterSlot(method,"Landroid/content/Context;"),connectionParameter=parameterSlot(method,"Landroid/content/ServiceConnection;");
        require(intentParameter>=0&&contextParameter>=0,"provider_bind_forward_signature");boolean found=false;
        for(int i=0;i<f.ins.size();i++){GmsDexFile.Instruction x=f.ins.get(i);if(!x.opname.startsWith("invoke-"))continue;Value call=f.call(i);
            int intent=argumentSlot(x,"Landroid/content/Intent;");
            if(intent>=0&&x.reference.contains("Landroid/content/ServiceConnection;")){
                require(call.arg(intent).param(intentParameter),"provider_bind_intent_forward");
                int connection=argumentSlot(x,"Landroid/content/ServiceConnection;");boolean[]rootSeen={false};
                require(connection>=0&&connectionParameter>=0&&connectionOrigin(graph,f,i,x.registers[connection],connectionParameter,new HashSet<String>(),rootSeen,0)&&rootSeen[0],"provider_bind_connection_forward");
                if(owner(x.reference).equals("Landroid/content/Context;")&&suffix(x.reference).startsWith("bindService(")){
                    require(call.arg(0).param(contextParameter),"provider_bind_context_forward");found=true;
                }else{
                    int context=argumentSlot(x,"Landroid/content/Context;");require(context>=0&&call.arg(context).param(contextParameter),"provider_bind_context_forward");
                    if(reachesBindService(graph,x.reference,depth+1,seen))found=true;
                }
            }
            boolean usesIntent=false;for(int register:x.registers)if(f.mayBeParameter(i,register,intentParameter))usesIntent=true;
            if(usesIntent){
                if(owner(x.reference).equals("Landroid/content/Intent;")&&call.arg(0).param(intentParameter))require(intentGetter(x.reference),"provider_bind_intent_mutation");
                else if(intent>=0&&!x.reference.contains("Landroid/content/ServiceConnection;"))require(readOnlyIntent(graph,x.reference,0,new HashSet<String>()),"provider_bind_intent_observer");
                else require(intent>=0,"provider_bind_intent_escape");
            }
        }return found;
    }
    private GmsSharingProof(){}
}
