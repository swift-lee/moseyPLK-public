package moseyPLK.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static moseyPLK.client.GmsAdaptiveResolver.*;
import static moseyPLK.client.GmsSemanticProof.*;

/** Flag identity and cache semantics, independent of obfuscated names and incidental layout. */
final class GmsFlagProof {
    private static final String ARRAY="Ljava/util/concurrent/atomic/AtomicReferenceArray;";
    private static final String GET=ARRAY+"->get(I)Ljava/lang/Object;";
    private static final String CAS=ARRAY+"->compareAndSet(ILjava/lang/Object;Ljava/lang/Object;)Z";
    private static final String NULLCHECK="Ljava/lang/Object;->getClass()Ljava/lang/Class;";
    static void verify(Graph graph,Gate gate,String prefix,String key)throws Exception {
        GmsDexFile.Method factory=graph.add(prefix+"Factory",gate.factory.getDescriptor());
        GmsDexFile.Method getter=graph.add(prefix+"Getter",gate.getter.getDescriptor());
        require((factory.accessFlags&8)!=0&&owner(factory.descriptor).equals(getter.owner),"getter_factory_owner");
        for(int i=1;i<gate.contracts.size();i++)graph.add(prefix+"Interface"+i,gate.contracts.get(i));
        Flow f=new Flow(factory);Value result=onlyReturn(f,"return-object");
        require(result.kind.equals("call")&&result.reference.contains("(ILjava/lang/String;Z)")&&result.args.size()==4,"factory_return_flow");
        Value config=result.arg(0),slot=result.arg(1),literal=result.arg(2),fallback=result.arg(3);
        require(config.kind.equals("sget-object")&&slot.kind.equals("const")&&slot.literal>=0&&literal.is("const-string",key)
                &&fallback.kind.equals("const")&&(fallback.literal==0||fallback.literal==1),"flag_key_default_or_index");
        graph.identity(prefix+"ConfigField",config.reference);
        require((field(graph.dex,config.reference).accessFlags&(8|16))==(8|16),"mutable_config_root");
        GmsDexFile.Method builder=graph.add(prefix+"ConfigBooleanBuilder",result.reference);
        rejectExtraCalls(f,Arrays.asList(result.reference));
        for(GmsDexFile.Instruction x:f.ins)if(x.opname.equals("check-cast"))require(x.reference.equals("Ljava/lang/Object;")||x.reference.equals(returnType(factory.descriptor)),"factory_unknown_cast");
        Flow g=new Flow(getter);Value returned=onlyReturn(g,"return");
        require(returned.is("call",UNBOX)&&returned.args.size()==1,"getter_operand_chain");
        Value read=returned.arg(0);
        require(read.kind.equals("call")&&read.args.size()==1&&read.arg(0).is("call",factory.descriptor)
                &&read.arg(0).args.isEmpty()&&read.reference.endsWith("()Ljava/lang/Object;")
                &&owner(read.reference).equals(returnType(factory.descriptor)),"getter_operand_chain");
        rejectExtraCalls(g,Arrays.asList(factory.descriptor,read.reference,UNBOX));
        for(GmsDexFile.Instruction x:g.ins)if(x.opname.equals("check-cast"))require(x.reference.equals("Ljava/lang/Object;")||x.reference.equals("Ljava/lang/Boolean;"),"getter_unknown_cast");
        graph.add(prefix+"FlagReaderInterface",read.reference);
        GmsDexFile.Method init=graph.add(prefix+"ConfigInitializer",getter.owner+"-><clinit>()V");
        Flow ci=new Flow(init);Value created=stored(ci,config.reference,null);
        require(created.is("new-instance",builder.owner),"config_initializer_flow");
        Value construction=constructor(ci,created);
        require(construction.args.size()==3&&construction.arg(1).kind.equals("sget-object")&&construction.arg(2).kind.equals("const")
                &&construction.arg(2).literal>slot.literal&&construction.arg(2).literal<=4096,"config_initializer_flow");
        String namespaceField=construction.arg(1).reference;require((field(graph.dex,namespaceField).accessFlags&(8|16))==(8|16),"mutable_namespace_root");graph.identity(prefix+"NamespaceField",namespaceField);
        GmsDexFile.Method configCtor=graph.add(prefix+"ConfigConstructor",construction.reference);
        Flow bc=new Flow(configCtor);String namespaceMember=parameterField(bc,1),arrayMember=null;
        for(int i=0;i<bc.ins.size();i++){GmsDexFile.Instruction x=bc.ins.get(i);if(x.opname.equals("iput-object")&&fieldType(x.reference).equals(ARRAY)){
            Value array=bc.at(i,x.registers[0]);require(bc.at(i,x.registers[1]).param(0)&&array.is("new-instance",ARRAY),"config_array_origin");
            Value ac=constructor(bc,array);require(ac.reference.equals(ARRAY+"-><init>(I)V")&&ac.arg(1).param(2),"config_array_capacity");
            require(arrayMember==null,"config_array_ambiguity");arrayMember=x.reference;
        }}require(arrayMember!=null,"config_array_missing");
        graph.identity(prefix+"ConfigArray",arrayMember);graph.identity(prefix+"ConfigNamespace",namespaceMember);
        require((field(graph.dex,namespaceMember).accessFlags&16)!=0&&(field(graph.dex,arrayMember).accessFlags&16)!=0,"mutable_config_members");
        GmsDexFile.Method nsInit=graph.add(prefix+"NamespaceInitializer",owner(namespaceField)+"-><clinit>()V");
        Flow ni=new Flow(nsInit);Value namespace=stored(ni,namespaceField,null);Value nc=constructor(ni,namespace);
        require(namespace.kind.equals("new-instance")&&nc.arg(1).is("const-string",NAMESPACE),"namespace_constructor_argument_flow");
        GmsDexFile.Method nsCtor=graph.add(prefix+"NamespaceConstructor",nc.reference);String namespaceName=parameterField(new Flow(nsCtor),1);
        verifyImmutableAssignments(graph,new Flow(nsCtor),Arrays.asList(namespaceName));
        require(graph.dex.findClass(namespace.reference).interfaces.contains(fieldType(namespaceField)),"namespace_interface_dispatch");
        Flow buildFlow=new Flow(builder);List<String> namespaceCalls=new ArrayList<>();
        for(int i=0;i<buildFlow.ins.size();i++){GmsDexFile.Instruction x=buildFlow.ins.get(i);if(x.opname.startsWith("invoke-interface")){
            Value call=buildFlow.call(i);if(call.arg(0).is("field",namespaceMember)&&call.arg(0).arg(0).param(0)){
                require(call.args.size()==3&&call.arg(1).param(2)&&call.arg(2).param(3),"namespace_builder_argument_flow");namespaceCalls.add(x.reference);
            }
        }}require(namespaceCalls.size()==1,"namespace_builder_receiver_contract");
        GmsDexFile.Method booleanFactory=graph.add(prefix+"NamespaceBooleanFactory",namespace.reference+"->"+suffix(namespaceCalls.get(0)));
        verifyBuilder(graph,builder,prefix,arrayMember,namespaceMember,namespaceCalls.get(0));
        Flow bf=new Flow(booleanFactory);Value flag=onlyReturn(bf,"return-object"),fc=constructor(bf,flag);
        require(flag.kind.equals("new-instance")&&(fc.args.size()==4||fc.args.size()==5)&&fc.arg(1).is("field",namespaceName)&&fc.arg(1).arg(0).param(0)
                &&fc.arg(2).param(1)&&fc.arg(fc.args.size()-1).param(2),"namespace_boolean_return_flow");
        verifyFlagConstructors(graph,prefix,fc.reference,read.reference);
        graph.proofs.add(prefix+"Flag");
    }
    static Value onlyReturn(Flow flow,String opcode)throws Exception {
        Value result=null;int returns=0;for(int i=0;i<flow.ins.size();i++){GmsDexFile.Instruction x=flow.ins.get(i);if(x.opname.equals(opcode)){
            Value v=flow.at(i,x.registers[0]);require(v!=UNKNOWN,"ambiguous_return_origin");if(result==null)result=v;else require(same(result,v),"multiple_return_origins");returns++;
        }}require(returns>0,"missing_return");return result;
    }
    static Value stored(Flow flow,String target,Value receiver)throws Exception {
        Value result=null;for(int i=0;i<flow.ins.size();i++){GmsDexFile.Instruction x=flow.ins.get(i);if((x.opname.startsWith("iput")||x.opname.startsWith("sput"))&&target.equals(x.reference)){
            if(receiver!=null)require(same(receiver,flow.at(i,x.registers[1])),"field_receiver_mismatch");
            require(result==null,"field_multiple_writes");result=flow.at(i,x.registers[0]);
        }}require(result!=null&&result!=UNKNOWN,"field_value_origin");return result;
    }
    static Value constructor(Flow flow,Value object)throws Exception {
        require(object!=UNKNOWN,"constructor_object_unknown");Value found=null;
        for(int i=0;i<flow.ins.size();i++){GmsDexFile.Instruction x=flow.ins.get(i);if(x.opname.startsWith("invoke-direct")&&suffix(x.reference).startsWith("<init>(")){
            Value call=flow.call(i);if(same(call.arg(0),object)){require(found==null,"constructor_ambiguity");found=call;}
        }}require(found!=null,"constructor_missing");return found;
    }
    static String parameterField(Flow flow,int parameter)throws Exception {
        String found=null;for(int i=0;i<flow.ins.size();i++){GmsDexFile.Instruction x=flow.ins.get(i);if(x.opname.startsWith("iput")&&flow.at(i,x.registers[0]).param(parameter)&&flow.at(i,x.registers[1]).param(0)){
            require(found==null,"parameter_field_ambiguity");found=x.reference;
        }}require(found!=null,"parameter_field_missing");return found;
    }
    static void rejectExtraCalls(Flow flow,List<String> calls)throws Exception{
        require(flow.code.triesSize==0,"critical_exception_handler");
        for(GmsDexFile.Instruction x:flow.ins){if(x.opname.startsWith("invoke-"))require(calls.contains(x.reference),"critical_unknown_call");
            require(!x.opname.startsWith("iput")&&!x.opname.startsWith("sput")&&!x.opname.startsWith("aput"),"critical_side_effect");}
    }
    private static void verifyFlagConstructors(Graph graph,String prefix,String ctor,String readerContract)throws Exception {
        // Follow the namespace/key operands through every superclass constructor,
        // never infer identity merely from adjacent strings or signatures.
        int namespaceParameter=1,keyParameter=2;String concrete=owner(ctor),current=concrete,defaultField=null;List<String>hierarchy=new ArrayList<>();
        String nsField=null,keyField=null;GmsDexFile.Method reader=null;
        for(int depth=0;depth<MAX_DEPTH;depth++){
            hierarchy.add(current);GmsDexFile.Method m=graph.add(prefix+"FlagConstructor"+depth,ctor);Flow f=new Flow(m);
            for(int i=0;i<f.ins.size();i++){GmsDexFile.Instruction x=f.ins.get(i);if(x.opname.startsWith("iput")&&f.at(i,x.registers[1]).param(0)){
                Value v=f.at(i,x.registers[0]);if(v.param(namespaceParameter)&&fieldType(x.reference).equals("Ljava/lang/String;"))nsField=x.reference;
                if(v.param(keyParameter)&&fieldType(x.reference).equals("Ljava/lang/String;"))keyField=x.reference;
                if(depth==0&&v.param(f.code.insSize-1)&&x.opname.equals("iput-boolean"))defaultField=x.reference;
            }}
            GmsDexFile.Method candidate=graph.dex.findMethod(current+"->"+suffix(readerContract));if(reader==null&&candidate!=null&&candidate.codeOffset!=0)reader=candidate;
            Value superCall=null;for(int i=0;i<f.ins.size();i++){GmsDexFile.Instruction x=f.ins.get(i);if(x.opname.startsWith("invoke-direct")&&suffix(x.reference).startsWith("<init>(")&&f.call(i).arg(0).param(0)){
                require(superCall==null,"flag_constructor_super_ambiguity");superCall=f.call(i);
            }}require(superCall!=null,"flag_constructor_chain");
            if(owner(superCall.reference).equals("Ljava/lang/Object;"))break;
            require(owner(superCall.reference).equals(graph.dex.findClass(current).superclass),"flag_constructor_super_dispatch");
            int ns=-1,k=-1;for(int i=1;i<superCall.args.size();i++){if(superCall.arg(i).param(namespaceParameter))ns=i;if(superCall.arg(i).param(keyParameter))k=i;}
            require(ns>=0&&k>=0&&ns!=k,"flag_constructor_key_flow");namespaceParameter=ns;keyParameter=k;ctor=superCall.reference;current=owner(ctor);
        }
        require(nsField!=null&&keyField!=null&&!nsField.equals(keyField)&&defaultField!=null&&reader!=null,"flag_identity_storage");
        for(Map.Entry<String,GmsDexFile.Method> entry:graph.methods.entrySet())if(entry.getKey().startsWith(prefix+"FlagConstructor"))verifyImmutableAssignments(graph,new Flow(entry.getValue()),Arrays.asList(nsField,keyField,defaultField));
        graph.identity(prefix+"FlagNamespace",nsField);graph.identity(prefix+"FlagKey",keyField);graph.identity(prefix+"FlagDefaultField",defaultField);
        graph.add(prefix+"FlagReader",reader.descriptor);Flow r=new Flow(reader);Value result=onlyReturn(r,"return-object");
        require(result.kind.equals("call")&&hierarchy.contains(owner(result.reference))&&result.arg(0).param(0),"flag_reader_receiver");
        List<String> readerCalls=new ArrayList<>();readerCalls.add(result.reference);readerCalls.add(NULLCHECK);
        for(int i=1;i<result.args.size();i++){Value arg=result.arg(i);if(arg.kind.equals("call"))readerCalls.add(arg.reference);}
        for(int i=0;i<r.ins.size();i++){GmsDexFile.Instruction x=r.ins.get(i);if(!x.opname.startsWith("invoke-")||readerCalls.contains(x.reference))continue;
            Value checked=r.call(i);require(checked.args.size()==1&&same(checked.arg(0),result),"flag_reader_null_receiver");verifyNullHelper(graph,x.reference,prefix+"FlagReaderNullCheck");readerCalls.add(x.reference);
        }
        rejectExtraCalls(r,readerCalls);
        GmsDexFile.Method dispatch=null;for(String type:hierarchy){GmsDexFile.Method m=graph.dex.findMethod(type+"->"+suffix(result.reference));if(m!=null&&m.codeOffset!=0){dispatch=m;break;}}
        require(dispatch!=null,"flag_read_dispatch_missing");graph.add(prefix+"FlagReadDispatch",dispatch.descriptor);
        // The terminal config engine is deliberately outside the gate contract.
        // Require this same key-bearing instance to be forwarded, not a fresh flag.
        Flow dispatchFlow=new Flow(dispatch);Value dispatchReturn=onlyReturn(dispatchFlow,"return-object");require(dispatchReturn.kind.equals("call")&&dispatchReturn.arg(0).param(0),"flag_dispatch_receiver");rejectExtraCalls(dispatchFlow,Arrays.asList(dispatchReturn.reference));
        List<GmsDexFile.Method> defaults=new ArrayList<>();for(GmsDexFile.Method m:graph.dex.findClass(concrete).methods)if(m.parameterTypes.isEmpty()&&m.returnType.equals("Ljava/lang/Object;")&&!m.name.startsWith("<"))defaults.add(m);
        require(defaults.size()==1,"flag_default_ambiguity");GmsDexFile.Method d=graph.add(prefix+"FlagDefault",defaults.get(0).descriptor);Value dr=onlyReturn(new Flow(d),"return-object");
        require(dr.is("call",BOX)&&dr.arg(0).is("field",defaultField)&&dr.arg(0).arg(0).param(0),"flag_default_flow");rejectExtraCalls(new Flow(d),Arrays.asList(BOX));
    }
    private static void verifyImmutableAssignments(Graph graph,Flow flow,List<String> fields)throws Exception {
        require(flow.code.triesSize==0,"flag_constructor_exception_handler");
        for(String field:fields){require((field(graph.dex,field).accessFlags&16)!=0,"flag_mutable_identity");int count=0;
            for(GmsDexFile.Instruction x:flow.ins)if(x.opname.startsWith("iput")&&field.equals(x.reference))count++;
            require(count<=1,"flag_identity_reassigned");
            if(owner(field).equals(flow.method.owner)){require(count==1,"flag_identity_uninitialized");int store=-1;
                for(int i=0;i<flow.ins.size();i++)if(flow.ins.get(i).opname.startsWith("iput")&&field.equals(flow.ins.get(i).reference))store=i;
                for(int i=0;i<flow.ins.size();i++)if(flow.ins.get(i).opname.equals("return-void"))require(flow.dominates(store,i),"flag_identity_conditional_store");
            }
        }
        for(int i=0;i<flow.ins.size();i++){GmsDexFile.Instruction x=flow.ins.get(i);if(!x.opname.startsWith("invoke-"))continue;
            Value call=flow.call(i);boolean thisArgument=false;for(Value arg:call.args)if(arg.param(0))thisArgument=true;
            if(thisArgument)require(x.opname.startsWith("invoke-direct")&&suffix(x.reference).startsWith("<init>(")&&call.arg(0).param(0)
                    &&(owner(x.reference).equals("Ljava/lang/Object;")||owner(x.reference).equals(graph.dex.findClass(flow.method.owner).superclass)),"flag_constructor_this_escape");
        }
    }
    private static boolean isNullCheck(Graph graph,GmsDexFile.Instruction x)throws Exception {
        if(!x.opname.startsWith("invoke-virtual")||!suffix(x.reference).equals("getClass()Ljava/lang/Class;"))return false;
        return x.reference.equals(NULLCHECK)||graph.dex.findClass(owner(x.reference))!=null&&graph.dex.findMethod(x.reference)==null;
    }
    interface Calls {Object invoke(GmsDexFile.Instruction x,List<Object> args)throws Exception;}
    /** Exhaustive over the finite cache outcomes; never executes target bytecode. */
    static Object execute(GmsDexFile.Method method,Object[] parameters,Map<String,Object> fields,Calls calls)throws Exception {
        GmsDexFile.Code c=code(method);require(c.triesSize==0,"critical_exception_handler");Object[] values=new Object[c.registersSize];
        System.arraycopy(parameters,0,values,c.registersSize-c.insSize,parameters.length);Object result=null;int index=0,steps=0;
        while(index<c.instructions.size()){
            require(++steps<=512,"critical_execution_budget");GmsDexFile.Instruction x=c.instructions.get(index);String n=normalOp(x.opname);int[]rs=x.registers;
            if(n.equals("nop")||n.equals("check-cast")){}
            else if(n.startsWith("move-result"))values[rs[0]]=result;
            else if(n.startsWith("move"))values[rs[0]]=values[rs[1]];
            else if(n.equals("const"))values[rs[0]]=Long.valueOf(x.literal);
            else if(n.startsWith("iget")){require("this".equals(values[rs[1]])&&fields.containsKey(x.reference),"critical_field_read");values[rs[0]]=fields.get(x.reference);}
            else if(n.startsWith("invoke-")){List<Object>a=new ArrayList<>();for(int r:rs)a.add(values[r]);result=calls.invoke(x,a);}
            else if(n.equals("if-eqz")||n.equals("if-nez")){boolean nonzero=values[rs[0]]!=null&&!Long.valueOf(0).equals(values[rs[0]])&&!Boolean.FALSE.equals(values[rs[0]]);if(nonzero==n.equals("if-nez")){index=position(c,x.target);continue;}}
            else if(n.equals("goto")){index=position(c,x.target);continue;}
            else if(n.startsWith("return"))return n.equals("return-void")?"void":values[rs[0]];
            else throw new Rejected("critical_unknown_opcode:"+n);
            index++;
        }throw new Rejected("critical_missing_return");
    }
    private static int position(GmsDexFile.Code c,int pc)throws Exception{for(int i=0;i<c.instructions.size();i++)if(c.instructions.get(i).pc==pc)return i;throw new Rejected("critical_invalid_target");}
    private static void verifyBuilder(Graph graph,GmsDexFile.Method builder,String prefix,String array,String ns,String factory)throws Exception {
        for(GmsDexFile.Instruction x:code(builder).instructions)if(x.opname.equals("check-cast"))require(x.reference.equals(returnType(builder.descriptor))||x.reference.equals("Ljava/lang/Object;"),"builder_unknown_cast");
        for(int mode=0;mode<3;mode++){
            final int outcome=mode;final int[]gets={0},made={0},cas={0};Map<String,Object>fields=new HashMap<>();fields.put(array,"array");fields.put(ns,"namespace");
            Object returned=execute(builder,new Object[]{"this","slot","key","default"},fields,new Calls(){
                @Override public Object invoke(GmsDexFile.Instruction x,List<Object> a)throws Exception {
                if(x.reference.equals(GET)){require(a.equals(Arrays.<Object>asList("array","slot")),"builder_cache_slot");return gets[0]++==0?(outcome==0?"cached":null):"raced";}
                if(x.reference.equals(factory)){require(a.equals(Arrays.<Object>asList("namespace","key","default")),"builder_flag_arguments");made[0]++;return "created";}
                if(x.reference.endsWith("("+ARRAY+"ILjava/lang/Object;)Z")){
                    require(a.equals(Arrays.<Object>asList("array","slot","created")),"builder_cas_arguments");verifyCas(graph,x.reference,prefix);cas[0]++;return outcome==1;
                }
                require(a.size()==1&&"raced".equals(a.get(0)),"builder_null_check_receiver");
                if(!isNullCheck(graph,x))verifyNullHelper(graph,x.reference,prefix+"NullCheck");return "class";
                }
            });
            require((mode==0?"cached":mode==1?"created":"raced").equals(returned),"builder_return_provenance");
            require(gets[0]==(mode==2?2:1)&&made[0]==(mode==0?0:1)&&cas[0]==(mode==0?0:1),"builder_cache_control");
        }
    }
    private static void verifyCas(Graph graph,String descriptor,String prefix)throws Exception {
        GmsDexFile.Method method=graph.add(prefix+"ConfigCompareAndSet",descriptor);
        for(int mode=0;mode<3;mode++){
            final int scenario=mode;final int[]attempts={0},gets={0};Object result=execute(method,new Object[]{"array","slot","value"},new HashMap<String,Object>(),new Calls(){
                @Override public Object invoke(GmsDexFile.Instruction x,List<Object> a)throws Exception {
                if(x.reference.equals(CAS)){require(a.equals(Arrays.<Object>asList("array","slot",Long.valueOf(0),"value")),"cas_compare_operands");return ++attempts[0]>(scenario==2?1:0)&&scenario!=1;}
                require(x.reference.equals(GET)&&a.equals(Arrays.<Object>asList("array","slot")),"cas_unknown_operation");gets[0]++;return scenario==1?"raced":null;
                }
            });require(Long.valueOf(mode==1?0:1).equals(result)&&attempts[0]==(mode==2?2:1)&&gets[0]==(mode==0?0:1),"cas_control_flow");
        }
    }
    static void verifyNullHelper(Graph graph,String descriptor,String role)throws Exception {
        GmsDexFile.Method helper=graph.add(role,descriptor);require((helper.accessFlags&8)!=0&&helper.parameterTypes.equals(Arrays.asList("Ljava/lang/Object;"))&&helper.returnType.equals("V"),"null_helper_signature");
        for(GmsDexFile.Instruction x:code(helper).instructions){require(!x.opname.startsWith("if-")&&!x.opname.startsWith("goto"),"null_helper_conditional_check");if(x.opname.equals("check-cast"))require(x.reference.equals("Ljava/lang/Object;"),"null_helper_unknown_cast");}
        final int[]calls={0};Object result=execute(helper,new Object[]{"object"},new HashMap<String,Object>(),new Calls(){
            @Override public Object invoke(GmsDexFile.Instruction x,List<Object> args)throws Exception {
            require(x.reference.equals(NULLCHECK)&&args.equals(Arrays.<Object>asList("object")),"null_helper_side_effect");calls[0]++;return "class";
            }
        });require("void".equals(result)&&calls[0]==1,"null_helper_effect");
        String type=helper.owner;for(int depth=0;depth<MAX_DEPTH&&!type.equals("Ljava/lang/Object;");depth++){
            GmsDexFile.ClassDef cls=graph.dex.findClass(type);require(cls!=null,"null_helper_initializer_missing");GmsDexFile.Method init=graph.dex.findMethod(type+"-><clinit>()V");
            if(init!=null&&init.codeOffset!=0){graph.add(role+"Initializer"+depth,init.descriptor);for(GmsDexFile.Instruction x:code(init).instructions)
                require(x.opname.equals("return-void")||x.opname.equals("nop"),"null_helper_class_side_effect");}
            type=cls.superclass;
        }require(type.equals("Ljava/lang/Object;"),"null_helper_class_depth");
    }
    private GmsFlagProof(){}
}
