package moseyPLK.client;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Interprets only object construction and immutable receiver access, never target code.
 * Names, register moves and unrelated field initialization do not identify the
 * receiver. The returned object must originate from the actual singleton's
 * constructors and implement the selected getter contract.
 */
final class GmsReceiverProof {
    private static final Object UNKNOWN = new Object();
    private final GmsAdaptiveResolver.Graph graph;
    private final String prefix;
    private final Map<String,Object> statics = new HashMap<>();
    private final Map<String,String> methodRoles = new LinkedHashMap<>();
    private final Set<String> active = new HashSet<>();
    private int allocations;

    private static final class Instance {
        final String type;
        final Map<String,Object> fields = new HashMap<>();
        boolean initialized;
        Instance(String type) { this.type=type; }
    }

    private GmsReceiverProof(GmsAdaptiveResolver.Graph graph,String prefix) {
        this.graph=graph;this.prefix=prefix;
    }

    static void verify(GmsAdaptiveResolver.Graph graph,GmsAdaptiveResolver.Gate gate,
            String accessor,String root,String prefix) throws Exception {
        new GmsReceiverProof(graph,prefix).verify(gate,accessor,root);
    }

    private void verify(GmsAdaptiveResolver.Gate gate,String accessor,String root) throws Exception {
        GmsDexFile.Field field=GmsAdaptiveResolver.field(graph.dex,root);
        require((field.accessFlags & (8|16))==(8|16),"mutable_root");
        require(field.type.equals(GmsAdaptiveResolver.owner(accessor)),"root_accessor_type");
        graph.identity(prefix+"ReceiverRoot",root);
        execute(GmsAdaptiveResolver.owner(root)+"-><clinit>()V",null,new ArrayList<Object>(),0);
        Object value=statics.get(root);
        require(value instanceof Instance && ((Instance)value).initialized,"root_not_constructed");
        Instance instance=(Instance)value;
        require(instance.type.equals(field.type),"root_implementation");
        Object returned=execute(accessor,instance,new ArrayList<Object>(),0);
        require(returned instanceof Instance && ((Instance)returned).initialized,"unknown_payload");
        Instance payload=(Instance)returned;
        require(payload.type.equals(GmsAdaptiveResolver.owner(gate.getter.getDescriptor())),"wrong_getter_implementation");
        require(assignable(payload.type,GmsAdaptiveResolver.returnType(accessor),0),"getter_contract");
        graph.identity(prefix+"ReceiverAccessor",accessor);
    }

    private GmsDexFile.Method method(String descriptor) throws Exception {
        String role=methodRoles.get(descriptor);
        if(role==null) {
            role=prefix+"ReceiverMethod"+methodRoles.size();methodRoles.put(descriptor,role);
        }
        return graph.add(role,descriptor);
    }

    private Object execute(String descriptor,Instance receiver,List<Object> arguments,int depth) throws Exception {
        require(depth<=GmsAdaptiveResolver.MAX_DEPTH,"wrapper_depth");
        require(active.add(descriptor),"recursive_constructor");
        try {
            GmsDexFile.Method method=method(descriptor);
            GmsDexFile.Code code=GmsAdaptiveResolver.code(method);
            require(code.triesSize==0 && code.instructions.size()<=256,"unsupported_control_flow");
            Map<Integer,Object> registers=new HashMap<>();
            int parameter=code.registersSize-code.insSize;
            if((method.accessFlags&8)==0) {
                require(receiver!=null,"missing_receiver");registers.put(parameter++,receiver);
            }
            require(arguments.size()==method.parameterTypes.size(),"constructor_arguments");
            for(int i=0;i<arguments.size();i++) {
                registers.put(parameter,arguments.get(i));
                parameter+=method.parameterTypes.get(i).equals("J")||method.parameterTypes.get(i).equals("D")?2:1;
            }
            require(parameter==code.registersSize,"parameter_frame");
            Object pending=null;
            boolean constructorChained=false;
            for(GmsDexFile.Instruction instruction:code.instructions) {
                String op=GmsAdaptiveResolver.normalOp(instruction.opname);int[] r=instruction.registers;
                for(int register:r)require(register>=0 && register<code.registersSize,"register_frame");
                if(!op.startsWith("move-result"))pending=null;
                if(op.equals("nop"))continue;
                if(op.equals("new-instance")) {
                    require(method.name.startsWith("<"),"accessor_allocation");
                    require(++allocations<=32,"allocation_budget");
                    registers.put(r[0],new Instance(instruction.reference));
                } else if(op.equals("move-object")||op.equals("move")||op.equals("move-wide")) {
                    registers.put(r[0],read(registers,r[1]));
                } else if(op.startsWith("const")) {
                    registers.put(r[0],UNKNOWN);
                } else if(op.equals("move-result-object")||op.equals("move-result")) {
                    require(pending!=null,"missing_result");registers.put(r[0],pending);pending=null;
                } else if(op.equals("check-cast")) {
                    Object object=read(registers,r[0]);
                    require(object instanceof Instance && assignable(((Instance)object).type,instruction.reference,0),"invalid_cast");
                } else if(op.equals("iget-object")) {
                    Object object=read(registers,r[1]);require(object instanceof Instance,"unknown_field_receiver");
                    GmsDexFile.Field field=GmsAdaptiveResolver.field(graph.dex,instruction.reference);
                    require((field.accessFlags&16)!=0 && (field.accessFlags&8)==0,"mutable_payload");
                    require(assignable(((Instance)object).type,field.owner,0),"field_owner");
                    Object member=((Instance)object).fields.get(instruction.reference);
                    require(member!=null,"uninitialized_payload");
                    registers.put(r[0],member);graph.identity(prefix+"ReceiverField"+field.descriptor,field.descriptor);
                } else if(op.startsWith("iput")) {
                    require(method.name.equals("<init>") && constructorChained,"accessor_write");
                    Object object=read(registers,r[1]);require(object==receiver,"constructor_foreign_write");
                    GmsDexFile.Field field=GmsAdaptiveResolver.field(graph.dex,instruction.reference);
                    require(assignable(receiver.type,field.owner,0),"field_owner");
                    Object member=read(registers,r[0]);
                    require(!receiver.fields.containsKey(field.descriptor),"payload_reassigned");
                    receiver.fields.put(field.descriptor,member);
                } else if(op.equals("sget-object")) {
                    Object known=statics.get(instruction.reference);
                    registers.put(r[0],known==null?UNKNOWN:known);
                } else if(op.startsWith("sget")) {
                    registers.put(r[0],UNKNOWN);
                } else if(op.startsWith("sput")) {
                    require(method.name.equals("<clinit>") && GmsAdaptiveResolver.owner(instruction.reference).equals(method.owner),"foreign_static_write");
                    require(!statics.containsKey(instruction.reference),"root_reassigned");
                    statics.put(instruction.reference,read(registers,r[0]));
                } else if(op.startsWith("invoke-")) {
                    pending=null;
                    if(op.equals("invoke-direct") && GmsAdaptiveResolver.suffix(instruction.reference).startsWith("<init>(")) {
                        require(method.name.startsWith("<"),"accessor_construction");
                        Object object=read(registers,r[0]);require(object instanceof Instance,"unknown_constructed_object");
                        Instance created=(Instance)object;
                        String calledOwner=GmsAdaptiveResolver.owner(instruction.reference);
                        boolean chain=object==receiver && method.name.equals("<init>");
                        if(chain) {
                            GmsDexFile.ClassDef definition=graph.dex.findClass(method.owner);
                            require(!constructorChained && definition!=null
                                    && (calledOwner.equals(method.owner)||calledOwner.equals(definition.superclass)),"constructor_chain");
                        } else require(!created.initialized && created.type.equals(calledOwner),"constructor_owner");
                        if(!instruction.reference.equals("Ljava/lang/Object;-><init>()V")) {
                            List<Object> args=new ArrayList<>();
                            GmsDexFile.Method constructor=graph.dex.findMethod(instruction.reference);
                            require(constructor!=null,"missing_constructor");
                            int index=1;
                            for(String type:constructor.parameterTypes) {
                                require(index<r.length,"constructor_arguments");args.add(read(registers,r[index]));
                                index+=type.equals("J")||type.equals("D")?2:1;
                            }
                            require(index==r.length,"constructor_arguments");
                            execute(instruction.reference,created,args,depth+1);
                        } else require(r.length==1,"object_constructor_arguments");
                        if(chain)constructorChained=true;
                        created.initialized=true;
                    } else {
                        // Only platform logging is irrelevant here; an arbitrary
                        // same-class helper could reassign the static root even
                        // without receiving an object argument.
                        require(method.name.equals("<clinit>") && op.equals("invoke-static")
                                && instruction.reference.matches("Landroid/util/Log;->[vdiew]\\(Ljava/lang/String;Ljava/lang/String;\\)I"),"unknown_critical_call");
                        for(int register:r) require(!(read(registers,register) instanceof Instance),"receiver_escape");
                        pending=UNKNOWN;
                    }
                } else if(op.equals("return-object")) {
                    require(!method.name.startsWith("<"),"constructor_return_value");
                    return read(registers,r[0]);
                } else if(op.equals("return-void")) {
                    require(method.name.startsWith("<"),"accessor_return_void");
                    require(!method.name.equals("<init>") || constructorChained,"missing_constructor_chain");
                    return UNKNOWN;
                } else {
                    throw new GmsAdaptiveResolver.Rejected("receiver","unsupported_instruction");
                }
            }
            throw new GmsAdaptiveResolver.Rejected("receiver","missing_return");
        } finally {active.remove(descriptor);}
    }

    private boolean assignable(String concrete,String target,int depth) throws Exception {
        if(concrete.equals(target)||target.equals("Ljava/lang/Object;"))return true;
        if(depth>GmsAdaptiveResolver.MAX_DEPTH)return false;
        GmsDexFile.ClassDef type=graph.dex.findClass(concrete);
        if(type==null)return false;
        for(String contract:type.interfaces)if(assignable(contract,target,depth+1))return true;
        return type.superclass!=null&&assignable(type.superclass,target,depth+1);
    }

    private static Object read(Map<Integer,Object> registers,int register) throws Exception {
        Object result=registers.get(register);require(result!=null,"undefined_register");return result;
    }
    private static void require(boolean valid,String reason) throws GmsAdaptiveResolver.Rejected {
        if(!valid)throw new GmsAdaptiveResolver.Rejected("receiver",reason);
    }
}
