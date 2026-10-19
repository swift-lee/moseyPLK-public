package moseyPLK.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Bounded reaching definitions. Unknown merges remain unknown; names are never evidence. */
final class GmsSemanticProof {
    static final class Value {
        final String kind, reference;
        final long literal;
        final int site;
        final List<Value> args;
        Value(String kind,String reference,long literal,int site,List<Value> args) {
            this.kind=kind;this.reference=reference;this.literal=literal;this.site=site;this.args=args;
        }
        boolean is(String kind,String reference) {return this.kind.equals(kind)&&reference.equals(this.reference);}
        boolean number(long n){return kind.equals("const")&&literal==n;}
        boolean param(int n){return kind.equals("param")&&literal==n;}
        Value arg(int i){return i>=0&&i<args.size()?args.get(i):UNKNOWN;}
        @Override public boolean equals(Object other){if(!(other instanceof Value))return false;Value v=(Value)other;return kind.equals(v.kind)&&java.util.Objects.equals(reference,v.reference)&&literal==v.literal&&site==v.site&&args.equals(v.args);}
        @Override public int hashCode(){return java.util.Objects.hash(kind,reference,literal,site,args);}
    }
    static final Value UNKNOWN=new Value("unknown","",0,-1,Collections.<Value>emptyList());
    static final class Flow {
        final GmsDexFile.Method method;
        final GmsDexFile.Code code;
        final List<GmsDexFile.Instruction> ins;
        final List<List<Integer>> next=new ArrayList<>(),previous=new ArrayList<>();
        final Set<Integer>[][] incoming;
        @SuppressWarnings("unchecked") Flow(GmsDexFile.Method method)throws Exception {
            this.method=method;code=GmsAdaptiveResolver.code(method);ins=code.instructions;
            GmsAdaptiveResolver.require(ins.size()<=4096,"flow_instruction_budget");
            incoming=(Set<Integer>[][])new Set<?>[ins.size()][code.registersSize];
            for(int i=0;i<ins.size();i++){next.add(new ArrayList<Integer>());previous.add(new ArrayList<Integer>());}
            for(int i=0;i<ins.size();i++){
                GmsDexFile.Instruction x=ins.get(i);String n=x.opname;
                if(n.startsWith("goto"))edge(i,index(x.target));
                else if(n.startsWith("if-")){edge(i,index(x.target));if(i+1<ins.size())edge(i,i+1);}
                else if(n.contains("switch")&&!n.contains("payload")){for(int target:x.targets)edge(i,index(target));if(i+1<ins.size())edge(i,i+1);}
                else if(!n.startsWith("return")&&!n.equals("throw")&&!n.contains("payload")&&i+1<ins.size())edge(i,i+1);
            }
            for(GmsDexFile.TryBlock block:code.tryBlocks)for(int i=0;i<ins.size();i++)if(ins.get(i).pc>=block.start&&ins.get(i).pc<block.end)
                for(GmsDexFile.Handler handler:block.handlers)edge(i,index(handler.target));
            for(int r=0;r<code.registersSize;r++)incoming[0][r]=singleton(r<code.registersSize-code.insSize?Integer.MIN_VALUE:-1-r);
            java.util.ArrayDeque<Integer> queue=new java.util.ArrayDeque<>();queue.add(0);boolean[] queued=new boolean[ins.size()];queued[0]=true;
            boolean[] visited=new boolean[ins.size()];visited[0]=true;int work=0;
            while(!queue.isEmpty()){
                GmsAdaptiveResolver.require(++work<=100000,"flow_work_budget");int at=queue.remove();queued[at]=false;
                GmsDexFile.Instruction x=ins.get(at);
                for(int to:next.get(at)){
                    boolean changed=!visited[to];visited[to]=true;
                    for(int r=0;r<code.registersSize;r++){
                        Set<Integer> source=incoming[at][r];
                        if(GmsAdaptiveResolver.writesFirst(x)&&x.registers[0]==r)source=singleton(at);
                        if(source==null)continue;
                        if(incoming[to][r]==null)incoming[to][r]=new LinkedHashSet<>();
                        if(incoming[to][r].size()>16)continue;
                        if(incoming[to][r].addAll(source)){changed=true;if(incoming[to][r].size()>16){incoming[to][r].clear();incoming[to][r].add(Integer.MIN_VALUE);}}
                    }
                    if(changed&&!queued[to]){queue.add(to);queued[to]=true;}
                }
            }
        }
        private static Set<Integer> singleton(int value){Set<Integer>s=new LinkedHashSet<>();s.add(value);return s;}
        void edge(int a,int b){if(!next.get(a).contains(b)){next.get(a).add(b);previous.get(b).add(a);}}
        int index(int pc)throws GmsAdaptiveResolver.Rejected{for(int i=0;i<ins.size();i++)if(ins.get(i).pc==pc)return i;throw new GmsAdaptiveResolver.Rejected("flow_invalid_target");}
        Value at(int index,int register){return at(index,register,new HashSet<String>(),0);}
        private Value at(int index,int register,Set<String> seen,int depth){
            if(depth>48||index<0||index>=ins.size()||register<0||register>=code.registersSize)return UNKNOWN;
            String key=index+":"+register;if(!seen.add(key))return UNKNOWN;
            Set<Integer> defs=incoming[index][register];Value result=null;
            if(defs!=null)for(int def:defs){Value value=definition(def,seen,depth+1);if(result==null)result=value;else if(!result.equals(value)){result=UNKNOWN;break;}}
            seen.remove(key);return result==null?UNKNOWN:result;
        }
        private Value definition(int site,Set<String> seen,int depth){
            if(site==Integer.MIN_VALUE)return UNKNOWN;
            if(site<0)return new Value("param","",-1-site-(code.registersSize-code.insSize),-1,Collections.<Value>emptyList());
            GmsDexFile.Instruction x=ins.get(site);String n=GmsAdaptiveResolver.normalOp(x.opname);
            if(n.startsWith("move-result")){if(site==0)return UNKNOWN;return call(site-1,seen,depth+1);}
            if(n.startsWith("move")&&!n.equals("move-exception"))return at(site,x.registers[1],seen,depth+1);
            if(n.equals("check-cast"))return at(site,x.registers[0],seen,depth+1);
            if(n.equals("const"))return new Value("const","",x.literal,-1,Collections.<Value>emptyList());
            if(n.equals("const-string")||n.equals("sget-object")||n.equals("sget")||n.equals("new-instance"))return new Value(n,x.reference,x.literal,n.equals("new-instance")?site:-1,Collections.<Value>emptyList());
            if(n.startsWith("iget"))return new Value("field",x.reference,0,-1,Arrays.asList(at(site,x.registers[1],seen,depth+1)));
            if(n.equals("instance-of"))return new Value(n,x.reference,0,site,Arrays.asList(at(site,x.registers[1],seen,depth+1)));
            return UNKNOWN;
        }
        Value call(int site){return call(site,new HashSet<String>(),0);}
        private Value call(int site,Set<String> seen,int depth){
            if(site<0||site>=ins.size())return UNKNOWN;GmsDexFile.Instruction x=ins.get(site);
            if(!x.opname.startsWith("invoke-"))return UNKNOWN;
            List<Value> args=new ArrayList<>();for(int r:x.registers)args.add(at(site,r,seen,depth+1));
            return new Value("call",x.reference,0,site,args);
        }
        List<Integer> calls(String reference){List<Integer>out=new ArrayList<>();for(int i=0;i<ins.size();i++)if(ins.get(i).opname.startsWith("invoke-")&&reference.equals(ins.get(i).reference))out.add(i);return out;}
        List<Integer> callsSuffix(String suffix){List<Integer>out=new ArrayList<>();for(int i=0;i<ins.size();i++)if(ins.get(i).opname.startsWith("invoke-")&&ins.get(i).reference.endsWith(suffix))out.add(i);return out;}
        boolean reachable(int start,int sink,int forcedSite,boolean truth)throws Exception{
            boolean[] seen=new boolean[ins.size()];java.util.ArrayDeque<Integer>q=new java.util.ArrayDeque<>();q.add(start);
            while(!q.isEmpty()){int i=q.remove();if(i==sink)return true;if(seen[i])continue;seen[i]=true;
                GmsDexFile.Instruction x=ins.get(i);String n=x.opname;
                if((n.equals("if-eqz")||n.equals("if-nez"))&&originCall(at(i,x.registers[0]),forcedSite)){
                    boolean jump=n.equals("if-nez")==truth;q.add(jump?index(x.target):i+1);
                }else q.addAll(next.get(i));
            }return false;
        }
        boolean mayBeParameter(int site,int register,int parameter){return mayBeParameter(site,register,parameter,new HashSet<String>(),0);}
        private boolean mayBeParameter(int site,int register,int parameter,Set<String>seen,int depth){
            if(depth>64||site<0||site>=ins.size())return true;String key=site+":"+register;if(!seen.add(key))return false;Set<Integer>defs=incoming[site][register];if(defs==null)return false;
            for(int def:defs){if(def==Integer.MIN_VALUE)continue;if(def<0){if(-1-def-(code.registersSize-code.insSize)==parameter)return true;continue;}GmsDexFile.Instruction x=ins.get(def);
                if(x.opname.equals("check-cast")&&mayBeParameter(def,x.registers[0],parameter,seen,depth+1))return true;
                if(x.opname.startsWith("move-object")&&mayBeParameter(def,x.registers[1],parameter,seen,depth+1))return true;
            }return false;
        }
        boolean dominates(int node,int sink){
            if(node==0)return true;boolean[] seen=new boolean[ins.size()];java.util.ArrayDeque<Integer>q=new java.util.ArrayDeque<>();q.add(0);
            while(!q.isEmpty()){int i=q.remove();if(i==node||seen[i])continue;if(i==sink)return false;seen[i]=true;q.addAll(next.get(i));}return true;
        }
        boolean gated(int sink,int callSite,boolean truth)throws Exception{return reachable(0,sink,callSite,truth)&&!reachable(0,sink,callSite,!truth);}
        boolean originCall(Value value,int site){return value.kind.equals("call")&&(value.site==site||value.reference.equals(GmsAdaptiveResolver.UNBOX)&&originCall(value.arg(0),site));}
    }
    static boolean same(Value a,Value b){return a!=UNKNOWN&&b!=UNKNOWN&&a.equals(b);}
    static boolean contains(Value value,String kind,String reference){if(value.is(kind,reference))return true;for(Value a:value.args)if(contains(a,kind,reference))return true;return false;}
    static boolean parameter(Value value,int parameter){if(value.param(parameter))return true;for(Value a:value.args)if(parameter(a,parameter))return true;return false;}
    private GmsSemanticProof(){}
}
