package moseyPLK.client;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Read-only standard DEX 035-040 reader. Never resolves or executes target classes.
 * Definition indexing is eager; method bodies and their operands are decoded only on demand.
 * All code positions, branch targets and try ranges use 16-bit DEX code units.
 */
public final class GmsDexFile implements AutoCloseable {
    private static final int MAX_DEX = 16 * 1024 * 1024, MAX_TOTAL = 256 * 1024 * 1024;
    private final Map<String, ClassLocation> definitions = new LinkedHashMap<>();
    private final Map<String, ClassDef> decodedClasses = new LinkedHashMap<>();
    private final List<Dex> dexes = new ArrayList<>();
    private File apk;
    private long apkLength, apkModified;
    private Dex activeDex;
    private boolean closed;

    /** Releases all retained DEX bytes/metadata. A closed reader cannot reload code. */
    @Override public synchronized void close() {
        closed=true;
        for (Dex dex : dexes) dex.release();
        dexes.clear(); definitions.clear(); decodedClasses.clear(); activeDex=null;
    }
    private synchronized void activate(Dex dex) throws IOException {
        if (closed) throw bad("reader is closed");
        if (dex.bytes != null) return;
        if (apk == null || apk.length()!=apkLength || apk.lastModified()!=apkModified)
            throw bad("APK changed while reading");
        if (activeDex != null) activeDex.release();
        try (ZipFile zip=new ZipFile(apk)) {
            ZipEntry entry=zip.getEntry(dex.entryName);
            if (entry==null||entry.getSize()!=dex.fileSize||entry.getCrc()!=dex.crc)
                throw bad("DEX entry changed while reading");
            dex.bytes=readEntry(zip,entry);
        }
        activeDex=dex;
    }
    private static byte[] readEntry(ZipFile zip,ZipEntry entry) throws IOException {
        if(entry.getSize()<112||entry.getSize()>MAX_DEX)throw bad("DEX entry size");
        byte[] bytes=new byte[(int)entry.getSize()];
        try(InputStream in=zip.getInputStream(entry)) {
            int done=0;
            while(done<bytes.length){int n=in.read(bytes,done,bytes.length-done);if(n<0)throw bad("truncated DEX entry");if(n==0)throw bad("zero-length read");done+=n;}
            if(in.read()!=-1)throw bad("DEX entry exceeds declared size");
        }
        return bytes;
    }

    public static GmsDexFile readApk(File file) throws IOException {
        GmsDexFile result = new GmsDexFile();
        result.apk=file.getCanonicalFile(); result.apkLength=file.length(); result.apkModified=file.lastModified();
        try (ZipFile zip = new ZipFile(file)) {
            int total = 0;
            Set<String> names=new HashSet<>();
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.getName().matches("classes(?:[2-9]|[1-9][0-9]+)?\\.dex")) continue;
                if (!names.add(entry.getName())) throw bad("duplicate DEX entry");
                if (result.dexes.size() >= 64 || entry.getSize() < 112 || entry.getSize() > MAX_DEX)
                    throw bad("DEX size/count limit");
                total += (int) entry.getSize();
                if (total > MAX_TOTAL) throw bad("APK DEX size limit");
                Dex dex=result.add(readEntry(zip,entry));
                dex.entryName=entry.getName();dex.crc=entry.getCrc();
                // Index one DEX at a time. Keep no uncompressed APK-wide byte arrays.
                dex.release();
            }
        } catch(IOException | RuntimeException e) { result.close(); throw e; }
        if (result.dexes.isEmpty()) throw bad("no standard classes DEX entries");
        return result;
    }

    public static GmsDexFile readDex(byte[] bytes) throws IOException {
        GmsDexFile result = new GmsDexFile();
        result.add(bytes.clone());
        return result;
    }
    private Dex add(byte[] bytes) throws IOException {
        Dex dex = new Dex(this, bytes, dexes.size());
        dexes.add(dex);
        int count = dex.u4i(96), offset = dex.u4i(100);
        dex.table(count, offset, 32);
        if ((long)definitions.size()+count>300000) throw bad("class definition limit");
        for (int i = 0; i < count; i++) {
            int at = offset + 32 * i;
            String owner = dex.type(dex.u4i(at));
            if (!owner.startsWith("L") || !owner.endsWith(";")) throw bad("invalid class descriptor");
            if (definitions.put(owner, new ClassLocation(dex, at)) != null)
                throw bad("duplicate class definition: " + owner);
        }
        return dex;
    }
    public synchronized ClassDef findClass(String descriptor) throws IOException {
        if (closed) throw bad("reader is closed");
        ClassDef result = decodedClasses.get(descriptor);
        if (result != null) return result;
        ClassLocation location = definitions.get(descriptor);
        if (location == null) return null;
        result = location.dex.classDef(location.offset);
        decodedClasses.put(descriptor, result);
        return result;
    }
    public Method findMethod(String descriptor) throws IOException {
        int arrow = descriptor.indexOf("->");
        if (arrow < 1) return null;
        ClassDef c = findClass(descriptor.substring(0, arrow));
        if (c != null) for (Method m : c.methods) if (m.descriptor.equals(descriptor)) return m;
        return null;
    }
    public Collection<String> classDescriptors() { return Collections.unmodifiableSet(definitions.keySet()); }
    /** Explicitly materializes every definition, but never any method body. */
    public List<ClassDef> classes() throws IOException {
        List<ClassDef> result = new ArrayList<>();
        for (String descriptor : definitions.keySet()) result.add(findClass(descriptor));
        return Collections.unmodifiableList(result);
    }
    public List<Method> methods() throws IOException {
        List<Method> result = new ArrayList<>();
        for (ClassDef c : classes()) result.addAll(c.methods);
        return Collections.unmodifiableList(result);
    }
    public int dexCount() { return dexes.size(); }

    public static final class ClassDef {
        public final String descriptor, superclass;
        public final int accessFlags;
        public final List<String> interfaces;
        public final List<Field> fields;
        public final List<Method> methods;
        ClassDef(String d, String s, int f, List<String> i, List<Field> fs, List<Method> ms) {
            descriptor=d; superclass=s; accessFlags=f;
            interfaces=immutable(i); fields=immutable(fs); methods=immutable(ms);
        }
    }
    public static final class Field {
        public final String descriptor, owner, name, type;
        public final int accessFlags;
        Field(String owner, String name, String type, int flags) {
            this.owner=owner; this.name=name; this.type=type; accessFlags=flags;
            descriptor=owner+"->"+name+":"+type;
        }
    }
    public static final class Method {
        public final String descriptor, owner, name, returnType;
        public final List<String> parameterTypes;
        public final int accessFlags, codeOffset, dexIndex;
        private final Dex dex;
        private Code decoded;
        Method(Dex dex, String owner, String name, String returns, List<String> parameters,
                int flags, int offset) {
            this.dex=dex; this.owner=owner; this.name=name; returnType=returns;
            parameterTypes=immutable(parameters); accessFlags=flags; codeOffset=offset;
            dexIndex=dex == null ? -1 : dex.index;
            StringBuilder b = new StringBuilder(owner).append("->").append(name).append('(');
            for (String p : parameters) b.append(p);
            descriptor=b.append(')').append(returns).toString();
        }
        // Host tests use the same verifier with deliberately malformed normalized operands.
        Method(String owner, String name, String returns, List<String> parameters, int flags, Code code) {
            this(null, owner, name, returns, parameters, flags, 1);
            decoded=code;
        }
        public synchronized Code code() throws IOException {
            if (codeOffset == 0) return null;
            if (dex == null) return decoded;
            synchronized (dex.owner) {
                if (dex.owner.closed) throw bad("reader is closed");
                if (decoded == null) decoded=dex.code(codeOffset);
                return decoded;
            }
        }
    }
    public static final class Code {
        public final int registersSize, insSize, outsSize, triesSize, units;
        public final List<Instruction> instructions;
        public final List<TryBlock> tryBlocks;
        Code(int r, int i, int o, int t, int u, List<Instruction> xs, List<TryBlock> ts) {
            registersSize=r; insSize=i; outsSize=o; triesSize=t; units=u;
            instructions=immutable(xs); tryBlocks=immutable(ts);
        }
    }
    public static final class Instruction {
        public final int pc, opcode, width, target;
        public final String opname, reference;
        public final int[] registers, targets, payloadWords;
        public final long literal;
        Instruction(int p,int op,int w,int[] rs,long v,String ref,int target,int[] targets,int[] payload) {
            pc=p; opcode=op; width=w; registers=rs; literal=v; reference=ref; this.target=target;
            this.targets=targets; payloadWords=payload;
            opname=op > 255 ? (op==0x100?"packed-switch-payload":op==0x200?"sparse-switch-payload":"fill-array-data-payload") : NAMES[op];
        }
    }
    public static final class Handler {
        /** null type denotes catch-all. */
        public final String type;
        public final int target;
        Handler(String t,int p) {type=t;target=p;}
    }
    public static final class TryBlock {
        public final int start, end;
        public final List<Handler> handlers;
        TryBlock(int s,int e,List<Handler> hs) {start=s;end=e;handlers=immutable(hs);}
    }
    private static <T> List<T> immutable(List<T> values) {return Collections.unmodifiableList(new ArrayList<>(values));}
    private static IOException bad(String message) {return new IOException("unsupported/malformed DEX: "+message);}
    private static final class ClassLocation {
        final Dex dex; final int offset;
        ClassLocation(Dex d,int o) {dex=d;offset=o;}
    }
    private static final class Cursor {int p;Cursor(int p){this.p=p;}}
    private static final class Dex {
        byte[] bytes; final int index, fileSize; final GmsDexFile owner;
        String entryName; long crc;
        final int stringsCount, stringsOffset, typesCount, typesOffset, protosCount, protosOffset;
        final int fieldsCount, fieldsOffset, methodsCount, methodsOffset;
        final Map<Integer,String> strings = new LinkedHashMap<>();
        Dex(GmsDexFile owner,byte[] b,int index) throws IOException {
            this.owner=owner;bytes=b;this.index=index;fileSize=b.length;
            if (b.length < 112 || b.length > MAX_DEX || b[0]!='d'||b[1]!='e'||b[2]!='x'||b[3]!=10||b[7]!=0||b[4]!='0'||b[5]<'0'||b[5]>'9'||b[6]<'0'||b[6]>'9')
                throw bad("header/magic");
            int version=(b[4]-'0')*100+(b[5]-'0')*10+b[6]-'0';
            if (version<35||version>40 || u4i(32)!=b.length || u4i(36)!=112 || u4i(40)!=0x12345678)
                throw bad("version, length, header or endian");
            stringsCount=u4i(56);stringsOffset=u4i(60);table(stringsCount,stringsOffset,4);
            typesCount=u4i(64);typesOffset=u4i(68);table(typesCount,typesOffset,4);
            protosCount=u4i(72);protosOffset=u4i(76);table(protosCount,protosOffset,12);
            fieldsCount=u4i(80);fieldsOffset=u4i(84);table(fieldsCount,fieldsOffset,8);
            methodsCount=u4i(88);methodsOffset=u4i(92);table(methodsCount,methodsOffset,8);
            int dataSize=u4i(104),dataOffset=u4i(108);range(dataOffset,dataSize);
            if (dataOffset<112 || (long)dataOffset+dataSize!=b.length) throw bad("data section");
        }
        void release(){bytes=null;strings.clear();}
        void range(int at,long n) throws IOException {if(at<0||n<0||(long)at+n>fileSize)throw bad("range");owner.activate(this);}
        void table(int count,int at,int width) throws IOException {
            if(count<0||count>2000000||(count==0 ? at!=0 : at<112)||at%4!=0)throw bad("index table");
            range(at,(long)count*width);
        }
        int u1(int p) throws IOException {range(p,1);return bytes[p]&255;}
        int u2(int p) throws IOException {range(p,2);return (bytes[p]&255)|((bytes[p+1]&255)<<8);}
        long u4(int p) throws IOException {return (long)u2(p)|((long)u2(p+2)<<16);}
        int u4i(int p) throws IOException {long v=u4(p);if(v>Integer.MAX_VALUE)throw bad("integer overflow");return(int)v;}
        int signed4(int p) throws IOException {return(int)u4(p);}
        int uleb(Cursor c) throws IOException {
            long value=0;
            for(int i=0;i<5;i++){int b=u1(c.p++);value|=(long)(b&127)<<(i*7);if((b&128)==0){if(value>Integer.MAX_VALUE)throw bad("ULEB overflow");return(int)value;}}
            throw bad("overlong ULEB");
        }
        int sleb(Cursor c) throws IOException {
            long value=0;int shift=0,b;
            do{if(shift>=35)throw bad("overlong SLEB");b=u1(c.p++);value|=(long)(b&127)<<shift;shift+=7;}while((b&128)!=0);
            if((b&64)!=0)value|=(-1L)<<shift;
            if(value<Integer.MIN_VALUE||value>Integer.MAX_VALUE)throw bad("SLEB overflow");return(int)value;
        }
        int checked(int id,int size) throws IOException {if(id<0||id>=size)throw bad("index out of range");return id;}
        String string(int id) throws IOException {
            checked(id,stringsCount);String cached=strings.get(id);if(cached!=null)return cached;
            Cursor c=new Cursor(u4i(stringsOffset+4*id));int count=uleb(c);
            if(count>1048576)throw bad("string limit");
            StringBuilder out=new StringBuilder(count);
            for(int i=0;i<count;i++){
                int a=u1(c.p++),v;
                if(a>0&&a<128)v=a;
                else if((a&224)==192){int b=u1(c.p++);if((b&192)!=128)throw bad("MUTF8");v=((a&31)<<6)|(b&63);if(v!=0&&v<128)throw bad("MUTF8 overlong");}
                else if((a&240)==224){int b=u1(c.p++),d=u1(c.p++);if((b&192)!=128||(d&192)!=128)throw bad("MUTF8");v=((a&15)<<12)|((b&63)<<6)|(d&63);if(v<2048)throw bad("MUTF8 overlong");}
                else throw bad("MUTF8 character");
                out.append((char)v);
            }
            if(u1(c.p)!=0)throw bad("MUTF8 length");
            String value=out.toString();strings.put(id,value);return value;
        }
        String type(int id) throws IOException {return string(u4i(typesOffset+4*checked(id,typesCount)));}
        List<String> typeList(int at) throws IOException {
            List<String> out=new ArrayList<>();if(at==0)return out;
            if(at%4!=0)throw bad("type list alignment");int n=u4i(at);if(n>65535)throw bad("type list size");range(at+4,(long)n*2);
            for(int i=0;i<n;i++)out.add(type(u2(at+4+2*i)));return out;
        }
        Field field(int id,int flags) throws IOException {
            int p=fieldsOffset+8*checked(id,fieldsCount);return new Field(type(u2(p)),string(u4i(p+4)),type(u2(p+2)),flags);
        }
        Method method(int id,int flags,int code) throws IOException {
            int p=methodsOffset+8*checked(id,methodsCount),proto=protosOffset+12*checked(u2(p+2),protosCount);
            return new Method(this,type(u2(p)),string(u4i(p+4)),type(u4i(proto+4)),typeList(u4i(proto+8)),flags,code);
        }
        ClassDef classDef(int at) throws IOException {
            String owner=type(u4i(at));int parent=(int)u4(at+8);
            List<Field> fs=new ArrayList<>();List<Method> ms=new ArrayList<>();
            int data=u4i(at+24);
            if(data!=0){Cursor c=new Cursor(data);int sf=uleb(c),inf=uleb(c),dm=uleb(c),vm=uleb(c);
                if((long)sf+inf>fieldsCount||(long)dm+vm>methodsCount)throw bad("class_data counts");
                Map<String,Boolean> seen=new LinkedHashMap<>();
                for(int group=0;group<2;group++){int id=0,n=group==0?sf:inf;
                    for(int j=0;j<n;j++){int delta=uleb(c);if(j>0&&delta==0)throw bad("duplicate encoded field");id=add(id,delta);Field f=field(id,uleb(c));
                        if(!owner.equals(f.owner)||seen.put(f.descriptor,true)!=null)throw bad("field owner/duplicate");fs.add(f);}}
                for(int group=0;group<2;group++){int id=0,n=group==0?dm:vm;
                    for(int j=0;j<n;j++){int delta=uleb(c);if(j>0&&delta==0)throw bad("duplicate encoded method");id=add(id,delta);int flags=uleb(c),offset=uleb(c);Method m=method(id,flags,offset);
                        if(!owner.equals(m.owner)||seen.put(m.descriptor,true)!=null)throw bad("method owner/duplicate");
                        if(offset!=0){if(offset%4!=0)throw bad("code alignment");range(offset,16);}ms.add(m);}}
            }
            return new ClassDef(owner,parent==-1?null:type(parent),u4i(at+4),typeList(u4i(at+12)),fs,ms);
        }
        int add(int a,int b) throws IOException {long sum=(long)a+b;if(sum<0||sum>Integer.MAX_VALUE)throw bad("offset overflow");return(int)sum;}
        Code code(int at) throws IOException {
            int regs=u2(at),ins=u2(at+2),outs=u2(at+4),tries=u2(at+6),n=u4i(at+12),base=at+16;
            if(ins>regs||n==0||n>65536)throw bad("code frame/size bound");range(base,(long)n*2);
            List<Instruction> xs=new ArrayList<>();Map<Integer,Instruction> pcs=new LinkedHashMap<>();
            for(int pc=0;pc<n;){Instruction x=instruction(base,pc,n);for(int r:x.registers)if(r<0||r>=regs)throw bad("register outside frame");xs.add(x);pcs.put(pc,x);pc=add(pc,x.width);}
            for(Instruction x:xs){if(x.opcode>255)continue;
                if(x.target!=-1){Instruction dest=pcs.get(x.target);if(dest==null)throw bad("branch/payload boundary");
                    if(x.opcode==0x26||x.opcode==0x2b||x.opcode==0x2c){int expected=x.opcode==0x26?0x300:x.opcode==0x2b?0x100:0x200;if(dest.opcode!=expected)throw bad("wrong payload kind");}
                    else if(dest.opcode>255)throw bad("branch into payload");}
                for(int target:x.targets){Instruction dest=pcs.get(target);if(dest==null||dest.opcode>255)throw bad("switch boundary");}
            }
            List<TryBlock> blocks=new ArrayList<>();
            if(tries!=0){int start=add(base,n*2+(n%2)*2);range(start,(long)tries*8);int handlerBase=add(start,tries*8);Cursor c=new Cursor(handlerBase);int count=uleb(c);
                if(count>65535)throw bad("handler count");Map<Integer,List<Handler>> handlers=new LinkedHashMap<>();
                for(int i=0;i<count;i++){int offset=c.p-handlerBase,size=sleb(c);if(size==Integer.MIN_VALUE||Math.abs(size)>65535)throw bad("handler size");List<Handler> hs=new ArrayList<>();
                    for(int j=0;j<Math.abs(size);j++)hs.add(new Handler(type(uleb(c)),uleb(c)));
                    if(size<=0)hs.add(new Handler(null,uleb(c)));
                    for(Handler h:hs)if(!pcs.containsKey(h.target)||pcs.get(h.target).opcode>255)throw bad("handler target");handlers.put(offset,hs);}
                int previousEnd=0;
                for(int i=0;i<tries;i++){int p=start+8*i,s=u4i(p),length=u2(p+4),end=add(s,length);List<Handler> hs=handlers.get(u2(p+6));
                    if(length==0||s<previousEnd||!pcs.containsKey(s)||end>n||(end!=n&&!pcs.containsKey(end))||hs==null)throw bad("try range/handler");
                    blocks.add(new TryBlock(s,end,hs));previousEnd=end;}
            }
            return new Code(regs,ins,outs,tries,n,xs,blocks);
        }
        Instruction instruction(int base,int pc,int units) throws IOException {
            int p=base+pc*2,word=u2(p),op=word&255,a=word>>>8;
            if(op==0&&a!=0){
                if((pc&1)!=0)throw bad("payload alignment");
                long width;int size=u2(p+2);
                if(word==0x100)width=4L+2L*size;
                else if(word==0x200)width=2L+4L*size;
                else if(word==0x300){if(size!=1&&size!=2&&size!=4&&size!=8)throw bad("array element width");width=4L+((long)size*u4(p+4)+1)/2;}
                else throw bad("unknown payload");
                if(width>units-pc)throw bad("payload length");int[] raw=new int[(int)width];for(int i=0;i<raw.length;i++)raw[i]=u2(p+2*i);
                return new Instruction(pc,word,(int)width,new int[0],0,null,-1,new int[0],raw);
            }
            String format=FORMATS[op];if(format==null)throw bad("unsupported opcode "+op);
            int width=format.charAt(0)-'0';if(width>units-pc)throw bad("truncated instruction");
            int[] rs=new int[0],targets=new int[0];long literal=0;String ref=null;int target=-1;
            int second=width>1?u2(p+2):0;
            switch(format){
                case "10x": if(a!=0)throw bad("reserved operand"); break;
                case "12x":rs=new int[]{a&15,a>>>4};break;
                case "11n":rs=new int[]{a&15};literal=(a<<24)>>28;break;
                case "11x":rs=new int[]{a};break;
                case "10t":target=add(pc,(byte)a);break;
                case "20t":if(a!=0)throw bad("reserved operand");target=add(pc,(short)second);break;
                case "30t":if(a!=0)throw bad("reserved operand");target=add(pc,signed4(p+2));break;
                case "22x":rs=new int[]{a,second};break;
                case "32x":if(a!=0)throw bad("reserved operand");rs=new int[]{second,u2(p+4)};break;
                case "21t":rs=new int[]{a};target=add(pc,(short)second);break;
                case "22t":rs=new int[]{a&15,a>>>4};target=add(pc,(short)second);break;
                case "21s":rs=new int[]{a};literal=(short)second;break;
                case "21h":rs=new int[]{a};literal=op==0x19?(long)(short)second<<48:(long)(short)second<<16;break;
                case "31i":rs=new int[]{a};literal=signed4(p+2);break;
                case "51l":rs=new int[]{a};literal=u4(p+2)|(u4(p+6)<<32);break;
                case "23x":rs=new int[]{a,second&255,second>>>8};break;
                case "22b":rs=new int[]{a,second&255};literal=(byte)(second>>>8);break;
                case "22s":rs=new int[]{a&15,a>>>4};literal=(short)second;break;
                case "21c":rs=new int[]{a};ref=reference(op,second);break;
                case "31c":rs=new int[]{a};ref=reference(op,u4i(p+2));break;
                case "22c":rs=new int[]{a&15,a>>>4};ref=reference(op,second);break;
                case "35c":{
                    int count=a>>>4,packed=u2(p+4);if(count>5)throw bad("invoke count");
                    int[] all={packed&15,(packed>>>4)&15,(packed>>>8)&15,packed>>>12,a&15};rs=Arrays.copyOf(all,count);ref=reference(op,second);break;}
                case "3rc":{
                    int first=u2(p+4);if((long)first+a>65536)throw bad("range registers");rs=new int[a];for(int i=0;i<a;i++)rs[i]=first+i;ref=reference(op,second);break;}
                case "31t":{
                    rs=new int[]{a};target=add(pc,signed4(p+2));if(target<0||target>=units||(target&1)!=0)throw bad("payload target");
                    int payload=base+target*2,kind=u2(payload),size=u2(payload+2);
                    if(op==0x2b||op==0x2c){if(kind!=(op==0x2b?0x100:0x200))throw bad("switch payload");
                        long payloadWidth=op==0x2b?4L+size*2L:2L+size*4L;if(payloadWidth>units-target)throw bad("switch payload size");
                        targets=new int[size];int targetStart=payload+(op==0x2b?8:4+size*4);
                        for(int i=0;i<size;i++)targets[i]=add(pc,signed4(targetStart+i*4));
                    }break;}
                default:throw bad("unsupported instruction format");
            }
            return new Instruction(pc,op,width,rs,literal,ref,target,targets,new int[0]);
        }
        String reference(int op,int id) throws IOException {
            if(op==0x1a||op==0x1b)return string(id);
            if(op==0x1c||op==0x1f||op==0x20||op==0x22||op==0x23||op==0x24||op==0x25)return type(id);
            if(op>=0x52&&op<=0x6d)return field(id,0).descriptor;
            if(op>=0x6e&&op<=0x78)return method(id,0,0).descriptor;
            throw bad("unsupported reference kind");
        }
    }
    private static final String[] NAMES=new String[256],FORMATS=new String[256];
    private static void ops(int first,String format,String names){for(String name:names.split(" ")){NAMES[first]=name;FORMATS[first++]=format;}}
    static {
        ops(0x00,"10x","nop");ops(0x01,"12x","move");ops(0x02,"22x","move/from16");ops(0x03,"32x","move/16");
        ops(0x04,"12x","move-wide");ops(0x05,"22x","move-wide/from16");ops(0x06,"32x","move-wide/16");
        ops(0x07,"12x","move-object");ops(0x08,"22x","move-object/from16");ops(0x09,"32x","move-object/16");
        ops(0x0a,"11x","move-result move-result-wide move-result-object move-exception");ops(0x0e,"10x","return-void");
        ops(0x0f,"11x","return return-wide return-object");ops(0x12,"11n","const/4");ops(0x13,"21s","const/16");
        ops(0x14,"31i","const");ops(0x15,"21h","const/high16");ops(0x16,"21s","const-wide/16");ops(0x17,"31i","const-wide/32");
        ops(0x18,"51l","const-wide");ops(0x19,"21h","const-wide/high16");ops(0x1a,"21c","const-string");ops(0x1b,"31c","const-string/jumbo");
        ops(0x1c,"21c","const-class");ops(0x1d,"11x","monitor-enter monitor-exit");ops(0x1f,"21c","check-cast");ops(0x20,"22c","instance-of");
        ops(0x21,"12x","array-length");ops(0x22,"21c","new-instance");ops(0x23,"22c","new-array");ops(0x24,"35c","filled-new-array");
        ops(0x25,"3rc","filled-new-array/range");ops(0x26,"31t","fill-array-data");ops(0x27,"11x","throw");
        ops(0x28,"10t","goto");ops(0x29,"20t","goto/16");ops(0x2a,"30t","goto/32");ops(0x2b,"31t","packed-switch sparse-switch");
        ops(0x2d,"23x","cmpl-float cmpg-float cmpl-double cmpg-double cmp-long");ops(0x32,"22t","if-eq if-ne if-lt if-ge if-gt if-le");
        ops(0x38,"21t","if-eqz if-nez if-ltz if-gez if-gtz if-lez");
        ops(0x44,"23x","aget aget-wide aget-object aget-boolean aget-byte aget-char aget-short aput aput-wide aput-object aput-boolean aput-byte aput-char aput-short");
        ops(0x52,"22c","iget iget-wide iget-object iget-boolean iget-byte iget-char iget-short iput iput-wide iput-object iput-boolean iput-byte iput-char iput-short");
        ops(0x60,"21c","sget sget-wide sget-object sget-boolean sget-byte sget-char sget-short sput sput-wide sput-object sput-boolean sput-byte sput-char sput-short");
        ops(0x6e,"35c","invoke-virtual invoke-super invoke-direct invoke-static invoke-interface");
        ops(0x74,"3rc","invoke-virtual/range invoke-super/range invoke-direct/range invoke-static/range invoke-interface/range");
        ops(0x7b,"12x","neg-int not-int neg-long not-long neg-float neg-double int-to-long int-to-float int-to-double long-to-int long-to-float long-to-double float-to-int float-to-long float-to-double double-to-int double-to-long double-to-float int-to-byte int-to-char int-to-short");
        ops(0x90,"23x","add-int sub-int mul-int div-int rem-int and-int or-int xor-int shl-int shr-int ushr-int add-long sub-long mul-long div-long rem-long and-long or-long xor-long shl-long shr-long ushr-long add-float sub-float mul-float div-float rem-float add-double sub-double mul-double div-double rem-double");
        ops(0xb0,"12x","add-int/2addr sub-int/2addr mul-int/2addr div-int/2addr rem-int/2addr and-int/2addr or-int/2addr xor-int/2addr shl-int/2addr shr-int/2addr ushr-int/2addr add-long/2addr sub-long/2addr mul-long/2addr div-long/2addr rem-long/2addr and-long/2addr or-long/2addr xor-long/2addr shl-long/2addr shr-long/2addr ushr-long/2addr add-float/2addr sub-float/2addr mul-float/2addr div-float/2addr rem-float/2addr add-double/2addr sub-double/2addr mul-double/2addr div-double/2addr rem-double/2addr");
        ops(0xd0,"22s","add-int/lit16 rsub-int mul-int/lit16 div-int/lit16 rem-int/lit16 and-int/lit16 or-int/lit16 xor-int/lit16");
        ops(0xd8,"22b","add-int/lit8 rsub-int/lit8 mul-int/lit8 div-int/lit8 rem-int/lit8 and-int/lit8 or-int/lit8 xor-int/lit8 shl-int/lit8 shr-int/lit8 ushr-int/lit8");
        // odex/quickened opcodes and invoke-custom/polymorphic/method-handle are unsupported.
    }
}
