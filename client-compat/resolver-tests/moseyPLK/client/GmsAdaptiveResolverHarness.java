package moseyPLK.client;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.luckypray.dexkit.DexKitBridge;

/** Host-only integration entry. APK inputs are DEX data, never executable classes. */
public final class GmsAdaptiveResolverHarness {
    public static void main(String[] args) throws Exception {
        if(args.length<2)throw new IllegalArgumentException("native-library apk [audit-output]");
        System.load(new File(args[0]).getAbsolutePath());
        if(args.length==3) {
            try(DexKitBridge bridge=DexKitBridge.create(args[1]);
                    GmsDexFile dex=GmsDexFile.readApk(new File(args[1]))) {
                bridge.setThreadNum(2);
                GmsAdaptiveResolver.Graph graph=GmsAdaptiveResolver.inspect(bridge,dex);
                String evidence=GmsGateVerifier.receipt(graph);
                Files.write(new File(args[2]).toPath(),evidence.getBytes(StandardCharsets.UTF_8));
                System.out.println("AUDIT_ONLY expression="+graph.expression+" roles="+graph.methods.size()+" decoded_methods="+graph.decoded.size()+" code_units="+graph.totalCodeUnits+" digest="+GmsGateVerifier.digest(evidence)+" proofs="+graph.proofs);
            }
            return;
        }
        ResolvedGateSet result=GmsAdaptiveResolver.resolve(new File(args[1]));
        if(result.supplierDescriptor!=null||result.secondaryGetterDescriptor!=null||!"A".equals(result.expression))
            throw new AssertionError("resolver returned a non-Phenotype hook contract");
        System.out.println("VERIFIED expression="+result.expression+" getter="+result.getterDescriptor
                +" supplier="+result.supplierDescriptor+" secondary="+result.secondaryGetterDescriptor
                +" scope=phenotype evidence="+result.evidenceDigest);
    }
}
