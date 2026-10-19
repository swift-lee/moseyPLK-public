package moseyPLK.client;

import java.io.File;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.DexFile;

/** The current source guard accepts definitions from a single, audited base APK only. */
final class GmsSourceGuard {
    private GmsSourceGuard() { }

    static Method method(Class<?> owner, String descriptor, File base, boolean getter) throws Exception {
        if (!owner.getName().equals(ResolvedGateSet.owner(descriptor)))
            throw new IllegalStateException("declaring_class_mismatch");
        ClassLoader loader = owner.getClassLoader();
        if (!(loader instanceof BaseDexClassLoader))
            throw new IllegalStateException("unsupported_declaring_loader");
        // Inspect the actual defining loader, not the loader that delegated loadClass.
        // Reject additional/split/dynamic dex sources rather than guessing precedence.
        Object pathList = field(BaseDexClassLoader.class, "pathList").get(loader);
        Object elements = field(pathList.getClass(), "dexElements").get(pathList);
        if (elements == null || Array.getLength(elements) != 1)
            throw new IllegalStateException("ambiguous_declaring_dex_sources");
        Object element = Array.get(elements, 0);
        Object dex = field(element.getClass(), "dexFile").get(element);
        if (!(dex instanceof DexFile)) throw new IllegalStateException("missing_declaring_dex");
        // Read the existing loader element's filename; never create/load a DexFile.
        // API 36 deprecates getName but still exposes it for this source check.
        @SuppressWarnings("deprecation")
        String dexName = ((DexFile) dex).getName();
        if (dexName == null || !base.getCanonicalFile().equals(new File(dexName).getCanonicalFile()))
            throw new IllegalStateException("declaring_source_not_base_apk");
        Method method = owner.getDeclaredMethod(ResolvedGateSet.name(descriptor));
        if (method.getDeclaringClass() != owner || method.getParameterTypes().length != 0
                || method.getReturnType() != (getter ? boolean.class : Object.class)
                || Modifier.isStatic(method.getModifiers())
                || Modifier.isAbstract(method.getModifiers()) || Modifier.isNative(method.getModifiers()))
            throw new IllegalStateException("resolved_signature_mismatch");
        return method;
    }

    private static Field field(Class<?> owner, String name) throws NoSuchFieldException {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }
}
