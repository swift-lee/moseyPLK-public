package dalvik.system;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Host JVM definitions with a fake Android pathList; does not parse or execute DEX. */
public class BaseDexClassLoader extends ClassLoader {
    private final PathList pathList;
    private final Path bytecode;
    private static final class PathList {
        private final Element[] dexElements;
        PathList(String[] names) {
            dexElements = new Element[names.length];
            for (int i = 0; i < names.length; i++) dexElements[i] = new Element(names[i]);
        }
    }
    private static final class Element {
        private final DexFile dexFile;
        Element(String name) { dexFile = "<missing-dex>".equals(name) ? null : new DexFile(name); }
    }
    public BaseDexClassLoader(Path bytecode, String... names) {
        super(BaseDexClassLoader.class.getClassLoader());
        this.bytecode = bytecode;
        pathList = new PathList(names);
    }
    @Override protected synchronized Class<?> loadClass(String name, boolean resolve)
            throws ClassNotFoundException {
        if (!name.startsWith("runtimefixtures.")) return super.loadClass(name, resolve);
        Class<?> result = findLoadedClass(name);
        if (result == null) result = findClass(name);
        if (resolve) resolveClass(result);
        return result;
    }
    @Override protected Class<?> findClass(String name) throws ClassNotFoundException {
        try {
            byte[] bytes = Files.readAllBytes(bytecode.resolve(name.replace('.', '/') + ".class"));
            return defineClass(name, bytes, 0, bytes.length);
        } catch (IOException missing) { throw new ClassNotFoundException(name, missing); }
    }
}
