package moseyPLK.client;

/** Run with plain javac/java; no Android stubs or mocking library required. */
public final class ClientPolicyTest {
    private static int checks;

    private static final class Binder implements ClientPolicy.BinderHandle {
        boolean live = true;
        boolean dieAfterDescriptor;
        boolean descriptorThrows;
        String descriptor = ClientPolicy.DESCRIPTOR;
        @Override public boolean alive() { return live; }
        @Override public String descriptor() throws Exception {
            if (descriptorThrows) throw new Exception("remote has gone away");
            if (dieAfterDescriptor) live = false;
            return descriptor;
        }
    }

    private static final class Lookup implements ClientPolicy.Lookup<Binder> {
        Binder binder;
        int calls;
        boolean fail;
        String lastName;
        Lookup(Binder binder) { this.binder = binder; }
        @Override public Binder check(String name) throws Exception {
            ++calls;
            lastName = name;
            if (fail) throw new SecurityException("find denied");
            return binder;
        }
    }

    private static void check(boolean condition, String name) {
        ++checks;
        if (!condition) throw new AssertionError(name);
    }

    private static ClientPolicy.Result<Binder> resolve(Lookup lookup) {
        return ClientPolicy.resolve(ClientPolicy.PACKAGE, ClientPolicy.PACKAGE,
                ClientPolicy.INSTANCE, lookup);
    }

    private static boolean recover(ClientPolicy.Result<Binder> result, int state) {
        return ClientPolicy.mayRecover(result, ClientPolicy.PACKAGE, ClientPolicy.PACKAGE,
                ClientPolicy.COMPONENT, true, state);
    }

    public static void main(String[] args) {
        check(ClientPolicy.applies(ClientPolicy.PACKAGE, ClientPolicy.PACKAGE), "main scope");
        String[][] outside = {
            {"android", "system_server"},
            {"com.google.android.gms", "com.google.android.gms"},
            {ClientPolicy.PACKAGE, ClientPolicy.PACKAGE + ":primes_lifeboat"},
            {ClientPolicy.PACKAGE, "com.google.android.gms"},
            {"other", ClientPolicy.PACKAGE}, {null, ClientPolicy.PACKAGE},
            {ClientPolicy.PACKAGE, null}
        };
        for (String[] scope : outside) {
            Lookup lookup = new Lookup(new Binder());
            ClientPolicy.Result<Binder> result = ClientPolicy.resolve(scope[0], scope[1],
                    ClientPolicy.INSTANCE, lookup);
            check(!result.targeted && !result.ready() && lookup.calls == 0,
                    "out-of-scope process never calls service manager");
        }
        for (String name : new String[] {null, "", "wifi",
                "com.google.pixel.moseyservice.IMoseyService/default",
                ClientPolicy.DESCRIPTOR, ClientPolicy.INSTANCE + "/extra"}) {
            Lookup lookup = new Lookup(new Binder());
            ClientPolicy.Result<Binder> result = ClientPolicy.resolve(ClientPolicy.PACKAGE,
                    ClientPolicy.PACKAGE, name, lookup);
            check(!result.targeted && result.binder == null && lookup.calls == 0,
                    "other service must keep original method");
        }

        Binder actual = new Binder();
        Lookup lookup = new Lookup(actual);
        ClientPolicy.Result<Binder> ready = resolve(lookup);
        check(ready.ready() && ready.binder == actual, "return exact real handle");
        check(lookup.calls == 1 && ClientPolicy.INSTANCE.equals(lookup.lastName),
                "only check exact Google name once");
        check("ready".equals(ready.reason), "ready reason");
        check(recover(ready, 2), "recover one explicitly disabled own component");
        for (int state : new int[] {-1, 0, 1, 3, 4, 99}) {
            check(!recover(ready, state), "retain default enabled user-disabled and unknown states");
        }

        check(!ClientPolicy.mayRecover(ready, "other", ClientPolicy.PACKAGE,
                ClientPolicy.COMPONENT, true, 2), "other Context excluded");
        check(!ClientPolicy.mayRecover(ready, ClientPolicy.PACKAGE, "other",
                ClientPolicy.COMPONENT, true, 2), "other package excluded");
        check(!ClientPolicy.mayRecover(ready, ClientPolicy.PACKAGE, ClientPolicy.PACKAGE,
                ClientPolicy.COMPONENT + "Lite", true, 2), "Lite never enabled");
        check(!ClientPolicy.mayRecover(ready, ClientPolicy.PACKAGE, ClientPolicy.PACKAGE,
                ClientPolicy.COMPONENT, false, 2), "other UID user excluded");
        check(!recover(null, 2), "no successful gate no mutation");

        Lookup absent = new Lookup(null);
        ClientPolicy.Result<Binder> missing = resolve(absent);
        check(missing.targeted && !missing.ready() && "absent".equals(missing.reason),
                "absent is not synthesized");
        check(!recover(missing, 2), "absent cannot enable component");
        Binder dead = new Binder(); dead.live = false;
        ClientPolicy.Result<Binder> deadResult = resolve(new Lookup(dead));
        check(!deadResult.ready() && "dead".equals(deadResult.reason), "reject dead handle");
        check(!recover(deadResult, 2), "dead cannot enable component");
        Binder wrong = new Binder(); wrong.descriptor = "com.google.pixel.moseyservice.IMoseyService";
        ClientPolicy.Result<Binder> wrongResult = resolve(new Lookup(wrong));
        check(!wrongResult.ready() && "descriptor_mismatch".equals(wrongResult.reason),
                "wrong descriptor cannot masquerade as Google interface");
        check(!recover(wrongResult, 2), "wrong descriptor cannot enable component");
        wrong.descriptor = null;
        check(!resolve(new Lookup(wrong)).ready(), "null descriptor rejected");
        Binder dying = new Binder(); dying.dieAfterDescriptor = true;
        ClientPolicy.Result<Binder> diedResult = resolve(new Lookup(dying));
        check(!diedResult.ready() && "died_during_check".equals(diedResult.reason),
                "death during remote descriptor query excluded");
        check(!recover(diedResult, 2), "death race cannot enable component");
        Lookup denied = new Lookup(new Binder()); denied.fail = true;
        ClientPolicy.Result<Binder> deniedResult = resolve(denied);
        check(!deniedResult.ready() && "lookup_failed".equals(deniedResult.reason),
                "permission denial is not a live service");
        check(!recover(deniedResult, 2), "permission denial cannot enable component");
        Binder throwing = new Binder(); throwing.descriptorThrows = true;
        check(!resolve(new Lookup(throwing)).ready(), "descriptor exception not success");

        // Ready on the first read does not authorize enabling after the daemon dies.
        Lookup changing = new Lookup(new Binder());
        check(resolve(changing).ready(), "initial gate succeeds");
        changing.binder = null;
        check(!recover(resolve(changing), 2), "fresh pre-mutation lookup catches disappearance");
        check(ClientPolicy.MAX_ATTEMPTS > 0 && ClientPolicy.MAX_ATTEMPTS <= 30
                && ClientPolicy.RETRY_MILLIS > 0
                && (ClientPolicy.MAX_ATTEMPTS - 1) * ClientPolicy.RETRY_MILLIS <= 60000L,
                "bounded retry schedule");
        System.out.println("PASS: " + checks + " client scope, Binder, and recovery checks");
    }
}
