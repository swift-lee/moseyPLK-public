package moseyPLK.client;

import java.lang.reflect.Method;

/** Real reflection and scope checks; loading signatures must not run getters. */
public final class GmsDiagnosticPolicyTest {
    private static int checks;
    private static int initialized;
    private static int invoked;

    public static class Fixture {
        static { ++initialized; }
        public boolean value() { ++invoked; return false; }
        public boolean value(String unused) { ++invoked; return true; }
        public static boolean staticValue() { ++invoked; return true; }
        public int category(String unused) { ++invoked; return 1; }
    }

    public static final class Child extends Fixture {}

    private static void check(boolean value, String name) {
        ++checks;
        if (!value) throw new AssertionError(name);
    }

    public static void main(String[] args) throws Exception {
        String gms = GmsDiagnosticPolicy.PACKAGE;
        check(GmsDiagnosticPolicy.applies(gms, gms, 10118), "exact user0 main process");
        for (String[] scope : new String[][] {
                {gms, gms + ".ui"}, {gms, gms + ".persistent"}, {gms, gms + ".unstable"},
                {gms, gms + ":sandbox"}, {"android", "system_server"},
                {ClientPolicy.PACKAGE, ClientPolicy.PACKAGE}, {"other", gms},
                {gms, "other"}, {null, gms}, {gms, null}}) {
            check(!GmsDiagnosticPolicy.applies(scope[0], scope[1], 10118), "exclude other process/package");
        }
        for (int uid : new int[] {-1, 0, 1000, 9999, 110118, 99810118, 99910118}) {
            check(!GmsDiagnosticPolicy.applies(gms, gms, uid), "exclude other user/non-app UID");
        }
        GmsDiagnosticPolicy.Profile old = GmsDiagnosticPolicy.profileFor(
                263332035L, "26.33.32 (260400-974685114)");
        GmsDiagnosticPolicy.Profile current = GmsDiagnosticPolicy.profileFor(
                263436035L, "26.34.36 (260400-981326859)");
        check(old != null && current != null && old != current, "two exact independent profiles");
        check(old.versionCode == 263332035L
                && old.versionName.equals("26.33.32 (260400-974685114)"), "old profile metadata");
        check(current.versionCode == 263436035L
                && current.versionName.equals("26.34.36 (260400-981326859)"), "current profile metadata");
        check(GmsDiagnosticPolicy.profileFor(old.versionCode, old.versionName) == old,
                "profile selection retains canonical identity");
        for (String name : new String[] {null, "", "26.33.32", "26.33.32 (other)",
                "26.34.32 (260400-974685114)"}) {
            check(GmsDiagnosticPolicy.profileFor(old.versionCode, name) == null,
                    "unknown old build string rejected");
            check(GmsDiagnosticPolicy.profileFor(current.versionCode, name) == null,
                    "unknown current build string rejected");
        }
        check(GmsDiagnosticPolicy.profileFor(263332036L, old.versionName) == null,
                "unknown code rejected");
        check(GmsDiagnosticPolicy.profileFor(old.versionCode, current.versionName) == null,
                "old code/current name rejected");
        check(GmsDiagnosticPolicy.profileFor(current.versionCode, old.versionName) == null,
                "current code/old name rejected");
        check(GmsDiagnosticPolicy.profileFor(current.versionCode, "26.34.36") == null,
                "short current version rejected");
        check(old.observesClass("jpsb") && !old.observesClass("jtmb"), "old class isolation");
        check(current.observesClass("jtmb") && !current.observesClass("jpsb"), "current class isolation");
        check(!old.observesClass("ecyv") && current.observesClass("ecyv"), "supplier class isolation");
        for (GmsDiagnosticPolicy.Profile profile : new GmsDiagnosticPolicy.Profile[] {old, current}) {
            GmsDiagnosticPolicy.Spec[] first = profile.specs(), second = profile.specs();
            check(first != second && first.length == second.length && first.length > 0,
                    "spec array is a defensive copy");
            for (int i = 0; i < first.length; ++i) {
                check(first[i] == second[i], "spec identities remain canonical");
                first[i] = null;
            }
            check(profile.specs()[0] == second[0], "caller cannot mutate published profile");
        }
        check(GmsDiagnosticPolicy.moseyProvider(ClientPolicy.PACKAGE, ClientPolicy.COMPONENT),
                "exact standard provider");
        check(!GmsDiagnosticPolicy.moseyProvider(ClientPolicy.PACKAGE, ClientPolicy.COMPONENT + "Lite"),
                "Lite excluded");
        check(!GmsDiagnosticPolicy.moseyProvider("other", ClientPolicy.COMPONENT), "other provider excluded");
        check(!GmsDiagnosticPolicy.moseyProvider(null, null), "null provider excluded");

        String owner = GmsDiagnosticPolicyTest.class.getName() + "$Fixture";
        Class<?> fixture = Class.forName(owner, false, GmsDiagnosticPolicyTest.class.getClassLoader());
        GmsDiagnosticPolicy.Spec getter = new GmsDiagnosticPolicy.Spec(
                owner, "value", "boolean", false, "flag_read", "test");
        int matching = 0;
        for (Method method : fixture.getDeclaredMethods()) if (getter.matches(method)) ++matching;
        check(matching == 1, "overload resolution exact");
        check(initialized == 0 && invoked == 0, "signature inspection never initializes/invokes fixture");
        check(!getter.matches(fixture.getDeclaredMethod("value", String.class)), "parameter mismatch");
        GmsDiagnosticPolicy.Spec wrongReturn = new GmsDiagnosticPolicy.Spec(
                owner, "value", "java.lang.Boolean", false, "flag_read", "test");
        check(!wrongReturn.matches(fixture.getDeclaredMethod("value")), "boxed/primitive mismatch");
        GmsDiagnosticPolicy.Spec wrongStatic = new GmsDiagnosticPolicy.Spec(
                owner, "value", "boolean", true, "flag_read", "test");
        check(!wrongStatic.matches(fixture.getDeclaredMethod("value")), "static/instance mismatch");
        GmsDiagnosticPolicy.Spec stat = new GmsDiagnosticPolicy.Spec(
                owner, "staticValue", "boolean", true, "flag_read", "test");
        check(stat.matches(fixture.getDeclaredMethod("staticValue")), "static signature accepted");
        GmsDiagnosticPolicy.Spec category = new GmsDiagnosticPolicy.Spec(
                owner, "category", "int", false, "category", null, "java.lang.String");
        check(category.matches(fixture.getDeclaredMethod("category", String.class)), "typed parameter");
        GmsDiagnosticPolicy.Spec wrongOwner = new GmsDiagnosticPolicy.Spec(
                GmsDiagnosticPolicyTest.class.getName() + "$Child", "value", "boolean", false,
                "flag_read", "test");
        check(!wrongOwner.matches(Child.class.getMethod("value")), "inherited declaration not assumed exact");
        check(initialized == 0 && invoked == 0, "no business calls after all reflection tests");
        for (GmsDiagnosticPolicy.Profile profile : new GmsDiagnosticPolicy.Profile[] {old, current}) {
            check(!profile.observesClass("java.lang.String"), "unrelated load ignored");
            check(!profile.observesClass("jpsbExtra"), "old class prefix not enough");
            check(!profile.observesClass("jtmbExtra"), "new class prefix not enough");
            check(!profile.observesClass(null), "null class ignored");
        }
        System.out.println("PASS: " + checks + " GMS scope/build/signature and non-initialization checks");
    }
}
