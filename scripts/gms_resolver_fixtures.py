#!/usr/bin/env python3
"""Compile Phenotype and downstream-variation DEX fixtures; never use ADB.

Expected outcomes stay in this host test driver, never in DEX input or resolver
arguments. Javac/D8 output is data: no generated target class is executed.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

from project_paths import ASSETS, BUILD_ROOT, ROOT

SOURCE = ROOT / 'client-compat/resolver-tests/fixtures'
OUTPUT = BUILD_ROOT / 'gms-resolver-v017/fixtures'
TOOLS = ASSETS / 'tools/client-compat'
ANDROID_JAR = TOOLS / 'android-36/android.jar'
D8_JAR = TOOLS / 'android-16/lib/d8.jar'

CLASS_TOKENS = '''MODEL READ_CONTRACT GATE_CONTRACT NS_CONTRACT NAMESPACE
NAMESPACE_ROOT FLAG_BASE FLAG CONTEXT CHECK CACHE_HELPER CONFIG HOLDER PAYLOAD
RECEIVER SUPPLIER MEMO_FACTORY MEMO COMMAND STATE REGISTRY BINDER B_GATE_CONTRACT B_HOLDER B_RECEIVER BIND_CONNECTION'''.split()
MEMBER_TOKENS = '''READ GET_A GET_B MAKE NS_VALUE ROOT DISPATCH DEFAULT CONTEXT_GET
CHECK_NULL CAS CONFIG_NS CONFIG_CACHE REGISTER HOLDER_CONFIG FACTORY_A FACTORY_B
PAYLOAD_FIELD RECEIVER_ROOT RECEIVER_FIELD ACCESS DIRECT WRAP MEMO_SOURCE
STATE_ROOT REDUCE REGISTRY_CONTEXT REGISTRY_STATE START STOP SEND FILTER BIND
DECOY SERVICE_MEMO SERVICE_REGISTRY LIFECYCLE ADVERTISING SCANNING FLAG_NAMESPACE FLAG_KEY FLAG_DEFAULT SERVICE_INIT'''.split()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def render(template, substitutions):
    for key, value in substitutions.items():
        template = template.replace('@' + key + '@', str(value))
    unexpanded = re.findall(r'@[A-Z_]+@', template)
    if unexpanded:
        raise ValueError('unexpanded fixture tokens: ' + ', '.join(unexpanded))
    return template


def substitutions(case):
    renamed = case.get('renamed', False)
    values = {'PACKAGE': 'rx' if renamed else 'resolverfixture'}
    values.update({key: ('C' if renamed else 'F') + str(i) for i, key in enumerate(CLASS_TOKENS)})
    values.update({key: ('z' if renamed else 'm') + str(i) for i, key in enumerate(MEMBER_TOKENS)})
    has_b = case.get('expression', 'A_OR_B') != 'A' or case.get('unused_secondary', False)
    values.update({
        'NAMESPACE_TEXT': case.get('namespace', 'com.google.android.gms.nearby'),
        'NAMESPACE_DECOY': 'static { android.util.Log.d("com.google.android.gms.nearby", "unrelated literal"); }' if case.get('namespace_decoy') else '',
        'KEY_A': case.get('key', '45704091'),
        'KEY_DECOY': 'android.util.Log.d("45704091", "unrelated literal");' if case.get('key_decoy') else '',
        'SLOT_A': case.get('slot', 56), 'CAPACITY': case.get('capacity', 64),
        'DEFAULT_A': 'true' if case.get('default_true') else 'false',
        'FACTORY_DEFAULT': '!fallback' if case.get('factory_drops_default') else 'fallback',
        'DEFAULT_BODY': 'return Boolean.TRUE;' if case.get('default_wrong_source') else 'return Boolean.valueOf(@FLAG_DEFAULT@);',
        'GETTER_FIELDS': 'public static boolean changed;' if case.get('getter_side_effect') else '',
        'HOLDER_INTERFACE': '' if case.get('no_getter_interface') else 'implements @GATE_CONTRACT@',
        'GETTER_BODY': case.get('getter_body',
            ('changed = true; ' if case.get('getter_side_effect') else '')
            + ('android.util.Log.d("critical", "unexpected call"); ' if case.get('getter_extra_call') else '')
            + 'return ((Boolean) @FACTORY_A@().@READ@()).booleanValue();'),
        'WRITE_SLOT': '0' if case.get('wrong_slot') else 'slot',
        'CHECK_FIELDS': ('public static int changed;' if case.get('helper_effect') else '') + ('static { android.util.Log.d("helper initialized", "effect"); }' if case.get('helper_init_effect') else ''),
        'CHECK_BODY': ('try { object.getClass(); } catch (NullPointerException ignored) {}' if case.get('helper_swallow') else ('if (object == null) return; ' if case.get('helper_skip_null') else '') + ('changed++; ' if case.get('helper_effect') else '') + ('((Object) (String) object).getClass();' if case.get('helper_cast') else 'object.getClass();')),
        'B_CONTRACT': 'boolean @GET_B@();' if has_b and not case.get('separate_b') else '',
        'B_IMPLEMENTATION': '''public static @READ_CONTRACT@ @FACTORY_B@() { return @HOLDER_CONFIG@.@REGISTER@(54, "45830365", false); }
        public boolean @GET_B@() { return ((Boolean) @FACTORY_B@().@READ@()).booleanValue(); }''' if has_b and not case.get('separate_b') else '',
        'NULL_CHECK': ('@CHECK@.@CHECK_NULL@(key);' if case.get('helper_wrong_object') else '@CHECK@.@CHECK_NULL@(found);') if case.get('helper') else '((Object) found).getClass();',
        'BIND_CALL': '@BINDER@.@DECOY@(info.serviceInfo, context);' if case.get('decoy_bind') else '@BINDER@.@BIND@(info.serviceInfo, context);',
        'PERIPHERAL_LOG': 'android.util.Log.d("changed peripheral log", "unused consumer body");' if case.get('peripheral') else '',
        'STOP_REGISTRY': 'new @REGISTRY@((Context) null)' if case.get('wrong_registry') else '@SERVICE_REGISTRY@',
        'MEMO_CONDITION': ('!' if case.get('inverted_memo') else '') + '((Boolean) @SERVICE_MEMO@.@READ@()).booleanValue()',
        'EXTRA_READERS': '', 'EXTRA_CLASSES': '',
        'PAYLOAD_FINAL': '' if case.get('mutable_payload') else 'final',
        'RECEIVER_PAYLOAD': 'new WrongHolder()' if case.get('wrong_payload') else 'new @HOLDER@()',
        'ACCESSOR_BODY': 'return new @HOLDER@();' if case.get('accessor_allocation') else 'return (@GATE_CONTRACT@) ((@PAYLOAD@) @RECEIVER_FIELD@).@PAYLOAD_FIELD@;',
        'RECEIVER_EXTRA_INIT': 'static { ExtraInitializer.run(); }' if case.get('receiver_initializer_call') else '',
        'MEMO_FACTORY_SOURCE': 'new WrongSupplier()' if case.get('memo_wrong_source') else 'source',
        'MEMO_FINAL': '' if case.get('memo_extra_writer') or case.get('memo_source_mutable') else 'final',
        'MEMO_READ_BODY': 'return Boolean.' + case['memo_constant'].upper() + ';' if 'memo_constant' in case else 'return @MEMO_SOURCE@.@READ@();',
        'MEMO_EXTRA_WRITER': 'public void overwrite(@READ_CONTRACT@ replacement) { @MEMO_SOURCE@ = replacement; }' if case.get('memo_extra_writer') else '',
        'PLATFORM_BIND': 'forward(context, intent, connection, Context.BIND_AUTO_CREATE)' if case.get('bind_wrapper') else 'context.bindService(intent, connection, Context.BIND_AUTO_CREATE)',
        'BIND_EXTRA_HELPER': '',
    })
    access = '@RECEIVER@.@RECEIVER_ROOT@.@ACCESS@()'
    prefix = ''
    if case.get('reuse_receiver'):
        prefix = '@GATE_CONTRACT@ receiver = ' + access + '; '
        access = 'receiver'
    if case.get('wrong_receiver'):
        access = 'new @HOLDER@()'
    a = access + '.@GET_A@()'
    b = ('@B_RECEIVER@.@RECEIVER_ROOT@.@ACCESS@()' if case.get('separate_b') else access) + '.@GET_B@()'
    expression = case.get('expression', 'A_OR_B')
    source_expression = {'A': a, 'A_OR_B': a + ' || ' + b,
                         'A_AND_B': a + ' && ' + b, 'NOT_A': '!' + a}[expression]
    if case.get('boolean_constants'):
        body = 'if (' + source_expression + ') return Boolean.TRUE; return Boolean.FALSE;'
    else:
        body = 'return Boolean.valueOf(' + source_expression + ');'
    values['SUPPLIER_BODY'] = prefix + body
    if case.get('peripheral'):
        values['EXTRA_READERS'] = '''public Object unrelatedMemoReader() { return @SERVICE_MEMO@.@READ@(); }
    public boolean unrelatedGetterCaller() { return @RECEIVER@.@RECEIVER_ROOT@.@ACCESS@().@GET_A@(); }'''
        values['EXTRA_CLASSES'] = '''public static final class ExtraLog { public static void unused() { android.util.Log.d("peripheral", "arbitrary changed text"); } }'''
    if case.get('bind_wrapper'):
        forwarded_context = '((Context) null)' if case.get('bind_drop_context') else 'context'
        forwarded_intent = 'new Intent("unrelated.action")' if case.get('bind_drop_intent') else 'intent'
        forwarded_connection = 'null' if case.get('bind_drop_connection') else 'connection'
        call = forwarded_context + '.bindService(' + forwarded_intent + ', ' + forwarded_connection + ', flags)'
        if case.get('bind_cycle'):
            call = 'forwardAgain(context, intent, connection, flags)'
        values['BIND_EXTRA_HELPER'] = 'public static boolean forward(Context context, Intent intent, ServiceConnection connection, int flags) { return ' + call + '; }'
        if case.get('bind_cycle'):
            values['BIND_EXTRA_HELPER'] += 'public static boolean forwardAgain(Context context, Intent intent, ServiceConnection connection, int flags) { return forward(context, intent, connection, flags); }'
    if case.get('memo_wrong_source'):
        values['EXTRA_CLASSES'] += 'public static final class WrongSupplier implements @READ_CONTRACT@ { public Object @READ@() { return Boolean.FALSE; } }'
    if case.get('separate_b'):
        values['EXTRA_CLASSES'] += '''public interface @B_GATE_CONTRACT@ { boolean @GET_B@(); }
    public static final class @B_HOLDER@ implements @B_GATE_CONTRACT@ {
        private static final @CONFIG@ @HOLDER_CONFIG@ = new @CONFIG@(@NAMESPACE_ROOT@.@ROOT@, @CAPACITY@);
        public static @READ_CONTRACT@ @FACTORY_B@() { return @HOLDER_CONFIG@.@REGISTER@(54, "45830365", false); }
        public boolean @GET_B@() { return ((Boolean) @FACTORY_B@().@READ@()).booleanValue(); }
    }
    public static final class @B_RECEIVER@ {
        public static final @B_RECEIVER@ @RECEIVER_ROOT@ = new @B_RECEIVER@();
        private final Object @RECEIVER_FIELD@;
        public @B_RECEIVER@() { @RECEIVER_FIELD@ = new @PAYLOAD@(new @B_HOLDER@()); }
        public @B_GATE_CONTRACT@ @ACCESS@() { return (@B_GATE_CONTRACT@) ((@PAYLOAD@) @RECEIVER_FIELD@).@PAYLOAD_FIELD@; }
    }'''
    if case.get('wrong_payload'):
        values['EXTRA_CLASSES'] += 'public static final class WrongHolder implements @GATE_CONTRACT@ { public boolean @GET_A@() { return false; } ' + ('public boolean @GET_B@() { return false; }' if has_b else '') + ' }'
    if case.get('receiver_initializer_call'):
        values['EXTRA_CLASSES'] += 'public static final class ExtraInitializer { public static void run() { android.util.Log.d("init", "unexpected helper"); } }'
    if case.get('unrelated_key_declaration'):
        values['EXTRA_CLASSES'] += '''public interface OtherContract { boolean readOther(); }
    public static final class OtherHolder implements OtherContract {
        private static final @CONFIG@ config = new @CONFIG@(@NAMESPACE_ROOT@.@ROOT@, @CAPACITY@);
        public static @READ_CONTRACT@ makeOther() { return config.@REGISTER@(@SLOT_A@, "45704091", @DEFAULT_A@); }
        public boolean readOther() { @OTHER_GETTER_BODY@ }
    }'''
        values['OTHER_GETTER_BODY'] = ('makeOther(); return false;' if case.get('other_getter_invalid')
            else 'return ((Boolean) makeOther().@READ@()).booleanValue();')
    if case.get('other_namespace_key'):
        values['EXTRA_CLASSES'] += '''public static final class OtherNamespaceRoot {
        public static final @NS_CONTRACT@ root = new @NAMESPACE@("com.google.android.gms.unrelated");
    }
    public interface OtherNamespaceContract { boolean readOther(); }
    public static final class OtherNamespaceHolder implements OtherNamespaceContract {
        private static final @CONFIG@ config = new @CONFIG@(OtherNamespaceRoot.root, @CAPACITY@);
        public static @READ_CONTRACT@ makeOther() { return config.@REGISTER@(@SLOT_A@, "45704091", @DEFAULT_A@); }
        public boolean readOther() { return ((Boolean) makeOther().@READ@()).booleanValue(); }
    }'''
    if case.get('irrelevant_secondary_key'):
        values['B_IMPLEMENTATION'] = values['B_IMPLEMENTATION'].replace('"45830365"', '"45830366"')
    # Expand nested source fragments before rendering the outer template.
    for _ in range(4):
        for key, value in list(values.items()):
            if isinstance(value, str):
                for token, replacement in values.items():
                    if token != key:
                        value = value.replace('@' + token + '@', str(replacement))
                values[key] = value
    return values


def write_zip(path, entries):
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in sorted(entries):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)


def build_case(case, java=None):
    case_id = case['id']
    if not re.fullmatch(r'[a-z][a-z0-9_]*', case_id):
        raise ValueError('unsafe fixture id')
    java = java or shutil.which('java')
    if not java or not ANDROID_JAR.is_file() or not D8_JAR.is_file():
        raise RuntimeError('existing java, Android 36 SDK and D8 are required')
    values = substitutions(case)
    model = render((SOURCE / 'Model.java.in').read_text(), values)
    if case.get('phenotype_only'):
        model = model.split('    // DOWNSTREAM_COMPATIBILITY_FIXTURE', 1)[0] + '}\n'
    sources = {values['PACKAGE'].replace('.', '/') + '/' + values['MODEL'] + '.java': model}
    if not case.get('phenotype_only'):
        sources['com/google/android/gms/nearby/sharing/NearbySharingChimeraService.java'] = render(
            (SOURCE / 'NearbySharingChimeraService.java.in').read_text(), values)
    fingerprint = hashlib.sha256(json.dumps({'sources': sources,
        'android_jar': sha(ANDROID_JAR), 'd8_jar': sha(D8_JAR)}, sort_keys=True).encode()).hexdigest()
    destination = OUTPUT / case_id
    container = destination / 'dex.zip'
    metadata_path = destination / 'metadata.json'
    if destination.is_symlink() or metadata_path.is_symlink() or container.is_symlink():
        raise ValueError('symlinked fixture output refused')
    if metadata_path.is_file() and container.is_file():
        previous = json.loads(metadata_path.read_text())
        if previous.get('source_tools_fingerprint') == fingerprint and previous.get('zip_sha256') == sha(container):
            previous['case'] = case
            previous['generator_sha256'] = sha(__file__)
            metadata_path.write_text(json.dumps(previous, indent=2) + '\n')
            return container
    if destination.exists():
        shutil.rmtree(destination)
    generated, classes, dex = (destination / key for key in ('generated', 'classes', 'dex'))
    for directory in (generated, classes, dex):
        directory.mkdir(parents=True)
    java_sources = []
    for name, source in sources.items():
        path = generated / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
        java_sources.append(path)
    commands = []

    def run(argv):
        result = subprocess.run(list(map(str, argv)), text=True, capture_output=True, timeout=60, cwd=ROOT)
        commands.append({'argv': list(map(str, argv)), 'returncode': result.returncode,
                         'stdout': result.stdout, 'stderr': result.stderr})
        (destination / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(case_id + ': fixture compilation failed\n' + result.stdout + result.stderr)

    run([java, '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-source', '8', '-target', '8',
         '-encoding', 'UTF-8', '-Xlint:all,-options', '-Werror', '-bootclasspath', ANDROID_JAR,
         '-d', classes, *java_sources])
    jar = destination / 'classes.jar'
    write_zip(jar, [(path.relative_to(classes).as_posix(), path.read_bytes()) for path in classes.rglob('*.class')])
    run([java, '-cp', D8_JAR, 'com.android.tools.r8.D8', '--release', '--min-api', '36',
         '--lib', ANDROID_JAR, '--output', dex, jar])
    dex_files = sorted(dex.glob('*.dex'))
    if not dex_files or not all(path.read_bytes().startswith(b'dex\n') for path in dex_files):
        raise RuntimeError('DEX fixture missing')
    write_zip(container, [(path.name, path.read_bytes()) for path in dex_files])
    metadata_path.write_text(json.dumps({'host_only': True, 'device_tested': False,
        'target_code_executed': False, 'container_installable': False,
        'source_tools_fingerprint': fingerprint, 'zip_sha256': sha(container),
        'case': case, 'generator_sha256': sha(__file__)}, indent=2) + '\n')
    print('BUILT', case_id)
    return container


def main():
    cases = json.loads((SOURCE / 'cases.json').read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', action='append', choices=[case['id'] for case in cases])
    args = parser.parse_args()
    for case in cases:
        if not args.case or case['id'] in args.case:
            print(build_case(case).relative_to(ROOT))


if __name__ == '__main__':
    main()
