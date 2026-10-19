#!/usr/bin/env python3
"""Build synthetic DEX query fixtures with existing javac/D8; never use ADB.

The fixture manifest describes intended source shapes and candidate identities.
It is not a semantic verifier, and the resolver must not read this answer key.
All generated Java/classes/DEX/ZIP files stay in ignored project build assets.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from project_paths import ASSETS, BUILD_ROOT, ROOT  # noqa: E402


SOURCE = Path(__file__).resolve().parent / 'fixtures'
OUTPUT = BUILD_ROOT / 'dexkit-probe/fixtures'
TOOLS = ASSETS / 'tools/client-compat'
ANDROID_JAR = TOOLS / 'android-36/android.jar'
D8_JAR = TOOLS / 'android-16/lib/d8.jar'
NAMESPACE = 'com.google.android.gms.nearby'
NAMES = {
    'BUILDER': 'fc', 'CELL': 'fd', 'READER': 'fi', 'CONTRACT': 'fk',
    'HOLDER': 'fj', 'PROVIDER': 'fp', 'SUPPLIER': 'fs', 'DUPLICATE': 'ft',
    'SIDE_EFFECT': 'fz', 'REGISTER': 'i', 'READ': 'ln', 'GETTER_A': 'a',
    'GETTER_B': 'b', 'FACTORY_A': 'g', 'FACTORY_B': 'h', 'ACCESS': 'b',
    'SUPPLY': 'ln', 'EFFECT': 'a',
}
RENAMED = {
    'BUILDER': 'nx', 'CELL': 'od', 'READER': 'pi', 'CONTRACT': 'qk',
    'HOLDER': 'ra', 'PROVIDER': 'sb', 'SUPPLIER': 'tc', 'DUPLICATE': 'ud',
    'SIDE_EFFECT': 've', 'REGISTER': 'k', 'READ': 'zz', 'GETTER_A': 'r',
    'GETTER_B': 's', 'FACTORY_A': 'm', 'FACTORY_B': 'n', 'ACCESS': 'c',
    'SUPPLY': 'xx', 'EFFECT': 'q',
}
TEMPLATES = {
    'Builder': 'BUILDER', 'Cell': 'CELL', 'Reader': 'READER',
    'Contract': 'CONTRACT', 'Holder': 'HOLDER', 'Provider': 'PROVIDER',
    'Supplier': 'SUPPLIER', 'SideEffect': 'SIDE_EFFECT',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render(template, substitutions):
    result = template
    for name, value in substitutions.items():
        result = result.replace('@' + name + '@', value)
    if re.search(r'@[A-Z_]+@', result):
        raise ValueError('Unexpanded fixture template token')
    return result


def zip_entries(destination, entries):
    with zipfile.ZipFile(destination, 'w') as archive:
        for name, data in sorted(entries):
            item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = 0o100644 << 16
            archive.writestr(item, data)


def describe(case, names):
    holder, reader, supplier = (names[key] for key in ('HOLDER', 'READER', 'SUPPLIER'))
    factory = f'L{holder};->{names["FACTORY_A"]}()L{reader};'
    getter = f'L{holder};->{names["GETTER_A"]}()Z'
    declarations = [{'namespace': NAMESPACE, 'factory': factory, 'getter': getter}]
    if 'duplicate_namespace' in case:
        duplicate = names['DUPLICATE']
        declarations.append({
            'namespace': case['duplicate_namespace'],
            'factory': f'L{duplicate};->{names["FACTORY_A"]}()L{reader};',
            'getter': f'L{duplicate};->{names["GETTER_A"]}()Z',
        })
    return {
        'fixture': case,
        'synthetic': True,
        'device_tested': False,
        'semantic_verification_performed': False,
        'expectations_are_source_design_only': True,
        'namespace': NAMESPACE,
        'namespace_anchor': f'L{holder};-><clinit>()V',
        'key': '45704091',
        'secondary_key': '45830365',
        'primary_declarations': declarations,
        'raw_primary_declaration_count': len(declarations),
        'target_namespace_declaration_count': sum(d['namespace'] == NAMESPACE for d in declarations),
        'interface_getter': f'L{names["CONTRACT"]};->{names["GETTER_A"]}()Z',
        'supplier': f'L{supplier};->{names["SUPPLY"]}()Ljava/lang/Object;',
        'supplier_directly_references_primary': 'A' in case['expression'],
        'supplier_calls_interface': 'A' in case['expression'],
        'limits': 'Candidate recall/ambiguity fixture only; no complete semantic gate or runtime flag proof.',
    }


def build_case(case, java):
    case_id = case['id']
    if not re.fullmatch(r'[a-z][a-z0-9_]*', case_id):
        raise ValueError('Unsafe fixture case identifier')
    destination = OUTPUT / case_id
    if destination.is_symlink():
        raise ValueError('Refusing to replace a symlinked fixture output')
    if destination.exists():
        shutil.rmtree(destination)
    generated = destination / 'generated'
    classes = destination / 'classes'
    dex = destination / 'dex'
    for directory in (generated, classes, dex):
        directory.mkdir(parents=True)
    names = dict(RENAMED if case.get('renamed') else NAMES)
    a = f'{names["PROVIDER"]}.x.{names["ACCESS"]}().{names["GETTER_A"]}()'
    b = f'{names["PROVIDER"]}.x.{names["ACCESS"]}().{names["GETTER_B"]}()'
    expressions = {'A': a, 'A || B': f'{a} || {b}', 'A && B': f'{a} && {b}', '!A': f'!{a}'}
    expression = case['expression']
    if expression in expressions:
        body = f'return Boolean.valueOf({expressions[expression]});'
    elif expression == 'discard A; false':
        body = f'{a};\n        return Boolean.FALSE;'
    elif expression in ('false', 'true'):
        body = 'return Boolean.' + expression.upper() + ';'
    else:
        raise ValueError('Unsupported fixture expression: ' + expression)
    effect = f'{names["SIDE_EFFECT"]}.{names["EFFECT"]}();\n        '
    if case.get('supplier_side_effect'):
        body = effect + body
    substitutions = {**names, 'NAMESPACE': NAMESPACE, 'SUPPLIER_BODY': body,
                     'GETTER_PREFIX': effect if case.get('getter_side_effect') else ''}
    sources = []
    for template, class_token in TEMPLATES.items():
        path = generated / (names[class_token] + '.java')
        path.write_text(render((SOURCE / (template + '.java.in')).read_text(), substitutions))
        sources.append(path)
    if 'duplicate_namespace' in case:
        path = generated / (names['DUPLICATE'] + '.java')
        duplicate = {**substitutions, 'HOLDER': names['DUPLICATE'],
                     'NAMESPACE': case['duplicate_namespace'], 'GETTER_PREFIX': ''}
        path.write_text(render((SOURCE / 'Holder.java.in').read_text(), duplicate))
        sources.append(path)

    commands = []

    def run(argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=60)
        commands.append({'argv': argv, 'returncode': result.returncode,
                         'stdout': result.stdout, 'stderr': result.stderr})
        (destination / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(f'Fixture build failed: {case_id}\n{result.stdout}\n{result.stderr}')

    run([java, '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-source', '8', '-target', '8',
         '-encoding', 'UTF-8', '-Xlint:all,-options', '-Werror', '-bootclasspath', ANDROID_JAR,
         '-d', classes, *sources])
    jar = destination / 'classes.jar'
    zip_entries(jar, [(path.relative_to(classes).as_posix(), path.read_bytes())
                      for path in classes.rglob('*.class')])
    run([java, '-cp', D8_JAR, 'com.android.tools.r8.D8', '--release', '--min-api', '36',
         '--lib', ANDROID_JAR, '--output', dex, jar])
    dex_files = sorted(dex.glob('*.dex'))
    if len(dex_files) != 1 or not dex_files[0].read_bytes().startswith(b'dex\n'):
        raise RuntimeError('Expected one valid DEX container for ' + case_id)
    container = destination / 'dex.zip'
    zip_entries(container, [(path.name, path.read_bytes()) for path in dex_files])
    metadata = describe(case, names)
    metadata.update({
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'container_is_installable_apk': False,
        'source_sha256': {path.name: sha(path) for path in sources},
        'tools_sha256': {'android.jar': sha(ANDROID_JAR), 'd8.jar': sha(D8_JAR)},
        'dex_sha256': sha(dex_files[0]), 'zip_sha256': sha(container),
        'dex': dex_files[0].relative_to(ROOT).as_posix(),
        'zip': container.relative_to(ROOT).as_posix(),
    })
    (destination / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(f'BUILT {case_id}: {metadata["dex"]}')
    return metadata


def main():
    cases = json.loads((SOURCE / 'cases.json').read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', action='append', choices=[case['id'] for case in cases],
                        help='Build only these cases; default builds all fixtures.')
    parser.add_argument('--list', action='store_true', help='List source shapes without building.')
    args = parser.parse_args()
    selected = [case for case in cases if not args.case or case['id'] in args.case]
    if args.list:
        for case in selected:
            print(f'{case["id"]}: {case["semantic_family"]} ({case["expression"]})')
        return
    java = shutil.which('java')
    if not java or not ANDROID_JAR.is_file() or not D8_JAR.is_file():
        raise SystemExit('Existing java, android-36/android.jar and android-16/lib/d8.jar are required.')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    results = [build_case(case, java) for case in selected]
    index = {'synthetic': True, 'semantic_verification_performed': False,
             'generator_sha256': sha(Path(__file__)), 'fixtures': results}
    (OUTPUT / 'index.json').write_text(json.dumps(index, indent=2) + '\n')
    print(f'PASS built {len(results)} synthetic DEX fixtures; no resolver verdict or device operation.')


if __name__ == '__main__':
    main()
