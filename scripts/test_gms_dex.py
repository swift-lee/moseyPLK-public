#!/usr/bin/env python3
"""Host-only standard DEX operand and conditional supplier-proof regression tests.

Reads retained APKs/fixtures, compiles host Java and synthetic DEX inputs into assets.
Does not execute target classes, access ADB, or build/sign the product APK.
"""
import json
import subprocess
import zipfile
from pathlib import Path
from project_paths import ROOT, ASSETS, BUILD_ROOT

OUT = BUILD_ROOT / 'gms-dex-tests'
PACKAGE = 'moseyPLK/client'
SRC = ROOT / 'client-compat/src/main/java' / PACKAGE
TEST = ROOT / 'client-compat/tests' / PACKAGE
RESEARCH = ROOT / 'research/gms-adaptive-tests'
FIXTURES = BUILD_ROOT / 'dexkit-probe/fixtures'
TOOLS = ASSETS / 'tools/client-compat'
OLD = ASSETS / 'research/device/gms-apk-26.33.32-20260914/base.apk'
CURRENT = ASSETS / 'research/device/discovery-20260920-230533/gms-base.apk'


def main():
    required = [OLD, CURRENT, TOOLS / 'android-36/android.jar', TOOLS / 'android-16/lib/d8.jar']
    required += [FIXTURES / name / 'dex.zip' for name in (
        'pure_a', 'pure_a_renamed', 'or_ab', 'and_ab', 'not_a', 'duplicate_other_namespace',
        'duplicate_same_namespace', 'supplier_side_effect', 'getter_side_effect',
        'constant_false', 'constant_true', 'discard_a_constant_false')]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    if missing:
        raise SystemExit('Missing existing static test assets (no device/network fallback): ' + ', '.join(missing))
    OUT.mkdir(parents=True, exist_ok=True)
    commands, logs = [], []

    def run(command):
        commands.append([str(value) for value in command])
        result = subprocess.run(commands[-1], cwd=ROOT, text=True, capture_output=True, timeout=180)
        logs.append(result.stdout + result.stderr)
        print(logs[-1], end='')
        (OUT / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        (OUT / 'results.txt').write_text(''.join(logs))
        result.check_returncode()

    classes = OUT / 'classes'
    classes.mkdir(exist_ok=True)
    run(['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-source', '8', '-target', '8', '-Xlint:-options',
         '-d', classes, SRC / 'GmsDexFile.java', SRC / 'GmsSupplierVerifier.java',
         TEST / 'GmsSupplierVerifierTest.java', RESEARCH / PACKAGE / 'GmsDexFileTest.java'])
    fixture_classes = OUT / 'fixture-classes'
    fixture_dex = OUT / 'fixture-dex'
    fixture_classes.mkdir(exist_ok=True)
    fixture_dex.mkdir(exist_ok=True)
    run(['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-source', '8', '-target', '8', '-Xlint:-options',
         '-bootclasspath', TOOLS / 'android-36/android.jar', '-d', fixture_classes,
         RESEARCH / 'fixtures/DexOperands.java'])
    jar = OUT / 'fixture.jar'
    with zipfile.ZipFile(jar, 'w') as out:
        for path in sorted(fixture_classes.rglob('*.class')):
            out.write(path, path.relative_to(fixture_classes).as_posix())
    run(['java', '-cp', TOOLS / 'android-16/lib/d8.jar', 'com.android.tools.r8.D8',
         '--min-api', '28', '--lib', TOOLS / 'android-36/android.jar', '--output', fixture_dex, jar])
    run(['java', '-cp', classes, 'moseyPLK.client.GmsSupplierVerifierTest'])
    run(['java', '-Xmx64m', '-cp', classes, 'moseyPLK.client.GmsDexFileTest',
         FIXTURES, OLD, CURRENT, fixture_dex / 'classes.dex'])


if __name__ == '__main__':
    main()
