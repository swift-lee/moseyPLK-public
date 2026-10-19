#!/usr/bin/env python3
"""Host tests of production adaptive coordination and callbacks; no ADB or native Android runtime."""
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile
import textwrap

from project_paths import ASSETS, BUILD_ROOT, ROOT
from test_gms_observer import STUBS

SOURCE = ROOT / 'client-compat/src/main/java/moseyPLK/client'
TESTS = ROOT / 'research/gms-adaptive-tests/moseyPLK/client'
EVIDENCE = BUILD_ROOT / 'client-compat-v0.6.0/adaptive-tests.txt'
FIXTURES = ROOT / 'research/gms-adaptive-tests'
GMS_APK = ASSETS / 'research/device/gms-apk-26.33.32-20260914/base.apk'
APKSIGNER = ASSETS / 'tools/client-compat/android-16/lib/apksigner.jar'


def compile_java(sources, classes, output, *, classpath=None):
    classes.mkdir()
    command = ['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-source', '8', '-target', '8',
               '-encoding', 'UTF-8', '-Xlint:all,-options,-restricted', '-Werror', '-d', str(classes)]
    if classpath is not None:
        command.extend(['-cp', str(classpath)])
    compiled = subprocess.run([*command, *map(str, sources)], capture_output=True, text=True, timeout=60)
    output.append(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError('Adaptive host compilation failed: ' + classes.name)


def run_java(classes, main_class, args, output):
    result = subprocess.run(['java', '-cp', str(classes),
                             'moseyPLK.client.' + main_class, *map(str, args)],
                            capture_output=True, text=True, timeout=60)
    output.append(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError('Adaptive host contracts failed: ' + main_class)


def public_certificates(stage, output):
    # Read only public certificates; no access to the module's local signing identity.
    classes = stage / 'signer-fixture-classes'
    compile_java([TESTS / 'GmsPublicSignerFixture.java'], classes, output, classpath=APKSIGNER)
    destination = stage / 'gms-public-signing-history'
    run_java(str(classes) + os.pathsep + str(APKSIGNER), 'GmsPublicSignerFixture',
             [GMS_APK, destination], output)
    with GMS_APK.open('rb') as source:
        apk_hash = hashlib.file_digest(source, 'sha256').hexdigest()
    output.append('Source APK: ' + str(GMS_APK.relative_to(ROOT)) + ' sha256=' + apk_hash + '\n')
    return destination


def main():
    if not GMS_APK.is_file() or not APKSIGNER.is_file():
        raise SystemExit('Adaptive runtime regression requires an externally retained GMS APK and '
                         'the pinned apksigner tool; no device/network fallback is used.')
    output = []
    try:
        with tempfile.TemporaryDirectory(prefix='mosey-adaptive-tests-') as temporary:
            stage = Path(temporary)
            classes = stage / 'classes'
            sources = [SOURCE / (name + '.java') for name in (
                'ResolvedGateSet', 'GmsApkSnapshot', 'GmsProfileCache', 'GmsResolutionFailure',
                'GmsResolutionTask', 'GmsHookTransaction')]
            sources.append(TESTS / 'GmsAdaptiveCoreTest.java')
            compile_java(sources, classes, output)
            work = stage / 'work'
            work.mkdir()
            run_java(classes, 'GmsAdaptiveCoreTest', [work], output)

            runtime_classes = stage / 'runtime-classes'
            runtime_sources = [SOURCE / (name + '.java') for name in (
                'ResolvedGateSet', 'GmsApkSnapshot', 'GmsProfileCache', 'GmsResolutionFailure', 'GmsResolutionTask',
                'GmsHookTransaction', 'DiagnosticEventLimiter', 'GmsDiagnosticPolicy', 'ClientPolicy',
                'GmsAdaptiveRuntime', 'GmsSourceGuard', 'GmsModuleIdentity',
                'GmsVersionAdvisory', 'GmsSignerTrust', 'HookLog', 'HookStateStore', 'HookTelemetry')]
            runtime_sources.extend(sorted((FIXTURES / 'runtime-stubs').rglob('*.java')))
            runtime_sources.append(TESTS / 'GmsAdaptiveRuntimeTest.java')
            for relative in ('de/robv/android/xposed/XposedHelpers.java', 'testsupport/Probe.java'):
                stub = stage / 'shared-stubs' / relative
                stub.parent.mkdir(parents=True, exist_ok=True)
                stub.write_text(textwrap.dedent(STUBS[relative]), encoding='utf-8')
                runtime_sources.append(stub)
            compile_java(runtime_sources, runtime_classes, output)
            # Keep business fixtures off the process classpath: every accepted definition
            # must come from its explicit test loader, and initialization remains forbidden.
            fixture_classes = stage / 'runtime-fixture-classes'
            compile_java(sorted((FIXTURES / 'runtime-fixtures').rglob('*.java')),
                         fixture_classes, output, classpath=runtime_classes)
            runtime_work = stage / 'runtime-work'
            runtime_work.mkdir()
            certificates = public_certificates(stage, output)
            run_java(runtime_classes, 'GmsAdaptiveRuntimeTest',
                     [runtime_work, fixture_classes, certificates], output)
            output.append('LIMIT: host contracts do not establish ART/LSPosed/native-load behavior or device performance.\n')
    finally:
        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE.write_text(''.join(output), encoding='utf-8')
        print(''.join(output), end='')


if __name__ == '__main__':
    main()
