#!/usr/bin/env python3
"""Host-only tests of the actual client APK and shared Java gate/scheduler."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

from build_client_compat import (ASSETS, BUILD, DIST, GMS_KNOWN_RANGE, GMS_RULE_VERSION,
                                 GHOSTLOCK_UI_REFERENCE, NAME, RETAINED_RELEASES, ROOT, VERSION, VERSION_CODE,
                                 VARIANT_SOURCE_ENTRY, RESOLVER_SOURCE_ENTRY, MODULE_SOURCE_ENTRY,
                                 archive, build, client_source_paths, validate_existing_signing,
                                 validate_resource_layout, validate_signing_directory, variant_paths,
                                 resolver_build_source, resolver_compatibility, resolver_source_paths,
                                 validate_resolver_compatibility)
from client_dexkit import (NATIVE_ENTRY, NATIVE_SHA256, RUNTIME_JARS, TEST_MARKER,
                           TEST_MARKER_BYTES, validate_native_layout, validate_variant_marker)

ANDROID = '{http://schemas.android.com/apk/res/android}'
PACKAGE = 'moseyPLK.client'
SCOPE = ['com.google.android.mosey', 'com.google.android.gms']
PUBLISHED_CERTIFICATE_SHA256 = 'f0f4827d5ea96f89472f256d77a437f9982b3e3a01597b8dbc1df51b7a811842'
APK = DIST / (NAME + '.apk')
ADAPTIVE_TEST = False


def pure_java_helpers():
    source = ROOT / 'client-compat/src/main/java/moseyPLK/client'
    return [source / (name + '.java') for name in (
        'ClientPolicy', 'RecoverySchedule', 'GmsDiagnosticPolicy', 'DiagnosticEventLimiter',
        'GmsRegistryEnablement', 'ResolvedGateSet', 'GmsApkSnapshot', 'GmsProfileCache',
        'GmsResolutionTask', 'GmsResolutionFailure', 'GmsHookTransaction', 'GmsDexFile',
        'GmsSupplierVerifier', 'GmsVersionAdvisory')]


def dex_classes(data):
    """Read class_defs, not string references (Xposed references are required)."""
    if data[:4] != b'dex\x0a':
        raise AssertionError('Expected standard DEX')
    count, offset = struct.unpack_from('<II', data, 56)
    strings = []
    for i in range(count):
        position = struct.unpack_from('<I', data, offset + 4 * i)[0]
        while data[position] & 0x80:
            position += 1
        position += 1
        end = data.index(b'\x00', position)
        strings.append(data[position:end].decode('utf-8', errors='replace'))
    type_count, type_offset = struct.unpack_from('<II', data, 64)
    types = [strings[struct.unpack_from('<I', data, type_offset + 4 * i)[0]]
             for i in range(type_count)]
    class_count, class_offset = struct.unpack_from('<II', data, 96)
    return [types[struct.unpack_from('<I', data, class_offset + 32 * i)[0]]
            for i in range(class_count)]


class ClientPackageTests(unittest.TestCase):
    def require_local_inputs(self, *paths):
        if any(not path.is_file() for path in paths):
            self.skipTest('This check requires explicitly supplied local APK/build/tool artifacts; no build is started.')

    def test_resolver_compatibility_identity_is_variant_and_release_independent(self):
        compatibility_id, inputs = resolver_compatibility()
        self.assertRegex(compatibility_id, r'^[0-9a-f]{64}$')
        selected = {path.relative_to(ROOT).as_posix() for path in resolver_source_paths()}
        self.assertEqual(set(inputs['sources']), selected)
        self.assertIn('client-compat/src/main/java/moseyPLK/client/ResolvedGateSet.java', selected)
        self.assertTrue(any(Path(name).name == 'GmsAdaptiveResolver.java' for name in selected))
        self.assertTrue(all(Path(name).name.startswith('Gms')
                            or Path(name).name == 'ResolvedGateSet.java' for name in selected))
        self.assertFalse(any(name.endswith(('.kt', 'release.json', 'GmsResolverBuild.java'))
                             for name in selected))
        fixed = inputs['fixed']
        self.assertEqual(fixed['rule_version'], GMS_RULE_VERSION)
        self.assertEqual(fixed['dexkit_version'], '2.2.0')
        for key in ('gradle_distribution_sha256', 'jdk_archive_sha256',
                    'android_platform_archive_sha256', 'android_build_tools_archive_sha256',
                    'android_gradle_plugin_sha256', 'xposed_api_82_sha256',
                    'dexkit_java_sha256', 'dexkit_native_sha256',
                    'flatbuffers_java_sha256', 'kotlin_stdlib_sha256'):
            self.assertRegex(fixed[key], r'^[0-9a-f]{64}$')
        self.assertEqual(fixed['kotlin_stdlib_coordinate'],
                         'org.jetbrains.kotlin:kotlin-stdlib:2.4.20')
        generated = resolver_build_source(compatibility_id)
        self.assertEqual(generated.count(compatibility_id.encode()), 1)
        self.assertNotIn(VERSION.encode(), generated)
        self.assertNotIn(b'ADAPTIVE_TEST', generated)

    def test_resolver_compatibility_guard_rejects_a_different_snapshot(self):
        compatibility_id, inputs = resolver_compatibility()
        validate_resolver_compatibility(compatibility_id, inputs)
        changed = json.loads(json.dumps(inputs))
        changed['fixed']['schema'] += 1
        with self.assertRaisesRegex(SystemExit, 'changed during the build'):
            validate_resolver_compatibility(compatibility_id, changed)

    def test_airdrop_support_ui_contract(self):
        source = (ROOT / 'client-compat/src/main/kotlin/moseyPLK/client/MainActivity.kt').read_text()
        support = source.index('title = "AirDrop 支持"')
        declared = source.index('"已声明" else "未声明"', support)
        details = source.index('title = "状态详情"', declared)
        self.assertLess(support, declared)
        self.assertLess(declared, details)

    def test_apk_has_no_mosey_application_restart_surface(self):
        production = '\n'.join((ROOT / path).read_text() for path in (
            'client-compat/src/main/java/moseyPLK/client/ClientPolicy.java',
            'client-compat/src/main/kotlin/moseyPLK/client/MainActivity.kt',
            'client-compat/src/main/kotlin/moseyPLK/client/manager/ManagerModels.kt',
            'client-compat/src/main/kotlin/moseyPLK/client/manager/ManagerViewModel.kt',
            'client-compat/src/main/kotlin/moseyPLK/client/manager/RootCommands.kt',
        ))
        for forbidden in ('LicenseMenuActivity', 'MOSEY_STOP', 'MOSEY_RESTART',
                          'RestartSequence', 'restartMosey'):
            self.assertNotIn(forbidden, production)
        self.require_local_inputs(APK)
        with zipfile.ZipFile(APK) as package:
            dex = b''.join(package.read(name) for name in package.namelist() if name.endswith('.dex'))
        for forbidden in (b'LicenseMenuActivity', b'MOSEY_STOP', b'MOSEY_RESTART',
                          b'RestartSequence', b'restartMosey'):
            self.assertNotIn(forbidden, dex)

    def test_build_metadata_matches_java_rule_and_advisory(self):
        with tempfile.TemporaryDirectory(prefix='mosey-gms-metadata-') as directory:
            exporter = Path(directory) / 'GmsPhenotypeMetadata.java'
            exporter.write_text('''
package moseyPLK.client;
public final class GmsPhenotypeMetadata {
    public static void main(String[] args) {
        System.out.println(ResolvedGateSet.RULE_VERSION);
        System.out.println(GmsVersionAdvisory.LOWEST_KNOWN);
        System.out.println(GmsVersionAdvisory.HIGHEST_KNOWN);
    }
}
''')
            subprocess.run(['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main',
                            '-Xlint:all', '-Werror', '-d', directory,
                            *map(str, pure_java_helpers()),
                            str(exporter)], check=True)
            values = subprocess.check_output(
                ['java', '-cp', directory, PACKAGE + '.GmsPhenotypeMetadata'], text=True).splitlines()
            self.assertEqual(values, [str(GMS_RULE_VERSION), *map(str, GMS_KNOWN_RANGE)])

    def test_update_requires_existing_identity_before_staging(self):
        with tempfile.TemporaryDirectory(prefix='mosey-update-signing-') as directory:
            root = Path(directory)
            signing = root / 'signing'
            for existing in [None, 'mosey-client-compat.p12', 'password.txt']:
                with self.subTest(existing=existing):
                    if existing:
                        signing.mkdir(exist_ok=True)
                        (signing / existing).write_bytes(b'dummy fixture')
                    with patch('build_client_compat.BUILD', root / 'build'):
                        with self.assertRaisesRegex(SystemExit, 'Existing signing identity required'):
                            build(root / 'tools', signing, existing_signing=True)
                    self.assertFalse((root / 'build').exists())
                    if existing:
                        (signing / existing).unlink()

    def test_update_signing_rejects_unreadable_or_wrong_certificate(self):
        with tempfile.TemporaryDirectory(prefix='mosey-update-signing-') as directory:
            signing = Path(directory)
            for name in ['mosey-client-compat.p12', 'password.txt']:
                (signing / name).write_bytes(b'dummy fixture')
            for returncode, expected in [(1, 'Cannot verify'), (0, 'does not match')]:
                with self.subTest(returncode=returncode):
                    result = subprocess.CompletedProcess([], returncode, b'wrong public certificate', b'')
                    with patch('build_client_compat.subprocess.run', return_value=result):
                        with self.assertRaisesRegex(SystemExit, expected):
                            validate_existing_signing(signing)

    def test_update_signing_checks_public_certificate_without_password_in_argv(self):
        with tempfile.TemporaryDirectory(prefix='mosey-update-signing-') as directory:
            signing = Path(directory)
            (signing / 'mosey-client-compat.p12').write_bytes(b'dummy fixture')
            (signing / 'password.txt').write_text('fixture-secret-never-in-argv\n')
            public_certificate = b'disposable public certificate fixture'
            expected = hashlib.sha256(public_certificate).hexdigest()
            result = subprocess.CompletedProcess([], 0, public_certificate, b'')
            with patch('build_client_compat.PUBLISHED_CERTIFICATE_SHA256', expected), \
                    patch('build_client_compat.subprocess.run', return_value=result) as runner:
                self.assertEqual(validate_existing_signing(signing), expected)
            argv = runner.call_args.args[0]
            self.assertIn('-exportcert', argv)
            self.assertIn('-storepass:file', argv)
            self.assertNotIn('fixture-secret-never-in-argv', ' '.join(argv))

    def test_signing_directory_is_ignored_and_untracked(self):
        with tempfile.TemporaryDirectory(prefix='mosey-signing-test-') as directory:
            root = Path(directory) / 'project'
            root.mkdir()
            subprocess.run(['git', 'init', '--quiet', str(root)], check=True)
            (root / '.gitignore').write_text('/moseyPLK-assets/\n/other-signing/\n')
            assets = root / 'moseyPLK-assets'
            signing = assets / 'signing/client-compat'
            signing.mkdir(parents=True)
            with patch('build_client_compat.ROOT', root), patch('build_client_compat.ASSETS', assets):
                self.assertEqual(validate_signing_directory(signing), signing.resolve())
                outside = Path(directory) / 'external-signing'
                self.assertEqual(validate_signing_directory(outside), outside.resolve())
                with self.assertRaisesRegex(SystemExit, 'inside the ignored work assets'):
                    validate_signing_directory(root / 'other-signing')
                # Dummy bytes in a disposable Git repository; never use a real key.
                (signing / 'mosey-client-compat.p12').write_bytes(b'dummy test identity')
                subprocess.run(['git', 'add', '-f', 'moseyPLK-assets/signing/client-compat'],
                               cwd=root, check=True)
                with self.assertRaisesRegex(SystemExit, 'Git-tracked'):
                    validate_signing_directory(signing)
                subprocess.run(['git', 'rm', '--cached', '-q', '--',
                                'moseyPLK-assets/signing/client-compat/mosey-client-compat.p12'],
                               cwd=root, check=True)
                (root / '.gitignore').write_text('')
                with self.assertRaisesRegex(SystemExit, 'Git ignore'):
                    validate_signing_directory(signing)

    def test_final_apk_resource_storage_and_alignment(self):
        self.require_local_inputs(APK)
        # Inspect actual local offsets independently of zipalign and the builder.
        data = APK.read_bytes()
        with zipfile.ZipFile(APK) as package:
            self.assertEqual(package.namelist().count('resources.arsc'), 1)
            info = package.getinfo('resources.arsc')
            self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
            header = struct.unpack_from('<4s5H3I2H', data, info.header_offset)
            self.assertEqual(header[0], b'PK\x03\x04')
            self.assertEqual(header[3], zipfile.ZIP_STORED)
            offset = info.header_offset + 30 + header[-2] + header[-1]
            self.assertEqual(offset % 4, 0)
            self.assertEqual(data[offset:offset + info.file_size], package.read(info))
        self.assertEqual(validate_resource_layout(APK)['data_offset'], offset)

    def test_resource_guard_rejects_compression_even_when_aligned(self):
        with tempfile.TemporaryDirectory(prefix='mosey-resource-test-') as directory:
            bad = Path(directory) / 'compressed.apk'
            archive(bad, [('resources.arsc', b'example resource table')])
            # A single resources.arsc entry starts at offset 44, already aligned.
            with self.assertRaisesRegex(ValueError, 'uncompressed'):
                validate_resource_layout(bad)

    def test_resource_guard_rejects_uncompressed_misalignment(self):
        with tempfile.TemporaryDirectory(prefix='mosey-resource-test-') as directory:
            bad = Path(directory) / 'misaligned.apk'
            archive(bad, [('pad', b'x'), ('resources.arsc', b'example resource table')],
                    stored_names={'pad', 'resources.arsc'})
            with self.assertRaisesRegex(ValueError, '4-byte alignment'):
                validate_resource_layout(bad)

    def test_shared_java_logic_and_scheduler(self):
        # These production helpers intentionally have no Android dependency.
        helpers = pure_java_helpers()
        # GmsDexFileTest consumes an explicit DEX path through test_gms_dex.py.
        tests = sorted(path for path in (ROOT / 'client-compat/tests').rglob('*Test.java')
                       if path.name != 'GmsDexFileTest.java')
        self.assertTrue(tests)
        with tempfile.TemporaryDirectory(prefix='mosey-client-test-') as directory:
            subprocess.run(['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main',
                            '-Xlint:all', '-Werror', '-d', directory,
                            *map(str, helpers + tests)], check=True)
            outputs = []
            for test in tests:
                class_name = '.'.join(test.relative_to(ROOT / 'client-compat/tests').with_suffix('').parts)
                outputs.append(subprocess.check_output(['java', '-cp', directory, class_name], text=True))
            BUILD.mkdir(parents=True, exist_ok=True)
            (BUILD / 'java-tests.txt').write_text(''.join(outputs))

    def test_signed_artifact(self):
        signer = ASSETS / 'tools/client-compat/android-16/lib/apksigner.jar'
        self.require_local_inputs(APK, signer, APK.with_name(NAME + '-build.json'))
        result = subprocess.check_output(['java', '--enable-native-access=ALL-UNNAMED', '-jar', str(signer), 'verify',
                                          '--verbose', '--print-certs', str(APK)], text=True)
        self.assertIn('Verified using v3 scheme (APK Signature Scheme v3): true', result)
        v2 = subprocess.check_output(['java', '--enable-native-access=ALL-UNNAMED', '-jar',
                                      str(signer), 'verify', '--verbose', '--min-sdk-version',
                                      '24', '--max-sdk-version', '27', str(APK)], text=True)
        self.assertIn('Verified using v2 scheme (APK Signature Scheme v2): true', v2)
        meta = json.loads(APK.with_name(NAME + '-build.json').read_text())
        certificate_digests = [line.split(': ', 1)[1] for line in result.splitlines()
                               if line.startswith('Signer #')
                               and ' certificate SHA-256 digest: ' in line]
        # A newly generated key would also match its own build metadata. Compare
        # the actual signing identity with the previously installed release.
        self.assertEqual(certificate_digests, [PUBLISHED_CERTIFICATE_SHA256])
        self.assertEqual(meta['certificate_sha256'], PUBLISHED_CERTIFICATE_SHA256)
        self.assertEqual(meta['scope'], SCOPE)
        self.assertEqual(hashlib.sha256(APK.read_bytes()).hexdigest(), meta['apk']['sha256'])

    def test_compiled_manifest_and_entrypoint(self):
        aapt = ASSETS / 'tools/client-compat/android-16/aapt2'
        self.require_local_inputs(APK, aapt)
        manifest = subprocess.check_output([str(aapt), 'dump', 'xmltree', str(APK),
                                             '--file', 'AndroidManifest.xml'], text=True)
        self.assertIn('"' + PACKAGE + '"', manifest)
        self.assertIn(f'versionCode(0x0101021b)={VERSION_CODE}', manifest)
        self.assertIn(f'versionName(0x0101021c)="{VERSION}"', manifest)
        self.assertRegex(manifest, r'extractNativeLibs\(0x[0-9a-f]+\)=false')
        self.assertIn('xposedscope', manifest)
        self.assertIn('"' + ';'.join(SCOPE) + '"', manifest)
        self.assertNotIn('E: service', manifest)
        self.assertNotIn('E: receiver', manifest)
        with zipfile.ZipFile(APK) as archive:
            self.assertIsNone(archive.testzip())
            entries = archive.read('assets/xposed_init').decode().splitlines()
            self.assertEqual(entries, [PACKAGE + '.MoseyHook', PACKAGE + '.GmsDiagnosticsHook'])
            dex_payloads = [archive.read(name) for name in archive.namelist() if name.endswith('.dex')]
            classes = [cls for payload in dex_payloads for cls in dex_classes(payload)]
            for entry in entries:
                self.assertIn('L' + entry.replace('.', '/') + ';', classes)
            for required in ('Lorg/luckypray/dexkit/DexKitBridge;',
                             'Lcom/google/flatbuffers/FlatBufferBuilder;',
                             'Lkotlin/jvm/internal/Intrinsics;',
                             'LmoseyPLK/client/GmsVersionAdvisory;',
                             'LmoseyPLK/client/GmsSignerTrust;',
                             'LmoseyPLK/client/GmsAdaptiveResolver;'):
                self.assertIn(required, classes)
            self.assertFalse(any(cls.startswith('Ltop/netkumiko/moseyclientcompat/') for cls in classes))
            for required in ('LmoseyPLK/client/MainActivity;', 'LmoseyPLK/client/ModuleBuild;',
                             'LmoseyPLK/client/GmsResolverBuild;', 'LmoseyPLK/client/HookStateStore;'):
                self.assertIn(required, classes)
            compatibility_id, _ = resolver_compatibility()
            self.assertTrue(any(compatibility_id.encode() in payload for payload in dex_payloads),
                            'generated resolver compatibility ID missing from compiled DEX')
            self.assertFalse(any(cls.startswith('Lde/robv/android/xposed/') for cls in classes))
            additional = json.loads((ROOT / 'client-compat/native-libraries.json').read_text())
            self.assertEqual(sorted(name for name in archive.namelist() if name.startswith('lib/')),
                             sorted([NATIVE_ENTRY, *additional]))
            self.assertFalse(any(name.endswith('.jar') for name in archive.namelist()))
            self.assertFalse(any(cls.startswith('LmoseyPLK/client/')
                                 and cls.endswith('Test;') for cls in classes))
            self.assertEqual(hashlib.sha256(archive.read(NATIVE_ENTRY)).hexdigest(), NATIVE_SHA256)
            self.assertIn('assets/mosey-dependencies.json', archive.namelist())
            packaged_dependencies = json.loads(archive.read('assets/mosey-dependencies.json'))
            self.assertEqual(packaged_dependencies['ui_reference'], GHOSTLOCK_UI_REFERENCE)
            self.assertIn('assets/third-party/Apache-2.0.txt', archive.namelist())
            self.assertIn(b'Apache License', archive.read('assets/third-party/Apache-2.0.txt'))

    def test_native_layout_and_variant_marker(self):
        align = ASSETS / 'tools/client-compat/android-16/zipalign'
        self.require_local_inputs(APK, align)
        layout = validate_native_layout(APK, json.loads((ROOT / 'client-compat/native-libraries.json').read_text()))
        self.assertEqual(layout['alignment_bytes'], 16384)
        validate_variant_marker(APK, ADAPTIVE_TEST)
        with zipfile.ZipFile(APK) as package:
            if ADAPTIVE_TEST:
                self.assertEqual(package.read(TEST_MARKER), TEST_MARKER_BYTES)
            else:
                self.assertNotIn(TEST_MARKER, package.namelist())
        subprocess.run([str(align), '-c', '-P', '16', '4', str(APK)], check=True)

    def test_source_manifest_contract(self):
        manifest = ET.parse(ROOT / 'client-compat/src/main/AndroidManifest.xml').getroot()
        self.assertNotIn('package', manifest.attrib)
        release = json.loads((ROOT / 'release.json').read_text())
        self.assertEqual(release['client_id'], PACKAGE)
        self.assertEqual(release['version'], VERSION)
        self.assertEqual(release['version_code'], VERSION_CODE)
        self.assertIsNone(manifest.find('uses-sdk'))
        app = manifest.find('application')
        self.assertNotIn(ANDROID + 'extractNativeLibs', app.attrib)
        gradle = (ROOT / 'client-compat/build.gradle.kts').read_text()
        self.assertIn('useLegacyPackaging = false', gradle)
        self.assertIn('androidx.compose.material:material-icons-extended:1.7.8', gradle)
        self.assertIn('top.yukonga.miuix.kmp:miuix-ui:0.9.3', gradle)
        self.assertIn('org.jetbrains.compose.foundation:foundation:1.11.1', gradle)
        metadata = {node.attrib[ANDROID + 'name']: node.attrib for node in app.findall('meta-data')}
        self.assertEqual(metadata['xposedscope'][ANDROID + 'value'].split(';'), SCOPE)
        self.assertEqual(metadata['xposedminversion'][ANDROID + 'value'], '82')
        self.assertEqual(len(app.findall('activity')), 1)
        self.assertEqual(app.find('activity').attrib[ANDROID + 'exported'], 'true')
        self.assertEqual(manifest.findall('uses-permission'), [])

    def test_previously_installed_client_release_is_retained(self):
        self.require_local_inputs(*(DIST / name for name in RETAINED_RELEASES))
        for name, expected in RETAINED_RELEASES.items():
            with self.subTest(artifact=name):
                self.assertEqual(hashlib.sha256((DIST / name).read_bytes()).hexdigest(), expected)

    def test_build_provenance_describes_phenotype_and_nonblocking_version_advisory(self):
        self.require_local_inputs(DIST / (NAME + '-build.json'))
        meta = json.loads(DIST.joinpath(NAME + '-build.json').read_text())
        self.assertEqual(meta['schema'], 5)
        self.assertEqual(meta['version'], VERSION)
        self.assertEqual(meta['version_code'], VERSION_CODE)
        self.assertFalse(meta['device_tested'])
        self.assertTrue(meta['native_module_changed'])
        self.assertEqual(meta['signing_mode'], 'existing-published-identity')
        self.assertEqual(meta['variant'], 'adaptive-test' if ADAPTIVE_TEST else 'release')
        self.assertEqual(meta['gms_adaptive']['scope'], 'phenotype_getter')
        self.assertEqual(meta['gms_adaptive']['versions'], 'automatic_for_all_versions')
        self.assertEqual(meta['gms_adaptive']['rule_version'], GMS_RULE_VERSION)
        self.assertFalse(meta['gms_adaptive']['version_allowlist'])
        self.assertFalse(meta['gms_adaptive']['whole_graph_digest_allowlist'])
        self.assertFalse(meta['gms_adaptive']['variant_changes_algorithm'])
        self.assertFalse(meta['gms_adaptive']['variant_changes_cache_identity'])
        self.assertEqual(meta['gms_adaptive']['variant_marker_purpose'], 'build_identity_only')
        compatibility_id, inputs = resolver_compatibility()
        self.assertEqual(meta['gms_adaptive']['cache_schema'], 3)
        self.assertEqual(meta['gms_adaptive']['cache_file'], 'profile-v3.bin')
        self.assertEqual(meta['gms_adaptive']['resolver_compatibility_id'], compatibility_id)
        self.assertEqual(meta['gms_adaptive']['resolver_compatibility_inputs'], inputs)
        self.assertEqual(meta['gms_adaptive']['signer_policy'], 'android_verified_rotation_from_reviewed_root')
        self.assertNotIn('force_adaptive', meta['gms_adaptive'])
        self.assertEqual(meta['adaptive_test_marker'], 'force_adaptive_v1' if ADAPTIVE_TEST else None)
        self.assertFalse(meta['gms_adaptive']['device_tested'])
        self.assertEqual(meta['dependencies']['java_program_inputs'], ['lib/dexkit-2.2.0.jar', 'locked_gradle_runtime_graph'])
        self.assertEqual(meta['native_library']['sha256'], NATIVE_SHA256)
        graph = meta['dependencies']['gradle_runtime_graph']
        for filename, key in [('gradle.lockfile', 'lockfile_sha256'),
                              ('gradle/verification-metadata.xml', 'verification_metadata_sha256')]:
            self.assertEqual(graph[key], hashlib.sha256((ROOT / 'client-compat' / filename).read_bytes()).hexdigest())
        self.assertEqual(graph['kotlin_stdlib'], '2.4.20')
        self.assertEqual(graph['compose'], '1.11.1')
        self.assertEqual(graph['material_icons_extended'], '1.7.8')
        self.assertEqual(graph['miuix'], '0.9.3')
        self.assertEqual(meta['ui_reference'], GHOSTLOCK_UI_REFERENCE)
        self.assertEqual(meta['dependencies']['ui_reference'], GHOSTLOCK_UI_REFERENCE)
        advisory = meta['gms_version_advisory']
        self.assertEqual((advisory['lowest_known'], advisory['highest_known']), GMS_KNOWN_RANGE)
        self.assertEqual(advisory['comparison'], 'long_version_code')
        self.assertEqual(advisory['outside_known_range'], 'warning_only')
        self.assertFalse(advisory['blocks_resolution'])
        self.assertTrue(advisory['ui_implemented'])
        self.assertNotIn('gms_diagnostic', meta)
        self.assertNotIn('gms_registry_enablement', meta)
        enablement = meta['gms_phenotype']
        self.assertEqual(enablement['process'], 'com.google.android.gms')
        self.assertEqual(enablement['user'], 0)
        self.assertEqual(enablement['namespace'], 'com.google.android.gms.nearby')
        self.assertEqual(enablement['flag'], '45704091')
        self.assertEqual(enablement['target'], 'unique_typed_boolean_getter')
        self.assertEqual(enablement['hook_count'], 1)
        self.assertFalse(enablement['supplier_hook'])
        self.assertFalse(enablement['flag_45830365_changed'])
        self.assertFalse(enablement['downstream_airdrop_proof_required'])
        self.assertFalse(enablement['database_writes'])

    def test_sources_match_and_exclude_keys_and_tools(self):
        self.require_local_inputs(DIST / (NAME + '-sources.zip'), DIST / (NAME + '-build.json'))
        with zipfile.ZipFile(DIST / (NAME + '-sources.zip')) as archive:
            meta = json.loads((DIST / (NAME + '-build.json')).read_text())
            expected_sources = {path.relative_to(ROOT).as_posix() for path in client_source_paths()}
            self.assertEqual(set(meta['sources']), expected_sources)
            self.assertEqual(set(archive.namelist()), expected_sources)
            self.assertNotIn('client-build-provenance.json', archive.namelist())
            for generated in (VARIANT_SOURCE_ENTRY, RESOLVER_SOURCE_ENTRY, MODULE_SOURCE_ENTRY):
                self.assertNotIn(generated, archive.namelist())
            for name in archive.namelist():
                self.assertFalse({'build', '.gradle', '__pycache__'}.intersection(Path(name).parts))
            for name, expected in meta['sources'].items():
                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), expected, name)
                self.assertEqual((ROOT / name).read_bytes(), archive.read(name), name)
            for name in archive.namelist():
                self.assertFalse(name.endswith(('.jar', '.apk', '.p12', '.jks', '.dex')))
                self.assertNotIn('password', name.lower())
                self.assertNotIn('research/device', name)
            self.assertIn('scripts/build_client_compat.py', archive.namelist())
            self.assertIn('scripts/test_client_package.py', archive.namelist())
            self.assertIn('scripts/client_dexkit.py', archive.namelist())
            self.assertIn('scripts/test_client_dexkit.py', archive.namelist())
            self.assertIn('scripts/project_paths.py', archive.namelist())
            self.assertIn('scripts/collect-gms-startup-readonly.sh', archive.namelist())
            self.assertIn('client-compat/third-party/GhostLock-App-Apache-2.0.txt', archive.namelist())
            self.assertIn('scripts/test_gms_adaptive.py', archive.namelist())
            self.assertIn('scripts/test_gms_resolver.py', archive.namelist())
            self.assertIn('scripts/test_gms_dex.py', archive.namelist())


if __name__ == '__main__':
    if '--adaptive-test' in sys.argv:
        sys.argv.remove('--adaptive-test')
        ADAPTIVE_TEST = True
        NAME, BUILD = variant_paths(True)
        APK = DIST / (NAME + '.apk')
    unittest.main(verbosity=2)
