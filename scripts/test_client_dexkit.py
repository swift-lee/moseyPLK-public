#!/usr/bin/env python3
"""Host dependency/layout preflight; no APK compilation, signing or device use."""
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from project_paths import ASSETS
from release_config import CLIENT_ID, VERSION
from build_client_compat import (RETAINED_RELEASES, archive, validate_retained_releases,
                                 variant_paths, variant_source)
from client_dexkit import (INPUTS, NATIVE_ENTRY, NATIVE_SHA256, PAGE_SIZE, RUNTIME_JARS,
                           TEST_MARKER, TEST_MARKER_BYTES, validate_native_elf,
                           validate_native_layout, validate_variant_marker, verified_dependencies)

TOOLS = ASSETS / 'tools/dexkit-research'


class ClientDexKitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if any(not (TOOLS / name).is_file() for name in INPUTS):
            raise unittest.SkipTest('Pinned third-party DexKit inputs are external to this public source tree.')
        cls.jars, cls.native, cls.metadata = verified_dependencies(TOOLS)

    def write_native_apk(self, path, *, native=None, compressed=False, aligned=True, extra_abi=False):
        data = self.native if native is None else native
        entry = zipfile.ZipInfo(NATIVE_ENTRY)
        entry.compress_type = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
        if aligned:
            padding = (-30 - len(NATIVE_ENTRY.encode())) % PAGE_SIZE
            entry.extra = struct.pack('<HH', 0xCAFE, padding - 4) + bytes(padding - 4)
        with zipfile.ZipFile(path, 'w') as apk:
            apk.writestr(entry, data)
            if extra_abi:
                apk.writestr('lib/x86_64/libdexkit.so', data)

    def test_fixed_dependencies_are_android_inputs(self):
        self.assertEqual(tuple(str(path.relative_to(TOOLS)) for path in self.jars), RUNTIME_JARS)
        self.assertEqual(hashlib.sha256(self.native).hexdigest(), NATIVE_SHA256)
        self.assertNotIn('lib/kotlin-stdlib-common-1.5.0.jar', RUNTIME_JARS)
        self.assertEqual(self.metadata['native']['abi'], 'arm64-v8a')
        self.assertEqual(set(self.metadata['native']['needed']),
                         {'libz.so', 'liblog.so', 'libm.so', 'libdl.so', 'libc.so'})

    def test_missing_or_modified_dependency_rejected(self):
        with tempfile.TemporaryDirectory(prefix='mosey-dependencies-') as tmp:
            root = Path(tmp)
            for relative in INPUTS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(TOOLS / relative, target)
            relative = RUNTIME_JARS[-1]
            original = (root / relative).read_bytes()
            (root / relative).write_bytes(original + b'changed')
            with self.assertRaisesRegex(ValueError, 'Missing or unexpected'):
                verified_dependencies(root)
            (root / relative).unlink()
            with self.assertRaisesRegex(ValueError, 'Missing or unexpected'):
                verified_dependencies(root)

    def test_java_api_and_d8_dependencies_in_isolated_fixture(self):
        """Compile a tiny host fixture and dependencies, without building/signing an APK."""
        tools = ASSETS / 'tools/client-compat'
        sdk = tools / 'android-36/android.jar'
        with tempfile.TemporaryDirectory(prefix='mosey-dexkit-java-') as tmp:
            root = Path(tmp)
            source = root / 'DexKitPackagingProbe.java'
            source.write_text('''
import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
public final class DexKitPackagingProbe {
    public static Object query(DexKitBridge bridge) {
        return bridge.findMethod(FindMethod.create().matcher(
                MethodMatcher.create().usingEqStrings("packaging-fixture")));
    }
}
''')
            classes, dex = root / 'classes', root / 'dex'
            classes.mkdir()
            dex.mkdir()
            compile_result = subprocess.run([
                'java', '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-source', '8', '-target', '8',
                '-Xlint:all,-options,-classfile', '-Werror', '-bootclasspath', str(sdk),
                '-classpath', os.pathsep.join(map(str, self.jars)), '-d', str(classes), str(source)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            compiled = classes / 'DexKitPackagingProbe.class'
            d8_result = subprocess.run([
                'java', '-cp', str(tools / 'android-16/lib/d8.jar'), 'com.android.tools.r8.D8',
                '--release', '--min-api', '36', '--lib', str(sdk), '--output', str(dex),
                str(compiled), *map(str, self.jars)], capture_output=True, text=True, timeout=60)
            self.assertEqual(d8_result.returncode, 0, d8_result.stderr)
            output = b''.join(path.read_bytes() for path in dex.glob('*.dex'))
            for descriptor in (b'LDexKitPackagingProbe;', b'Lorg/luckypray/dexkit/DexKitBridge;',
                               b'Lcom/google/flatbuffers/FlatBufferBuilder;',
                               b'Lkotlin/jvm/internal/Intrinsics;'):
                self.assertIn(descriptor, output)

    def test_native_elf_rejects_wrong_architecture(self):
        data = bytearray(self.native)
        struct.pack_into('<H', data, 18, 62)  # EM_X86_64
        with self.assertRaisesRegex(ValueError, 'AArch64'):
            validate_native_elf(data)

    def test_native_elf_rejects_four_kilobyte_load_alignment(self):
        data = bytearray(self.native)
        phoff = struct.unpack_from('<Q', data, 32)[0]
        size, count = struct.unpack_from('<HH', data, 54)
        for i in range(count):
            at = phoff + i * size
            if struct.unpack_from('<I', data, at)[0] == 1:
                struct.pack_into('<Q', data, at + 48, 4096)
                break
        with self.assertRaisesRegex(ValueError, '16 KiB'):
            validate_native_elf(data)

    def test_native_zip_accepts_exact_uncompressed_aligned_artifact(self):
        with tempfile.TemporaryDirectory(prefix='mosey-native-layout-') as tmp:
            apk = Path(tmp) / 'fixture.apk'
            self.write_native_apk(apk)
            layout = validate_native_layout(apk)
            self.assertEqual(layout['data_offset'], PAGE_SIZE)
            self.assertEqual(layout['sha256'], NATIVE_SHA256)

    def test_native_zip_rejects_compression_even_when_aligned(self):
        with tempfile.TemporaryDirectory(prefix='mosey-native-layout-') as tmp:
            apk = Path(tmp) / 'fixture.apk'
            self.write_native_apk(apk, compressed=True)
            with self.assertRaisesRegex(ValueError, 'uncompressed'):
                validate_native_layout(apk)

    def test_native_zip_rejects_uncompressed_misalignment(self):
        with tempfile.TemporaryDirectory(prefix='mosey-native-layout-') as tmp:
            apk = Path(tmp) / 'fixture.apk'
            self.write_native_apk(apk, aligned=False)
            with self.assertRaisesRegex(ValueError, '16 KiB ZIP'):
                validate_native_layout(apk)

    def test_native_zip_rejects_changed_bytes_and_extra_abi(self):
        with tempfile.TemporaryDirectory(prefix='mosey-native-layout-') as tmp:
            apk = Path(tmp) / 'fixture.apk'
            self.write_native_apk(apk, native=self.native + b'changed')
            with self.assertRaisesRegex(ValueError, 'fixed Android artifact'):
                validate_native_layout(apk)
            self.write_native_apk(apk, extra_abi=True)
            with self.assertRaisesRegex(ValueError, 'exactly the reviewed arm64'):
                validate_native_layout(apk)

    def test_release_rejects_test_marker_and_test_requires_exact_marker(self):
        with tempfile.TemporaryDirectory(prefix='mosey-variant-') as tmp:
            apk = Path(tmp) / 'fixture.apk'
            archive(apk, [])
            validate_variant_marker(apk, False)
            with self.assertRaisesRegex(ValueError, 'requires its exact'):
                validate_variant_marker(apk, True)
            archive(apk, [(TEST_MARKER, TEST_MARKER_BYTES)])
            validate_variant_marker(apk, True)
            with self.assertRaisesRegex(ValueError, 'must not contain'):
                validate_variant_marker(apk, False)
            archive(apk, [(TEST_MARKER, b'force_adaptive_v1')])
            with self.assertRaisesRegex(ValueError, 'requires its exact'):
                validate_variant_marker(apk, True)


    def test_additional_ui_jni_requires_explicit_hash_abi_dependencies_and_alignment(self):
        entry = 'lib/arm64-v8a/libfixture.so'
        expected = {entry: {'sha256': NATIVE_SHA256,
                           'needed': ['libz.so', 'liblog.so', 'libm.so', 'libdl.so', 'libc.so']}}
        with tempfile.TemporaryDirectory(prefix='mosey-ui-native-') as tmp:
            apk = Path(tmp) / 'fixture.apk'
            self.write_native_apk(apk)
            with zipfile.ZipFile(apk, 'a') as package:
                info = zipfile.ZipInfo(entry)
                padding = (-package.fp.tell() - 30 - len(entry)) % PAGE_SIZE
                if 0 < padding < 4:
                    padding += PAGE_SIZE
                if padding:
                    info.extra = struct.pack('<HH', 0xCAFE, padding - 4) + bytes(padding - 4)
                info.compress_type = zipfile.ZIP_STORED
                package.writestr(info, self.native)
            with self.assertRaisesRegex(ValueError, 'exactly the reviewed'):
                validate_native_layout(apk)
            result = validate_native_layout(apk, expected)
            self.assertEqual(result['additional_libraries'][entry]['sha256'], NATIVE_SHA256)
            wrong_hash = {entry: dict(expected[entry], sha256='0' * 64)}
            with self.assertRaisesRegex(ValueError, 'pinned artifact'):
                validate_native_layout(apk, wrong_hash)
            wrong_deps = {entry: dict(expected[entry], needed=['libc.so'])}
            with self.assertRaisesRegex(ValueError, 'Unexpected Android native dependencies'):
                validate_native_layout(apk, wrong_deps)

    def test_variants_have_distinct_names_and_build_directories(self):
        release_name, release_build = variant_paths(False)
        test_name, test_build = variant_paths(True)
        self.assertEqual(release_name, f'{CLIENT_ID}-v{VERSION}')
        self.assertEqual(test_name, release_name + '-adaptive-test')
        self.assertEqual(test_build.name, release_build.name + '-adaptive-test')
        self.assertNotEqual(release_build, test_build)
        self.assertIn(b'ADAPTIVE_TEST = false;', variant_source(False))
        self.assertIn(b'ADAPTIVE_TEST = true;', variant_source(True))

    def test_retained_release_guard_rejects_changed_old_artifact(self):
        with tempfile.TemporaryDirectory(prefix='mosey-retained-') as tmp:
            root = Path(tmp)
            (root / next(iter(RETAINED_RELEASES))).write_bytes(b'changed')
            with patch('build_client_compat.DIST', root):
                with self.assertRaisesRegex(SystemExit, 'Previously retained release'):
                    validate_retained_releases()

    def test_archive_rejects_duplicate_entries(self):
        with tempfile.TemporaryDirectory(prefix='mosey-duplicate-') as tmp:
            with self.assertRaisesRegex(ValueError, 'unique'):
                archive(Path(tmp) / 'fixture.zip', [('same', b'1'), ('same', b'2')])


if __name__ == '__main__':
    unittest.main(verbosity=2)
