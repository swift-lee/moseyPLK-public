#!/usr/bin/env python3
"""Build/sign the independent LSPosed client APK on the host; never uses ADB."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from urllib.parse import urlsplit

from release_config import VERSION, VERSION_CODE, CLIENT_ID
from client_gradle import prepare, environment, INPUTS as GRADLE_INPUTS, TOOLS as UI_TOOLS

from project_paths import ASSETS, BUILD_ROOT, DIST, ROOT
from public_sources import archive_sources, source_files
from client_dexkit import (DEXKIT_VERSION, INPUTS as DEXKIT_INPUTS, NATIVE_ENTRY, NATIVE_SHA256,
                           TEST_MARKER, TEST_MARKER_BYTES, dependency_assets,
                           validate_native_layout, validate_variant_marker, verified_dependencies)

NAME = f'{CLIENT_ID}-v{VERSION}'
BUILD = BUILD_ROOT / f'client-compat-v{VERSION}'
VARIANT_SOURCE_ENTRY = 'generated/moseyPLK/client/GmsBuildVariant.java'
RESOLVER_SOURCE_ENTRY = 'generated/moseyPLK/client/GmsResolverBuild.java'
RETAINED_RELEASES = {
    'moseyPLK.client-v0.6.6.apk': 'e86cc4ea692a464f43c168f0c1366cde4292cb391c8ef000f13c259a08c9786f',
    'moseyPLK.client-v0.6.6-sources.zip': 'f2e0b16f12ce6e3e86ceddc203ae4bb1b84e0e1a5c97e172f2b3e304df662e6b',
    'moseyPLK.client-v0.6.6-adaptive-test.apk': 'b48b6dda2806a6748975fa947414880f3a8e95b7d07e445680409f4e6629f491',
    'moseyPLK.client-v0.6.6-adaptive-test-sources.zip': '9c0272934a5900b5ca23a6a3abf43e22a48eeac73202124d85b27e1c449d4efe',
    'moseyPLK.client-v0.6.5.apk': '9df4b61684cd0d93ef39a9a9ea6916a8c515dc16352257abbbc367d52ddf5c33',
    'moseyPLK.client-v0.6.5-sources.zip': 'fe141e292a6d25d1210b56f0643fa10507a30c6de9de655a638db49134ab1146',
    'moseyPLK.client-v0.6.5-adaptive-test.apk': '1476babb113c6decd5dcca1718c47e4874003e2fe4b7ffdfb51e68fd5fecbf9c',
    'moseyPLK.client-v0.6.5-adaptive-test-sources.zip': 'aaf16c73565be3db318b5af7f8ab06ee0505e40cfe6fef5281dc2ee95c60e6ed',
    'moseyPLK.client-v0.6.4.apk': '3fd25a0f60f6b0c3b3d894965e6809c504b5647d5c980938ce4f8100c1c239b1',
    'moseyPLK.client-v0.6.4-sources.zip': 'f69e756a7b347889c28f8abdbfb4c343b762c9288bd5e05cf0ae7f9e5b79a9f9',
    'moseyPLK.client-v0.6.4-adaptive-test.apk': '7b05693d0382e57c6eba935102bec64fc6e8a107012d82bf819ec36bff028968',
    'moseyPLK.client-v0.6.4-adaptive-test-sources.zip': 'dc01ae819a3dd18a60c0a61ce63653b4e37417902f9be58e6078e577d55ee86c',
    'moseyPLK.client-v0.6.3.apk': '2c5676c313a1cbb72ba280fceb6d029a987fc41a9b4e0979762a4db894d846d3',
    'moseyPLK.client-v0.6.3-sources.zip': '2633089d04c8df4570922e79ae347925a9dc2ef16e1e11cb4a7460d579975854',
    'moseyPLK.client-v0.6.3-adaptive-test.apk': '7af7a5f3c0f102f1de97498620572e61829eb7f2c3a1ed4d97a1530200a47756',
    'moseyPLK.client-v0.6.3-adaptive-test-sources.zip': '778c68bd327c17ae88f164b1033164017a0d2f0b6a1e45e1939513050f1eaad5',
    'moseyPLK.client-v0.6.2.apk': '0192b7ff349fe6b80334475fb774431273303a6fd73392641484fb89d5ec587e',
    'moseyPLK.client-v0.6.2-sources.zip': '5e73714921dcb6cdb411faa42db3ac16ab63f1ff1e6a55a15b40739e31532c56',
    'moseyPLK.client-v0.6.2-adaptive-test.apk': '094c5c0cc26c53ab795039d5b46e221f62590aa0c2d90afed4ed754b84e23583',
    'moseyPLK.client-v0.6.2-adaptive-test-sources.zip': '72af40fd8eed6e52f4896ee8fa87463836384f9e896c67ec49c7caf4ded1b852',
    'moseyPLK.client-v0.6.1.apk': 'f12d49516782882a70806aac40a777df2cd0a513bf4e32cd4c1b92c52b5809e6',
    'moseyPLK.client-v0.6.1-sources.zip': '9a941bd6b92c0392ad6477ba916f01578584447b2aa36d73ecb44337e8778528',
    'moseyPLK.client-v0.6.1-adaptive-test.apk': '15bbbf01cd4da07c4f4e96234c6d7ad05fe2f886247340bc44a9a2764884cf9e',
    'moseyPLK.client-v0.6.1-adaptive-test-sources.zip': '5b109bfc9d348778672ec9280219646dd49d0f48d9e986f76c9664d969198fc5',
    'mosey-client-compat-v0.1.7.apk': '837fd0515953c4f5aa1ffa0ea87e1de4b98279c1884ff3bd43bc054acf59f2b4',
    'mosey-client-compat-v0.1.7-adaptive-test.apk': 'cffb7b0d4e38f15c94ccf178f7e72dfa47ad170fc6cf8f3a7edd99b3e9e2dad2',
    'mosey-client-compat-v0.1.7-sources.zip': '16f94674d1f0b196312d1c2b53f87aa2caecfbe947ef7f8e473cb57156ad2d37',
    'mosey-client-compat-v0.1.7-adaptive-test-sources.zip': 'ddfbe854217b83d8bd09df1fdffdbf4d0d54f1db4666ad7d6ee92845dbcf1011',
    'mosey-client-compat-v0.1.3.apk': 'f68305e30694cd74a3bc587fd14882416f6e255114902327d95d02dea6f35fc9',
    'mosey-client-compat-v0.1.3-sources.zip': '4f64902d4c61aa7bb5f47483eec99bec031e97fe574f970cf69920d1387d14fc',
    'mosey-client-compat-v0.1.4.apk': 'facfdbf8519d742869b6f5f9016c9055d0a571e6ca6cebf225f1dd0957193d26',
    'mosey-client-compat-v0.1.4-sources.zip': 'd34dfaa00f567eea3e3dc88cdb4c8623d38cc4d56edfd969f0e101056c5775f0',
    'mosey-client-compat-v0.1.5.apk': '84fde58df2735079a490064b82fd68cc07fef364b7c853ead5c1099785ab3d7c',
    'mosey-client-compat-v0.1.5-sources.zip': '950eb4a54e9080f5cf69bdd13cb277c9f0f6a263b77d6ce128502adf478682f8',
    'mosey-client-compat-v0.1.5-adaptive-test.apk': 'bee7ea800f8ebf43f0641a67c8382838cbf0383a37bf035c4e14aea1deb4c0f2',
    'mosey-client-compat-v0.1.5-adaptive-test-sources.zip': '61a2a6b1860956ef6d94abfd058c7213a8af631a1468f9a7f3f12efd43d19abe',
    'mosey-client-compat-v0.1.6.apk': 'de189889961df43eb343b6a2b4a242c04398678c49d26aa1aec0a8f6ea22659e',
    'mosey-client-compat-v0.1.6-sources.zip': 'c282142c404e8fe850fab2198f6683b8bbf68ebfb3d88cc719878ce22029fd67',
    'mosey-client-compat-v0.1.6-adaptive-test.apk': 'd685d0af6651e37adf5d139d60934592f76a1878d2c6598362968b78086155ae',
    'mosey-client-compat-v0.1.6-adaptive-test-sources.zip': 'ac3f7cca1e2f8603539c3aaa9eea436b9acdd9b4e179fb9df37469a94b89f253',
}
PUBLISHED_CERTIFICATE_SHA256 = 'f0f4827d5ea96f89472f256d77a437f9982b3e3a01597b8dbc1df51b7a811842'
GMS_RULE_VERSION = 3
GMS_KNOWN_RANGE = (263161029, 263633035)
GHOSTLOCK_UI_REFERENCE = {
    'project': 'GhostLock-App',
    'repository': 'https://github.com/YuKongA/ghostlock-app',
    'revision': '3bd95d37e4874821d4143fc7f0fbd85fc2348ee3',
    'license': 'Apache-2.0',
    'source_modified': True,
    'scope': 'Compose manager UI visual components',
}
MODULE_SOURCE_ENTRY = 'generated/moseyPLK/client/ModuleBuild.java'
RESOLVER_COMPATIBILITY_SCHEMA = 1
TOOLS_SHA = {
    'android-36/android.jar': 'd9eb9da824d9e247a352f570f01e1169e725b2954bca9e283a71786c59b59f9a',
    'api-82.jar': 'f48c635f1c7469fdec0e00ad2ea0b7a6b2f5b55065784a35b7ca3a84615e8e25',
    'android-16/aapt2': '012764928a2e5ad747531f669fcda1cf2ccd2d0b6eb8bdb728807c17e3cf16d0',
    'android-16/zipalign': '3975cdfd5379e72edbe01c6fb0a0cdc3fdb2badd9e219d0b3fe4fc35f521362a',
    'android-16/lib/d8.jar': 'e0c2803fbf9a1258051c3202daad46a2e00f33a0eb91258ac9fd373df0a832ce',
    'android-16/lib/apksigner.jar': '71e18adf733f5e112d1f062dbe6b0c2eb439a4d7c773d083c42a703c66f56df1',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def variant_paths(adaptive_test=False):
    suffix = '-adaptive-test' if adaptive_test else ''
    return NAME + suffix, BUILD.with_name(BUILD.name + suffix)


def variant_source(adaptive_test=False):
    return ('package moseyPLK.client;\n\n'
            '/** Generated by build_client_compat.py; agrees with the APK test marker. */\n'
            'public final class GmsBuildVariant {\n'
            '    public static final boolean ADAPTIVE_TEST = '
            + ('true' if adaptive_test else 'false') + ';\n'
            '    private GmsBuildVariant() { }\n'
            '}\n').encode()


def resolver_source_paths():
    """Hash the reviewed resolver/runtime sources without requiring a Git checkout."""
    prefix = 'client-compat/src/main/java/moseyPLK/client/'
    paths = sorted(path for name, path in source_files(root=ROOT)
                   if Path(name).parent.as_posix() == prefix.rstrip('/') and path.suffix == '.java'
                   and (path.name.startswith('Gms') or path.name == 'ResolvedGateSet.java'))
    if not paths or not any(path.name == 'ResolvedGateSet.java' for path in paths):
        raise SystemExit('Resolver compatibility sources are incomplete.')
    if any(path.name == 'GmsResolverBuild.java' for path in paths):
        raise SystemExit('Generated resolver identity must not hash itself.')
    return paths


def resolver_build_configuration():
    """Read only compiler/runtime settings that can affect cached resolver descriptors."""
    script = (ROOT / 'client-compat/build.gradle.kts').read_text()

    def capture(pattern, label, convert=str):
        matches = re.findall(pattern, script)
        if len(matches) != 1:
            raise SystemExit(f'Expected exactly one resolver build setting for {label}.')
        return convert(matches[0])

    source = capture(r'sourceCompatibility\s*=\s*JavaVersion\.VERSION_(\d+)', 'Java source')
    target = capture(r'targetCompatibility\s*=\s*JavaVersion\.VERSION_(\d+)', 'Java target')
    if source != target:
        raise SystemExit('Resolver Java source and target levels differ.')
    for setting in ('isMinifyEnabled = false', 'isShrinkResources = false'):
        if script.count(setting) != 1:
            raise SystemExit(f'Expected fixed resolver build setting: {setting}')
    return {
        'android_gradle_plugin': capture(
            r'id\("com\.android\.application"\)\s+version\s+"([^"]+)"', 'Android Gradle Plugin'),
        'android_compile_sdk': capture(r'compileSdk\s*=\s*(\d+)', 'compile SDK', int),
        'android_build_tools': capture(r'buildToolsVersion\s*=\s*"([^"]+)"', 'build tools'),
        'android_min_sdk': capture(r'minSdk\s*=\s*(\d+)', 'minimum SDK', int),
        'android_target_sdk': capture(r'targetSdk\s*=\s*(\d+)', 'target SDK', int),
        'java_source_target': source,
        'minify_enabled': False,
        'shrink_resources': False,
        'flatbuffers_coordinate': capture(
            r'implementation\("(com\.google\.flatbuffers:flatbuffers-java:[^"]+)"\)', 'FlatBuffers'),
        'kotlin_stdlib_coordinate': capture(
            r'implementation\("(org\.jetbrains\.kotlin:kotlin-stdlib:[^"]+)"\)', 'Kotlin stdlib'),
    }


def verification_artifact_sha(coordinate, artifact_name):
    group, name, version = coordinate.split(':')
    root = ET.parse(ROOT / 'client-compat/gradle/verification-metadata.xml').getroot()
    matches = []
    for component in root.findall('.//{*}component'):
        if component.attrib.get('group') != group or component.attrib.get('name') != name \
                or component.attrib.get('version') != version:
            continue
        for artifact in component.findall('{*}artifact'):
            if artifact.attrib.get('name') == artifact_name:
                matches.extend(item.attrib.get('value', '') for item in artifact.findall('{*}sha256'))
    if len(matches) != 1 or not re.fullmatch(r'[0-9a-f]{64}', matches[0]):
        raise SystemExit(f'Missing unique verified SHA-256 for {coordinate}/{artifact_name}.')
    return matches[0]


def resolver_compatibility():
    """Create the variant/version/UI-independent identity used by schema-3 profiles."""
    sources = {path.relative_to(ROOT).as_posix(): sha(path) for path in resolver_source_paths()}
    configuration = resolver_build_configuration()
    agp_version = configuration['android_gradle_plugin']
    flatbuffers_coordinate = configuration['flatbuffers_coordinate']
    flatbuffers_version = flatbuffers_coordinate.rsplit(':', 1)[1]
    kotlin_coordinate = configuration['kotlin_stdlib_coordinate']
    kotlin_version = kotlin_coordinate.rsplit(':', 1)[1]
    fixed = {
        'schema': RESOLVER_COMPATIBILITY_SCHEMA,
        'rule_version': GMS_RULE_VERSION,
        **configuration,
        'android_gradle_plugin_sha256': verification_artifact_sha(
            f'com.android.tools.build:gradle:{agp_version}', f'gradle-{agp_version}.jar'),
        'gradle_distribution_sha256': GRADLE_INPUTS['gradle-9.6.1-bin.zip'][0],
        'jdk_archive_sha256': GRADLE_INPUTS[
            'OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz'][0],
        'android_platform_archive_sha256': GRADLE_INPUTS['platform-37.0_r02.zip'][0],
        'android_build_tools_archive_sha256': GRADLE_INPUTS['build-tools_r37_linux.zip'][0],
        'xposed_api_82_sha256': TOOLS_SHA['api-82.jar'],
        'dexkit_version': DEXKIT_VERSION,
        'dexkit_java_sha256': DEXKIT_INPUTS['lib/dexkit-2.2.0.jar']['sha256'],
        'dexkit_native_sha256': NATIVE_SHA256,
        'flatbuffers_java_sha256': verification_artifact_sha(
            flatbuffers_coordinate, f'flatbuffers-java-{flatbuffers_version}.jar'),
        'kotlin_stdlib_sha256': verification_artifact_sha(
            kotlin_coordinate, f'kotlin-stdlib-{kotlin_version}.jar'),
    }
    inputs = {'fixed': fixed, 'sources': sources}
    encoded = json.dumps(inputs, sort_keys=True, separators=(',', ':')).encode()
    compatibility_id = hashlib.sha256(b'mosey-gms-resolver-compatibility-v1\0' + encoded).hexdigest()
    return compatibility_id, inputs


def resolver_build_source(compatibility_id):
    if len(compatibility_id) != 64 or any(value not in '0123456789abcdef' for value in compatibility_id):
        raise ValueError('Invalid resolver compatibility ID')
    return ('package moseyPLK.client;\n\n'
            '/** Generated by build_client_compat.py from resolver-only compatibility inputs. */\n'
            'public final class GmsResolverBuild {\n'
            f'    public static final String COMPATIBILITY_ID = "{compatibility_id}";\n'
            '    private GmsResolverBuild() { }\n'
            '}\n').encode()


def validate_resolver_compatibility(expected_id, expected_inputs):
    actual_id, actual_inputs = resolver_compatibility()
    if actual_id != expected_id or actual_inputs != expected_inputs:
        raise SystemExit('Resolver compatibility inputs changed during the build; retry from a stable tree.')


def validate_retained_releases():
    for name, expected in RETAINED_RELEASES.items():
        path = DIST / name
        if path.exists() and sha(path) != expected:
            raise SystemExit('Previously retained release differs from its recorded hash: ' + name)


def archive(path, entries, *, stored_names=()):
    names = [name for name, _ in entries]
    if len(names) != len(set(names)):
        raise ValueError('Archive entry names must be unique')
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name, data in sorted(entries):
            item = zipfile.ZipInfo(name, (2026, 9, 14, 0, 0, 0))
            item.external_attr = 0o100644 << 16
            item.compress_type = zipfile.ZIP_STORED if name in stored_names else zipfile.ZIP_DEFLATED
            output.writestr(item, data)


def validate_resource_layout(path):
    """Enforce Android R+ resource storage requirements on the actual APK bytes."""
    with zipfile.ZipFile(path) as apk:
        if apk.namelist().count('resources.arsc') != 1:
            raise ValueError('APK must have exactly one resources.arsc entry')
        info = apk.getinfo('resources.arsc')
    with path.open('rb') as stream:
        stream.seek(info.header_offset)
        header = stream.read(30)
        if len(header) != 30 or header[:4] != b'PK\x03\x04':
            raise ValueError('Invalid resources.arsc local ZIP header')
        method = struct.unpack_from('<H', header, 8)[0]
        name_length, extra_length = struct.unpack_from('<HH', header, 26)
        if stream.read(name_length) != b'resources.arsc':
            raise ValueError('resources.arsc local and central ZIP names differ')
    if info.compress_type != zipfile.ZIP_STORED or method != zipfile.ZIP_STORED:
        raise ValueError('Android R+ requires resources.arsc to be stored uncompressed')
    offset = info.header_offset + 30 + name_length + extra_length
    if offset % 4:
        raise ValueError(f'Android R+ requires resources.arsc 4-byte alignment: offset={offset}')
    return {'compression_method': method, 'data_offset': offset,
            'alignment_bytes': 4, 'size': info.file_size}


def validate_signing_directory(signing):
    """Keep host signing identities outside tracked project files."""
    signing = signing.resolve()
    root = ROOT.resolve()
    if not signing.is_relative_to(root):
        return signing
    if not signing.is_relative_to(ASSETS.resolve()):
        raise SystemExit('In-repository signing directories must be inside the ignored work assets.')
    relative = signing.relative_to(root).as_posix()
    tracked = subprocess.run(['git', 'ls-files', '-z', '--', relative], cwd=root,
                             capture_output=True, check=False)
    if tracked.returncode or tracked.stdout:
        raise SystemExit('Signing directory must contain no Git-tracked files.')
    for path in (relative + '/', relative + '/mosey-client-compat.p12',
                 relative + '/password.txt'):
        ignored = subprocess.run(['git', 'check-ignore', '--quiet', '--no-index', '--', path],
                                 cwd=root, capture_output=True, check=False)
        if ignored.returncode:
            raise SystemExit('Signing directory and key files must be excluded by Git ignore rules.')
    return signing


def validate_existing_signing(signing):
    """Refuse an update without the previously published signing identity."""
    key = signing / 'mosey-client-compat.p12'
    password = signing / 'password.txt'
    if not key.is_file() or not password.is_file():
        raise SystemExit('Existing signing identity required; restore the original key/password together.')
    # Export the public certificate in memory. The password itself is neither
    # read by Python nor put in command arguments, logs or build metadata.
    result = subprocess.run(['keytool', '-exportcert', '-keystore', str(key),
                             '-storetype', 'PKCS12', '-storepass:file', str(password),
                             '-alias', 'mosey-client'], capture_output=True, check=False)
    if result.returncode:
        raise SystemExit('Cannot verify the existing signing certificate; no replacement identity was created.')
    certificate = hashlib.sha256(result.stdout).hexdigest()
    if certificate != PUBLISHED_CERTIFICATE_SHA256:
        raise SystemExit('Existing signing certificate does not match the previously published client APK.')
    return certificate


def client_source_paths():
    """Use the complete publication allowlist, never local assets or tree globs."""
    return [path for _, path in source_files(root=ROOT)]


def build(tools, signing, *, existing_signing=True, adaptive_test=False, dexkit_tools=None, online=False,
          proxy=None, refresh_locks=False):
    tools, signing = tools.resolve(), signing.resolve()
    validate_existing_signing(signing)
    signing = validate_signing_directory(signing)
    name, build_root = variant_paths(adaptive_test)
    validate_retained_releases()
    dexkit_tools = (dexkit_tools or ASSETS / 'tools/dexkit-research').resolve()
    try:
        runtime_jars, native, dependencies = verified_dependencies(dexkit_tools)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        raise SystemExit(f'DexKit dependencies unavailable or changed: {error}') from error
    source_paths = client_source_paths()
    for rel, expected in TOOLS_SHA.items():
        path = tools / rel
        if not path.is_file() or sha(path) != expected:
            raise SystemExit(f'Missing or unexpected tool: {path}; see scripts/BUILD.md')
    stage = build_root / 'staging'
    if stage.exists():
        shutil.rmtree(stage)
    for subdir in ('generated', 'assets', 'jniLibs/arm64-v8a'):
        (stage / subdir).mkdir(parents=True)
    commands = []

    def run(argv, env=None, cwd=ROOT):
        argv = [str(arg) for arg in argv]
        if Path(argv[0]).name == 'gradle':
            log = build_root / 'gradle.log'
            with log.open('w') as output:
                process = subprocess.run(argv, cwd=cwd, env=env, text=True,
                                         stdout=output, stderr=subprocess.STDOUT)
            process.stdout, process.stderr = log.read_text(), ''
        else:
            process = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True)
        commands.append({'argv': argv, 'returncode': process.returncode,
                         'stdout': process.stdout, 'stderr': process.stderr})
        (build_root / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if process.returncode:
            raise SystemExit(f'Host build failed: {argv[0]}\n{process.stdout}\n{process.stderr}')
        return process.stdout

    gradle, jdk, sdk = prepare()
    env = environment(jdk, sdk)
    variant_java = stage / VARIANT_SOURCE_ENTRY
    variant_java.parent.mkdir(parents=True, exist_ok=True)
    variant_java.write_bytes(variant_source(adaptive_test))
    resolver_compatibility_id, resolver_inputs = resolver_compatibility()
    resolver_java = stage / RESOLVER_SOURCE_ENTRY
    resolver_java.write_bytes(resolver_build_source(resolver_compatibility_id))
    variant = 'adaptive-test' if adaptive_test else 'release'
    build_id = hashlib.sha256()
    for path in source_paths:
        if path.is_relative_to(ROOT / 'client-compat') or path.name in (
                'release.json', 'build_client_compat.py', 'client_gradle.py', 'client_dexkit.py'):
            build_id.update(path.relative_to(ROOT).as_posix().encode() + b'\0' + path.read_bytes())
    build_id.update(variant.encode())
    build_id = build_id.hexdigest()
    module_java = stage / MODULE_SOURCE_ENTRY
    module_java.write_text('package moseyPLK.client;\npublic final class ModuleBuild {\n'
                          f' public static final String VERSION = "{VERSION}";\n'
                          f' public static final long VERSION_CODE = {VERSION_CODE}L;\n'
                          f' public static final String BUILD_ID = "{build_id}";\n'
                          f' public static final String VARIANT = "{variant}";\n'
                          ' private ModuleBuild() {}\n}\n')
    # Keep DexKit JNI bytes exactly as reviewed. Kotlin and FlatBuffers now
    # resolve through the locked Gradle graph; old Kotlin 1.5 is research-only.
    (stage / 'jniLibs/arm64-v8a/libdexkit.so').write_bytes(native)
    dependencies['java_program_inputs'] = ['lib/dexkit-2.2.0.jar', 'locked_gradle_runtime_graph']
    dependencies['legacy_research_inputs'] = dependencies.pop('inputs')
    dependencies['gradle_runtime_graph'] = {
        'lockfile_sha256': sha(ROOT / 'client-compat/gradle.lockfile')
            if (ROOT / 'client-compat/gradle.lockfile').is_file() else None,
        'verification_metadata_sha256': sha(ROOT / 'client-compat/gradle/verification-metadata.xml')
            if (ROOT / 'client-compat/gradle/verification-metadata.xml').is_file() else None,
        'kotlin_stdlib': '2.4.20', 'compose': '1.11.1',
        'material_icons_extended': '1.7.8', 'miuix': '0.9.3', 'libsu': '6.0.0',
    }
    dependencies['ui_reference'] = GHOSTLOCK_UI_REFERENCE
    for entry, data in dependency_assets(dexkit_tools, dependencies):
        target = stage / entry
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    if adaptive_test:
        (stage / TEST_MARKER).write_bytes(TEST_MARKER_BYTES)
    argv = [gradle, '--no-daemon', '--console=plain', '--project-cache-dir',
            UI_TOOLS / 'project-cache', '-PmoseyStage=' + str(stage),
            '--dependency-verification=strict']
    if not online:
        argv.append('--offline')
    if proxy:
        address = urlsplit(proxy)
        if address.scheme != 'http' or not address.hostname or not address.port or address.username:
            raise SystemExit('Proxy must be an HTTP host:port URL without credentials')
        for scheme in ('http', 'https'):
            argv += [f'-D{scheme}.proxyHost={address.hostname}', f'-D{scheme}.proxyPort={address.port}']
    if refresh_locks:
        argv += ['--write-locks', '--write-verification-metadata', 'sha256']
    argv += ['assembleRelease', 'testReleaseUnitTest']
    run(argv, env=env, cwd=ROOT / 'client-compat')
    validate_resolver_compatibility(resolver_compatibility_id, resolver_inputs)
    unsigned_apks = list((stage / 'gradle/outputs/apk/release').glob('*-unsigned.apk'))
    if len(unsigned_apks) != 1:
        raise SystemExit('Expected exactly one unsigned Gradle release APK')
    unsigned = unsigned_apks[0]
    bin_dir = tools / 'android-16'
    aligned = stage / 'aligned.apk'
    run([bin_dir / 'zipalign', '-P', '16', '-f', '4', unsigned, aligned])
    validate_resource_layout(aligned)
    additional_native = json.loads((ROOT / 'client-compat/native-libraries.json').read_text())
    validate_native_layout(aligned, additional_native)
    validate_variant_marker(aligned, adaptive_test)

    # Package migration retains the published certificate; never create a key.
    validate_existing_signing(signing)
    key = signing / 'mosey-client-compat.p12'
    password = signing / 'password.txt'
    dist = DIST
    dist.mkdir(parents=True, exist_ok=True)
    apk = dist / (name + '.apk')
    signer = ['java', '--enable-native-access=ALL-UNNAMED', '-jar', bin_dir / 'lib/apksigner.jar']
    run([*signer, 'sign', '--ks', key, '--ks-key-alias', 'mosey-client',
         '--ks-pass', 'file:' + str(password),
         '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
         '--v3-signing-enabled', 'true', '--v4-signing-enabled', 'false',
         '--out', apk, aligned])
    signature = run([*signer, 'verify', '--verbose', '--print-certs', apk])
    (build_root / 'signature.txt').write_text(signature)
    # API36 chooses v3. Inspect the v2 block separately; this does not lower the
    # application's SDK requirement or claim compatibility with older Android.
    signature_v2 = run([*signer, 'verify', '--verbose', '--min-sdk-version', '24',
                        '--max-sdk-version', '27', apk])
    (build_root / 'signature-v2.txt').write_text(signature_v2)
    if 'Verified using v3 scheme (APK Signature Scheme v3): true' not in signature:
        raise SystemExit('APK v3 signature was not verified.')
    if 'Verified using v2 scheme (APK Signature Scheme v2): true' not in signature_v2:
        raise SystemExit('APK v2 signature was not verified.')
    run([bin_dir / 'zipalign', '-c', '-P', '16', '4', apk])
    resource_layout = validate_resource_layout(apk)
    native_layout = validate_native_layout(apk, additional_native)
    validate_variant_marker(apk, adaptive_test)
    validate_retained_releases()
    (build_root / 'resource-layout.json').write_text(json.dumps(resource_layout, indent=2) + '\n')
    (build_root / 'native-layout.json').write_text(json.dumps(native_layout, indent=2) + '\n')
    (build_root / 'manifest.txt').write_text(run([bin_dir / 'aapt2', 'dump', 'xmltree', apk,
                                           '--file', 'AndroidManifest.xml']))
    (build_root / 'badging.txt').write_text(run([bin_dir / 'aapt2', 'dump', 'badging', apk]))
    certificate_line = next(line for line in signature.splitlines()
                            if 'certificate SHA-256 digest:' in line)
    certificate = certificate_line.split(': ', 1)[1]
    if certificate != PUBLISHED_CERTIFICATE_SHA256:
        raise SystemExit('Signed APK certificate does not match the previously published client APK.')
    metadata = {
        'schema': 5, 'package': CLIENT_ID, 'version': VERSION,
        'version_code': VERSION_CODE, 'min_sdk': 36, 'target_sdk': 36,
        'variant': 'adaptive-test' if adaptive_test else 'release',
        'adaptive_test_marker': TEST_MARKER_BYTES.decode().strip() if adaptive_test else None,
        'generated_sources': {VARIANT_SOURCE_ENTRY: sha(variant_java),
                              RESOLVER_SOURCE_ENTRY: sha(resolver_java),
                              MODULE_SOURCE_ENTRY: sha(module_java)},
        'module_build_id': build_id, 'ui_implemented': True,
        'ui_reference': GHOSTLOCK_UI_REFERENCE,
        'scope': ['com.google.android.mosey', 'com.google.android.gms'],
        'api82_compile_only': True,
        'phone_operations': [], 'device_tested': False,
        'native_module_changed': True,
        'app_native_library_added': True,
        'gms_adaptive': {'scope': 'phenotype_getter',
                         'versions': 'automatic_for_all_versions',
                         'rule_version': GMS_RULE_VERSION,
                         'version_allowlist': False,
                         'whole_graph_digest_allowlist': False,
                         'variant_changes_algorithm': False,
                         'variant_changes_cache_identity': False,
                         'variant_marker_purpose': 'build_identity_only',
                         'cache_schema': 3,
                         'cache_file': 'profile-v3.bin',
                         'resolver_compatibility_id': resolver_compatibility_id,
                         'resolver_compatibility_inputs': resolver_inputs,
                         'signer_policy': 'android_verified_rotation_from_reviewed_root',
                         'device_tested': False},
        'gms_version_advisory': {'lowest_known': GMS_KNOWN_RANGE[0],
                                 'highest_known': GMS_KNOWN_RANGE[1],
                                 'comparison': 'long_version_code',
                                 'outside_known_range': 'warning_only',
                                 'blocks_resolution': False, 'ui_implemented': True},
        'gms_phenotype': {'user': 0, 'process': 'com.google.android.gms',
                          'namespace': 'com.google.android.gms.nearby', 'flag': '45704091',
                          'target': 'unique_typed_boolean_getter', 'hook_count': 1,
                          'change': 'Boolean false to true after successful natural calls only',
                          'supplier_hook': False, 'flag_45830365_changed': False,
                          'downstream_airdrop_proof_required': False, 'database_writes': False},
        'signing_mode': 'existing-published-identity',
        'certificate_sha256': certificate,
        'apk': {'file': apk.name, 'bytes': apk.stat().st_size, 'sha256': sha(apk)},
        'resources_arsc': resource_layout,
        'native_library': native_layout,
        'dependencies': dependencies,
        'tool_sha256': TOOLS_SHA,
        'gradle_tool_archives': {name: info[0] for name, info in GRADLE_INPUTS.items()},
        'sources': {p.relative_to(ROOT).as_posix(): sha(p) for p in source_paths},
    }
    metadata_bytes = (json.dumps(metadata, indent=2, ensure_ascii=False) + '\n').encode()
    validate_resolver_compatibility(resolver_compatibility_id, resolver_inputs)
    sources = dist / (name + '-sources.zip')
    archive_sources(sources, root=ROOT)
    metadata_path = dist / (name + '-build.json')
    metadata_path.write_bytes(metadata_bytes)
    for artifact in (apk, sources, metadata_path):
        artifact.with_name(artifact.name + '.sha256').write_text(f'{sha(artifact)}  {artifact.name}\n')
    print(json.dumps({'apk': str(apk), 'sha256': sha(apk), 'bytes': apk.stat().st_size,
                      'sources': str(sources)}, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', type=Path, default=ASSETS / 'tools/client-compat')
    parser.add_argument('--signing-dir', type=Path, default=ASSETS / 'signing/client-compat')
    parser.add_argument('--dexkit-tools', type=Path, default=ASSETS / 'tools/dexkit-research')
    parser.add_argument('--adaptive-test', action='store_true',
                        help='Build a separately marked APK/source archive; both variants use automatic resolution')
    parser.add_argument('--existing-signing', action='store_true',
                        help='Compatibility option; the published signing identity is now always required')
    parser.add_argument('--online', action='store_true', help='Allow Gradle dependency downloads')
    parser.add_argument('--proxy', help='HTTP proxy host:port URL without credentials')
    parser.add_argument('--refresh-locks', action='store_true', help='Explicitly regenerate reviewed dependency locks/checksums')
    args = parser.parse_args()
    build(args.tools, args.signing_dir, existing_signing=args.existing_signing,
          adaptive_test=args.adaptive_test, dexkit_tools=args.dexkit_tools, online=args.online,
          proxy=args.proxy, refresh_locks=args.refresh_locks)
