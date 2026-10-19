#!/usr/bin/env python3
"""Build the opt-in Mosey registration experiment, without contacting a device."""
import argparse
import json
import os
from pathlib import Path
from project_paths import ASSETS
import shutil
import subprocess

from build_module import (DONOR, LAUNCHER, LAUNCHER_SHA, ROOT, SEPOLICY_SHA, sha,
                          copy_public_tree, stage_module_inputs, validate_module_inputs)
from build_load_probe import archive, PROBE, LIBRARY as PROBE_LIBRARY
from public_sources import archive_sources, source_files

from release_config import VERSION, VERSION_CODE, SERVICE_ID

MODULE_ID = SERVICE_ID
OUTPUT = f'{MODULE_ID}-v{VERSION}.zip'
LIBRARY = 'system/odm/lib64/libmosey_registration_compat.so'
CONTROL_HELPER = 'mosey_service_control'
BUILD = ASSETS / f'build/registration-compat-v{VERSION}'
STAGE = BUILD / 'module'
RETAINED_RELEASES = {
    'moseyPLK.service-v0.6.7.zip': 'a3c84ba39e24f28f66b700a1668f581a1ab13ca6ad458ec9ff4e29a33248c832',
    'moseyPLK.service-v0.6.7-sources.zip': '5e31a794955c4bd4f0bc5669cee973efbeec9034349095edfc076862c1be7497',
    'moseyPLK.service-v0.6.6.zip': '80b0c5f0bcce45c62a6abeb0267ab8c5953b56208bcda555c2d0bdfe24546d1f',
    'moseyPLK.service-v0.6.6-sources.zip': 'c0a7fc9de7e10c208f2aa699646770ab783c099ec74424c290087f1ffc6105ae',
    'moseyPLK.service-v0.6.5.zip': '9dd543f761b3e42ffbe200a7f13b4bd0e0b8764aaba5f68325d58891b1b72f6f',
    'moseyPLK.service-v0.6.5-sources.zip': '2564a553fdbee74b5e6c5515aee9467978da44c08bdc17c21387d3118e7bdb56',
    'moseyPLK.service-v0.6.4.zip': '08dc88395acd2b594b492b2a1b65007a04c869785606a61e5ffe6e8a8bbd2f44',
    'moseyPLK.service-v0.6.4-sources.zip': 'eb3b800f407322c944cb3e8f4da9525eee2f4b7664595f5ba63afbc6b6f3782a',
    'moseyPLK.service-v0.6.3.zip': '1cf835baec98f050cfd226efbc597a4f027f3906fdf72e889638576baedad4b7',
    'moseyPLK.service-v0.6.3-sources.zip': '078f28ee9f01528bfeefa083f2977e406246e103039ddc2df68024a8903bf356',
    'moseyPLK.service-v0.6.2.zip': 'e37e55335fc6e5f974bd29d0b5080351611b8020f1b38078fc28248d3f586497',
    'moseyPLK.service-v0.6.2-sources.zip': '213e999eeb41a0e7b1d86e5aa88f476986bb965069775b74b099e546fdba6cb2',
    'moseyPLK.service-v0.6.1.zip': 'a616903e6e2ece51c7cf13f442953590af303c8b99be3b5498c436857b427fc0',
    'moseyPLK.service-v0.6.1-sources.zip': '62beb6a3573f3e616ae1b4d97b9517fed14d4d86dc5adaa9a95bdfc1092d389b',
}


def validate_retained_releases():
    for name, expected in RETAINED_RELEASES.items():
        path = ASSETS / 'dist' / name
        if path.exists() and sha(path) != expected:
            raise SystemExit('Previously retained release differs from its recorded hash: ' + name)


def build(ndk):
    inputs = validate_module_inputs()
    validate_retained_releases()
    clang = ndk / 'toolchains/llvm/prebuilt/linux-x86_64/bin/clang'
    readelf = clang.with_name('llvm-readelf')
    for tool in [clang, readelf]:
        if not tool.is_file():
            raise SystemExit(f'Missing NDK tool: {tool}; pass --ndk or ANDROID_NDK_HOME')
    native = BUILD / 'native'
    native.mkdir(parents=True, exist_ok=True)
    probe_source = ROOT / 'native/load-probe'
    compat_source = ROOT / 'native/registration-compat'
    control_source = ROOT / 'native/service-control'
    flags = ['--target=aarch64-linux-android35', '-std=c11', '-Oz', '-Wall', '-Wextra',
             '-Werror', '-Wconversion', '-Wshadow', '-Wpedantic',
             '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
             '-fvisibility=hidden', '-mbranch-protection=standard',
             '-Wl,-z,relro,-z,now,-z,noexecstack', '-Wl,--build-id=sha1',
             f'-ffile-prefix-map={ROOT}=.', '-Wl,-z,max-page-size=16384']
    commands = [
        [str(clang), *flags, '-fPIE', '-pie', str(control_source / 'control.c'),
         str(probe_source / 'probe_parse.c'), '-o', str(native / CONTROL_HELPER)],
        [str(clang), *flags, '-fPIE', '-pie', str(probe_source / 'probe.c'),
         str(probe_source / 'probe_parse.c'), '-ldl', '-o', str(native / Path(PROBE).name)],
        [str(clang), *flags, '-fPIC', '-shared', str(probe_source / 'marker.c'),
         '-Wl,-soname,libmosey_load_probe.so', '-o', str(native / Path(PROBE_LIBRARY).name)],
        # The compatibility source has its own narrow export version script.
        [str(clang), *flags, '-fPIC', '-shared', str(compat_source / 'compat.c'),
         str(compat_source / 'identity.c'), str(probe_source / 'probe_parse.c'),
         '-I', str(probe_source), '-ldl',
         '-Wl,-soname,libmosey_registration_compat.so',
         '-Wl,--version-script=' + str(compat_source / 'exports.map'),
         '-Wl,--no-undefined', '-o', str(native / Path(LIBRARY).name)],
    ]
    for command in commands:
        subprocess.run(command, check=True)
    binary_paths = [native / Path(rel).name for rel in [PROBE, PROBE_LIBRARY, LIBRARY, CONTROL_HELPER]]
    for file in binary_paths:
        data = file.read_bytes()
        assert data[:6] == b'\x7fELF\x02\x01' and int.from_bytes(data[18:20], 'little') == 183
        details = subprocess.check_output([str(readelf), '-h', '-l', '-d', '-n', '-Ws', str(file)], text=True)
        needed = '\n'.join(line for line in details.splitlines() if '(NEEDED)' in line)
        assert 'libbinder' not in needed and 'libc++' not in needed
        if file.name == Path(LIBRARY).name:
            assert 'AServiceManager_addService@@LIBBINDER_NDK' in details
        (BUILD / (file.name + '.readelf.txt')).write_text(details)
    metadata = {
        'ndk': (ndk / 'source.properties').read_text(),
        'clang': subprocess.check_output([str(clang), '--version'], text=True),
        'commands': [[arg.replace(str(ndk), '${NDK}').replace(str(ROOT), '${REPO}')
                      for arg in command] for command in commands],
    }
    (BUILD / 'toolchain.json').write_text(json.dumps(metadata, indent=2) + '\n')

    if STAGE.exists():
        shutil.rmtree(STAGE)
    copy_public_tree('module-src', STAGE)
    (STAGE / 'customize.sh').rename(STAGE / 'customize-base.sh')
    # Remove the manager Action inherited from the historical v0.4.1 layer.
    (STAGE / 'action.sh').unlink(missing_ok=True)
    customize_base = STAGE / 'customize-base.sh'
    customize_base.write_text(customize_base.read_text().replace('service.sh action.sh uninstall.sh',
                                                                 'service.sh uninstall.sh'))
    copy_public_tree('experiments/registration-compat/module', STAGE, exclude=('action.sh',))
    shutil.copyfile(ROOT / 'experiments/load-probe/module/load-probe.sh', STAGE / 'load-probe.sh')
    stage_module_inputs(STAGE, inputs)
    for rel in [PROBE, PROBE_LIBRARY, LIBRARY, CONTROL_HELPER]:
        shutil.copyfile(native / Path(rel).name, STAGE / rel)
    shutil.copyfile(ROOT / 'research/scripts/collect-device.sh', STAGE / 'collect-device.sh')
    shutil.copyfile(ROOT / 'scripts/collect-registration-readonly.sh', STAGE / 'collect-registration-readonly.sh')
    shutil.copyfile(ROOT / 'experiments/registration-compat/README.md', STAGE / 'README.md')
    (STAGE / 'module.prop').write_text(
        f'id={MODULE_ID}\nname=moseyPLK Service\n'
        f'version=v{VERSION}\nversionCode={VERSION_CODE}\n'
        'author=PLK110 adaptation; original Z Fold6 launcher\n'
        'description=[⚪ Unknown] Native Mosey service for PLK110.\n')
    provenance = {
        'module_id': MODULE_ID, 'version': VERSION, 'version_code': VERSION_CODE,
        'experiment': 'native-registration-with-explicit-control',
        'control': {'schema': 1, 'root_only': True, 'module_local_helper': CONTROL_HELPER,
                    'commands': ['capabilities', 'status', 'start', 'stop', 'restart'],
                    'budgets_seconds': {'status': 10, 'start': 180, 'stop': 30, 'restart': 210},
                    'signal': 'pidfd SIGTERM only', 'adopt_existing_process': False,
                    'manager_action': False,
                    'public_start_preflight': {
                        'caller_mount_namespace': 'must match init',
                        'observed_state': 'exactly Stopped',
                        'unknown_is_stopped': False,
                    },
                    'device_tested': False},
        'boot_start': {
            'entrypoint': 'service.sh',
            'registration_command': 'registration-compat.sh service 180',
            'registration_budget_seconds': 180,
            'readiness_retry_window_seconds': 60,
            'bounded_queries_seconds': {'package': 8, 'binder': 5},
            'query_timeouts_are_independent': True,
            'complete_binder_list_required': True,
            'system_server_identity_rechecked_after_queries': True,
            'payload_mount_views': ['caller', 'init', 'system_server'],
            'caller_mount_namespace_may_differ_from_init': True,
            'uses_public_control_start': False,
            'shared_control_lock': True,
            'restarts_system_processes': False,
            'device_tested': False,
        },
        'event_log': {'tag': 'KernelSU', 'max_bytes': 1048576, 'backups': 2, 'private': True},
        'starts_donor': True, 'installation_opts_into_experiment': True,
        'service_name': 'com.google.android.moseyservice.IMoseyService/default',
        'original_files': DONOR, 'launcher_sha256': LAUNCHER_SHA,
        'launcher_byte_identical': True, 'donor_changes': False,
        'sepolicy_sha256': SEPOLICY_SHA, 'policy_changes_from_v041': False,
        'extra_mounts': [PROBE, PROBE_LIBRARY, LIBRARY], 'mounting': 'external provider only',
        'system_library_replacement': False, 'servicemanager_injection': False,
        'client_adaptation': False, 'component_state_changes': False, 'database_changes': False,
        'device_installation_tested': False, 'device_registration_tested': False,
        'device_transfer_tested': False,
        'manager_status': {
            'preferred_field': 'temporary module config override.description',
            'fallback_field': 'module.prop:description', 'poll_interval_seconds': 30,
            'binder_probe': 'passive service list', 'device_tested': False,
            'webui': False,
        },
        'runtime_mutable_files': ['module.prop'],
        'payload_checksum_phase': 'installer extraction, before runtime status updates',
        'input_distribution': 'Restricted local inputs are not included in public sources.',
        'generated_compatibility_sha256': sha(inputs['compatibility.sh']),
        'payload_checksum_scope': 'All installed files except checksum manifest; META-INF stays ZIP-only',
        'native_binary_sha256': {p.name: sha(p) for p in binary_paths},
        'native_source_sha256': {name: sha(path) for name, path in source_files(root=ROOT)
                                 if name.startswith(('native/load-probe/', 'native/registration-compat/',
                                                     'native/service-control/'))},
    }
    (STAGE / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    installed = [(str(p.relative_to(STAGE)), p) for p in STAGE.rglob('*')
                 if p.is_file() and p.relative_to(STAGE).parts[0] != 'META-INF']
    (STAGE / 'payload.sha256').write_text(''.join(f'{sha(p)}  {name}\n' for name, p in sorted(installed)))
    output = ASSETS / 'dist' / OUTPUT
    output.parent.mkdir(exist_ok=True)
    archive(output, [(str(p.relative_to(STAGE)), p) for p in STAGE.rglob('*') if p.is_file()])
    source_zip = output.with_name(f'{MODULE_ID}-v{VERSION}-sources.zip')
    archive_sources(source_zip, root=ROOT)
    validate_retained_releases()
    for path in [output, source_zip]:
        digest = sha(path)
        path.with_suffix('.zip.sha256').write_text(f'{digest}  {path.name}\n')
        print(f'{path.relative_to(ROOT)} ({path.stat().st_size:,} bytes) SHA256={digest}')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default = os.environ.get('ANDROID_NDK_HOME', str(ASSETS / 'tools/android-ndk-r29'))
    parser.add_argument('--ndk', type=Path, default=Path(default))
    args = parser.parse_args()
    build(args.ndk.resolve())


if __name__ == '__main__':
    main()
