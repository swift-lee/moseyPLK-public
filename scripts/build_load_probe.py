#!/usr/bin/env python3
"""Build an opt-in, probe-only variant; never communicates with a device."""
import argparse
import json
import os
from pathlib import Path
from project_paths import ASSETS
import shutil
import stat
import subprocess
import zipfile

from build_module import (DONOR, LAUNCHER, LAUNCHER_SHA, ROOT, SEPOLICY_SHA, sha,
                          copy_public_tree, stage_module_inputs, validate_module_inputs)
from public_sources import archive_sources, source_files

VERSION = '0.4.2.1'
VERSION_CODE = 10
OUTPUT = f'mosey-plk110-cn-v{VERSION}-load-probe.zip'
PROBE = 'system/odm/bin/mosey_load_probe'
LIBRARY = 'system/odm/lib64/libmosey_load_probe.so'
BUILD = ASSETS / 'build/load-probe'
STAGE = BUILD / 'module'


def archive(path, files):
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, p in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(2026, 9, 14, 0, 0, 0))
            executable = p.suffix == '.sh' or p.name in {
                'mosey_load_probe', 'mosey_launcher', 'mosey_server', 'mosey_service_control', 'update-binary'}
            info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
            info.create_system = 3
            z.writestr(info, p.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def build(ndk):
    inputs = validate_module_inputs()
    clang = ndk / 'toolchains/llvm/prebuilt/linux-x86_64/bin/clang'
    readelf = clang.with_name('llvm-readelf')
    for tool in [clang, readelf]:
        if not tool.is_file():
            raise SystemExit(f'Missing NDK tool: {tool}; pass --ndk or ANDROID_NDK_HOME')
    native = BUILD / 'native'
    native.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'native/load-probe'
    flags = ['--target=aarch64-linux-android35', '-std=c11', '-Oz', '-Wall', '-Wextra',
             '-Werror', '-Wconversion', '-Wshadow', '-Wpedantic',
             '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
             '-fvisibility=hidden', '-mbranch-protection=standard',
             '-Wl,-z,relro,-z,now,-z,noexecstack', '-Wl,--build-id=sha1',
             f'-ffile-prefix-map={ROOT}=.', '-Wl,-z,max-page-size=16384']
    commands = [
        [str(clang), *flags, '-fPIE', '-pie', str(source / 'probe.c'),
         str(source / 'probe_parse.c'), '-ldl', '-o', str(native / 'mosey_load_probe')],
        [str(clang), *flags, '-fPIC', '-shared', str(source / 'marker.c'),
         '-Wl,-soname,libmosey_load_probe.so', '-o', str(native / 'libmosey_load_probe.so')],
    ]
    for command in commands:
        subprocess.run(command, check=True)
    metadata = {'ndk': (ndk / 'source.properties').read_text(),
                'clang': subprocess.check_output([str(clang), '--version'], text=True),
                'commands': [[arg.replace(str(ndk), '${NDK}').replace(str(ROOT), '${REPO}')
                              for arg in command] for command in commands]}
    binaries = [native / Path(relative).name for relative in (PROBE, LIBRARY)]
    for file in binaries:
        data = file.read_bytes()
        assert data[:6] == b'\x7fELF\x02\x01' and int.from_bytes(data[18:20], 'little') == 183
        details = subprocess.check_output([str(readelf), '-h', '-l', '-d', '-n', str(file)], text=True)
        assert 'libbinder' not in details and 'libc++' not in details
        (BUILD / (file.name + '.readelf.txt')).write_text(details)
    (BUILD / 'toolchain.json').write_text(json.dumps(metadata, indent=2) + '\n')

    # Isolated staging: the normal v0.4.1 package and build/module are untouched.
    if STAGE.exists():
        shutil.rmtree(STAGE)
    copy_public_tree('module-src', STAGE)
    (STAGE / 'customize.sh').rename(STAGE / 'customize-base.sh')
    copy_public_tree('experiments/load-probe/module', STAGE)
    stage_module_inputs(STAGE, inputs)
    for rel in [PROBE, LIBRARY]:
        shutil.copyfile(native / Path(rel).name, STAGE / rel)
    shutil.copyfile(ROOT / 'research/scripts/collect-device.sh', STAGE / 'collect-device.sh')
    (STAGE / 'module.prop').write_text(
        'id=mosey-plk110-cn\nname=OnePlus 15 Mosey Load Probe (experiment)\n'
        f'version=v{VERSION}-load-probe\nversionCode={VERSION_CODE}\n'
        'author=PLK110 adaptation; original Z Fold6 launcher\n'
        'description=Probe-only experiment: verify identity and LD_PRELOAD after external mounts. '
        'Does not start Mosey or change Binder registration. Action repeats the probe.\n')
    shutil.copyfile(ROOT / 'experiments/load-probe/README.md', STAGE / 'README.md')
    provenance = {
        'version': VERSION, 'experiment': 'load-probe-only', 'starts_donor': False,
        'original_files': DONOR, 'launcher_sha256': LAUNCHER_SHA,
        'launcher_byte_identical': True, 'donor_changes': False,
        'sepolicy_sha256': SEPOLICY_SHA, 'policy_changes_from_v041': False,
        'extra_mounts': [PROBE, LIBRARY], 'mounting': 'external provider only',
        'binder_operations': False, 'compatibility_layer': False,
        'device_installation_tested': False, 'device_transfer_tested': False,
        'payload_checksum_scope': 'All installed module files; excludes META-INF installer metadata and the checksum manifest itself',
        'input_distribution': 'Restricted local inputs are not included in public sources.',
        'generated_compatibility_sha256': sha(inputs['compatibility.sh']),
        'native_source_sha256': {name: sha(path) for name, path in source_files(root=ROOT)
                                 if name.startswith('native/load-probe/')},
        'native_binary_sha256': {p.name: sha(p) for p in binaries},
    }
    (STAGE / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    # Metainstall excludes META-INF from MODPATH. Keep those entry points in
    # the ZIP, but check only files extracted into the installed module.
    files = [(str(p.relative_to(STAGE)), p) for p in STAGE.rglob('*')
             if p.is_file() and p.relative_to(STAGE).parts[0] != 'META-INF']
    (STAGE / 'payload.sha256').write_text(''.join(f'{sha(p)}  {name}\n' for name, p in sorted(files)))
    output = ASSETS / 'dist' / OUTPUT
    output.parent.mkdir(exist_ok=True)
    archive(output, [(str(p.relative_to(STAGE)), p) for p in STAGE.rglob('*') if p.is_file()])
    source_zip = output.with_name(f'mosey-plk110-cn-v{VERSION}-load-probe-sources.zip')
    archive_sources(source_zip, root=ROOT)
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
