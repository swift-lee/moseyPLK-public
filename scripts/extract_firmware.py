#!/usr/bin/env python3
"""Prepare pinned build inputs locally; never contacts or modifies a phone."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import tempfile
import zipfile

from build_module import DONOR
from project_paths import ROOT, ASSETS

ARCHIVES = {
    'OxygenOS': '9cdf1bccf0f91a20a5560d6386665a261818132db1309789c20df1cd4e5084fe',
    'ColorOS': 'e031da58af93781971be4109c73579e3020a85510cf0fb26747bb20fbd8d61cf',
    'Fold6': '1a0c62cfb1e698e46315d2ad265c448edf85a8b516e34364579dda27d666b364',
}
COLOROS = {
    'system_ext/etc/selinux/mapping/202504.cil': '4aac5563b972fa8ccb020036189b4f1085ad75a08ea1ff0c86de54e5f2483918',
    'system_ext/etc/selinux/system_ext_seapp_contexts': '060a57848a4e09da791e1bae227e1ed71c5101f26a480a8f404c9de65a43945d',
    'system_ext/etc/selinux/system_ext_sepolicy.cil': 'c74ef3f2ce6a2cdd2f77de02193a90433b75cd14b7c94c62208864d99f902a3d',
    'system_ext/etc/sysconfig/hidden-api-whitelist-ext.xml': '7281f136608b8393fd7859f85173912c9e6b1037499642877eb7fdd0f0fcf0ae',
    'vendor/etc/selinux/vendor_file_contexts': '79b8e47f39c79af069c8493e17937ee2c8839d87be41ac75da070b685e9c1824',
    'vendor/etc/selinux/vendor_sepolicy.cil': '0dc24d8ef9d834d1978342152910070142c9b6a10b85465f491bacb77bbd4256',
    'vendor/etc/selinux/vendor_service_contexts': '9a5119f396e27e1235822e07e437d3379e12e549361d7f2c2751b679a89d0352',
}
FOLD6 = {
    'META-INF/com/google/android/update-binary': 'b4c882fffba5b85804f6212b1bdf9ca68437e5150dd3a50f869ef115f4af5380',
    'META-INF/com/google/android/updater-script': 'd2b8203193a083e43ad076fde01b9c7821e0aa521e1f8077b8628fb1cdb70c60',
    'common/functions.sh': '77c512a548310316ad0c6e16f9427c2209f313b779b0272fdc685af3a9a008e0',
    'common/install.sh': '62fb15a843343f146404097f929843f894ec950fe773489171f0b4406cd32f68',
    'common/addon/placeholder': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'system/vendor/etc/vintf/manifest/manifest_mosey.xml': 'db757b0669bcaa434d01f4c490a130dae79b8eaecbf1c2eb21f245beaacbf917',
    'system/vendor/etc/init/mosey.rc': '610bfff12609ab93d2eb7fdab84fccf24861e65d9e7b3a84629d24f77245f727',
    'system/vendor/bin/mosey_launcher': '1e9528a3ee0cebf52e8334c487f081a5c351a65c6283f8be8899e2c0801e870b',
    'system/system_ext/etc/permissions/privapp-permissions-com.google.android.mosey.xml': '1add90954c70167b5d6fcd3089031aba370c83cfa435bf5728ad1f75834a77dd',
    'system/system_ext/etc/default-permissions/default-permissions-com.google.android.mosey.xml': '04c1f4ade51c17f0f5ce88070673cdf30bf5e4ca698de6e5af730ab8af117ad7',
    'system/product/etc/vintf/compatibility_matrix.xml': 'cb2c2e628cee5a22c35e0f3e58ee44924ab3437b0302f2b5e15b176e214bc110',
    'module.prop': '43d9e07da67f2912c7e00174d517c0d3fa25038b5e5063024e5153afd8231b14',
    'donor.prop': '0b7160dc91fc697e9781d31590e7f8cf74afff517118ad0b2da8ce38570627b8',
    'customize.sh': '1e2283964995dc5f99991ff02c59cd20c2c48223505366416e67f6bc254b36a6',
    'service.sh': '8de7bc5f15f0c5215cc00df9ee6fc05e0c442d5fe674c0f345ca917cc468ab94',
    'action.sh': 'd22c2b975a5385b143de9840c2a55083115896660f93bcc9e266fbcc606ca3b4',
    'sepolicy.rule': 'd4614f42082ef3817ba4fd83cfd1973fa94c01943abccea5df78eb1971347ba1',
}


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def destination(relative):
    """Reject traversal and every existing symlink in the asset output path."""
    rel = PurePosixPath(relative)
    if rel.is_absolute() or '..' in rel.parts or not rel.parts:
        raise ValueError(f'Unsafe asset path: {relative}')
    path = ASSETS
    for part in ('', *rel.parts):
        if part:
            path /= part
        if path.is_symlink():
            raise ValueError(f'Refusing symlink in asset output: {path}')
    return path


def verify(path, expected):
    if not path.is_file() or path.is_symlink():
        raise ValueError(f'Required regular file missing: {path}')
    actual = digest(path)
    if actual != expected:
        raise ValueError(f'SHA256 mismatch (not overwritten): {path}\nexpected={expected}\nactual={actual}')


def missing_inputs(prefix, files):
    missing = []
    for relative, expected in files.items():
        path = destination(f'{prefix}/{relative}')
        if path.exists():
            verify(path, expected)
        else:
            missing.append(relative)
    print(f'{prefix}: {len(files) - len(missing)}/{len(files)} existing files verified', flush=True)
    return missing


def publish(source, relative):
    """Publish a complete verified file; hard-link creation cannot overwrite."""
    target = destination(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    source.chmod(0o755 if target.name.endswith('.sh') or target.name in
                 ('update-binary', 'mosey_launcher', 'mosey_server') else 0o644)
    os.link(source, target)


def manifest_partitions(archive):
    spec = importlib.util.spec_from_file_location('mosey_update_metadata', ROOT / 'research/scripts/update_metadata_pb2.py')
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except ModuleNotFoundError as error:
        raise ValueError('Payload parsing requires python3-protobuf; see docs/build.md') from error
    with zipfile.ZipFile(archive) as ota:
        if ota.namelist().count('payload.bin') != 1:
            raise ValueError('Expected exactly one payload.bin in OTA ZIP')
        with ota.open('payload.bin') as payload:
            header = payload.read(24)
            if len(header) != 24 or header[:4] != b'CrAU':
                raise ValueError('Invalid payload header')
            version, length, _ = struct.unpack('>QQI', header[4:])
            if version != 2 or not 0 < length <= 32 * 1024 * 1024:
                raise ValueError('Unsupported payload version or manifest length')
            data = payload.read(length)
            if len(data) != length:
                raise ValueError('Truncated payload manifest')
    manifest = module.DeltaArchiveManifest()
    manifest.ParseFromString(data)
    parts = {}
    for part in manifest.partitions:
        info = part.new_partition_info
        if part.partition_name in parts or not info.size or len(info.hash) != 32:
            raise ValueError('Invalid partition metadata')
        # These full OTA packages mark minor_version=9 / partial_update=true.
        # Source dependence must be determined from operations, not those flags.
        if part.partition_name in ('odm', 'system_ext', 'vendor'):
            if any(operation.type not in (0, 1, 6, 7, 8, 14) for operation in part.operations):
                raise ValueError(f'Source-dependent partition is unsupported: {part.partition_name}')
        parts[part.partition_name] = (info.size, info.hash.hex())
    return parts


def extract_ota(label, archive, files, missing, stage, dumper, jobs):
    parts = manifest_partitions(archive)
    required = sorted({name.split('/', 1)[0] for name in missing})
    images = {}
    absent = []
    for part in required:
        if part not in parts:
            raise ValueError(f'Partition {part} is missing from {label}')
        image = destination(f'research/images/{label}/{part}.img')
        images[part] = image
        if image.exists():
            if image.stat().st_size != parts[part][0]:
                raise ValueError(f'Existing image size mismatch (not overwritten): {image}')
            verify(image, parts[part][1])
        else:
            absent.append(part)
    if absent:
        if not dumper.is_file() or not os.access(dumper, os.X_OK):
            raise ValueError(f'payload-dumper-go missing or not executable: {dumper}')
        output = stage / 'images'
        output.mkdir()
        subprocess.run([str(dumper.resolve()), '-c', str(jobs), '-p', ','.join(absent),
                        '-o', str(output), str(archive.resolve())], check=True)
        for part in absent:
            image = output / f'{part}.img'
            if image.stat().st_size != parts[part][0]:
                raise ValueError(f'Extracted image size mismatch: {part}')
            verify(image, parts[part][1])
            publish(image, f'research/images/{label}/{part}.img')
    fsck = shutil.which('fsck.erofs')
    if not fsck:
        raise ValueError('fsck.erofs with --path support is required')
    for number, relative in enumerate(missing):
        part, inside = relative.split('/', 1)
        output = stage / f'file-{number}'
        subprocess.run([fsck, '--no-preserve', '--path=/' + inside,
                        '--extract=' + str(output), str(images[part])], check=True)
        verify(output, files[relative])
        publish(output, f'research/extracted/{label}/{relative}')
        print(f'Prepared {label}/{relative}', flush=True)


def extract_fold6(archive, missing, stage):
    with zipfile.ZipFile(archive) as source:
        for number, relative in enumerate(missing):
            if source.namelist().count(relative) != 1:
                raise ValueError(f'Missing or duplicate Fold6 entry: {relative}')
            info = source.getinfo(relative)
            if info.file_size > 1024 * 1024 or info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f'Unexpected Fold6 entry: {relative}')
            output = stage / f'fold6-{number}'
            output.write_bytes(source.read(info))
            verify(output, FOLD6[relative])
            publish(output, f'research/module/{relative}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oxygenos', type=Path, default=ASSETS / 'OxygenOS.zip')
    parser.add_argument('--fold6', type=Path, default=ASSETS / 'mosey-f9560-cn.zip')
    parser.add_argument('--coloros', nargs='?', type=Path, const=ASSETS / 'ColorOS.zip',
                        help='also prepare seven original ColorOS regression inputs')
    parser.add_argument('--dumper', type=Path, default=ASSETS / 'research/tools/payload-dumper-go')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--check-only', action='store_true', help='verify prepared files without writing or extracting')
    parser.add_argument('--verify-archives', action='store_true', help='also hash original ZIPs when all files already exist')
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error('--jobs must be between 1 and 32')
    inputs = [('OxygenOS', args.oxygenos, DONOR, 'research/extracted/OxygenOS'),
              ('Fold6', args.fold6, FOLD6, 'research/module')]
    if args.coloros:
        inputs.append(('ColorOS', args.coloros, COLOROS, 'research/extracted/ColorOS'))
    plans = [(label, archive, files, missing_inputs(prefix, files))
             for label, archive, files, prefix in inputs]
    if args.check_only and any(missing for _, _, _, missing in plans):
        raise ValueError('Prepared inputs are incomplete; run without --check-only to extract them')
    # Verify every required input archive before publishing any new file.
    for label, archive, _, missing in plans:
        if missing or args.verify_archives:
            print(f'Checking {label} ZIP SHA256 (may take a while)', flush=True)
            verify(archive, ARCHIVES[label])
    if args.check_only or not any(missing for _, _, _, missing in plans):
        print('All requested build inputs are already verified; no extraction needed.')
        return
    work = destination('build/firmware-extraction')
    work.mkdir(parents=True, exist_ok=True)
    for label, archive, files, missing in plans:
        if not missing:
            continue
        with tempfile.TemporaryDirectory(prefix=label + '-', dir=work) as temporary:
            stage = Path(temporary)
            if label == 'Fold6':
                extract_fold6(archive, missing, stage)
            else:
                extract_ota(label, archive, files, missing, stage, args.dumper, args.jobs)
    print('All requested build inputs prepared and verified.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error)) from error
