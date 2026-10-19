"""Pinned Android DexKit inputs and APK layout checks; no network or device access."""
import hashlib
import json
from pathlib import Path
import struct
import zipfile

DEXKIT_VERSION = '2.2.0'
PAGE_SIZE = 16384
NATIVE_ENTRY = 'lib/arm64-v8a/libdexkit.so'
NATIVE_SHA256 = '673b3c809259316fc01b5288dca886ffba3463c9e86984e761aad6aba7673aea'
TEST_MARKER = 'assets/mosey-adaptive-test'
TEST_MARKER_BYTES = b'force_adaptive_v1\n'
MAVEN = 'https://repo.maven.apache.org/maven2/'
INPUTS = {
    'dexkit-2.2.0.aar': {
        'sha256': 'cf4488da9f721750ce5ff4311e88356cbfcb1d4444c2b519b12d8bdb5f33f2c6',
        'url': MAVEN + 'org/luckypray/dexkit/2.2.0/dexkit-2.2.0.aar',
        'license': 'Apache-2.0 Java wrapper; LGPL-3.0-or-later native Core/JNI'},
    'lib/dexkit-2.2.0.jar': {
        'sha256': '195979d9576ba6d68a1c60bdd3e38cd3aed068d4e0c5c6c99caa50bc25fcb9f1',
        'source': 'dexkit-2.2.0.aar:classes.jar', 'license': 'Apache-2.0'},
    'lib/flatbuffers-java-23.5.26.jar': {
        'sha256': '8d10cac2ea9878896077ba437d76fdb1b9a07f55a863c560bb8a024b04103f8b',
        'url': MAVEN + 'com/google/flatbuffers/flatbuffers-java/23.5.26/flatbuffers-java-23.5.26.jar',
        'license': 'Apache-2.0'},
    'lib/kotlin-stdlib-1.5.0.jar': {
        'sha256': '52283996fe4067cd7330288b96ae67ecd463614dc741172c54d9d349ab6a9cd7',
        'url': MAVEN + 'org/jetbrains/kotlin/kotlin-stdlib/1.5.0/kotlin-stdlib-1.5.0.jar',
        'license': 'Apache-2.0'},
    'lib/annotations-13.0.jar': {
        'sha256': 'ace2a10dc8e2d5fd34925ecac03e4988b2c0f851650c94b8cef49ba1bd111478',
        'url': MAVEN + 'org/jetbrains/annotations/13.0/annotations-13.0.jar',
        'license': 'Apache-2.0'},
    'source/DexKit-2.2.0/LICENSE': {
        'sha256': '43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1',
        'url': 'https://github.com/LuckyPray/DexKit/blob/2.2.0/LICENSE'},
    'source/DexKit-2.2.0/Core/LICENSE': {
        'sha256': 'ccf8a822bf4d4cbec96787bcf810b9d150afe858a2d407111df23d8f0fa2b65c',
        'url': 'https://github.com/LuckyPray/DexKit/blob/2.2.0/Core/LICENSE'},
}
RUNTIME_JARS = tuple(name for name in INPUTS if name.endswith('.jar'))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_native_elf(data, *, expected_needed=None):
    """Require an Android AArch64 shared object with 16 KiB-compatible LOADs."""
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('Expected a little-endian ELF64 native library')
    if struct.unpack_from('<HH', data, 16) != (3, 183):
        raise ValueError('Expected an AArch64 shared object')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', data, 54)
    if phsize != 56 or not phnum or phoff + phsize * phnum > len(data):
        raise ValueError('Invalid ELF program header table')
    loads, dynamic = [], None
    for i in range(phnum):
        kind, _, offset, vaddr, _, size, memsize, align = struct.unpack_from(
            '<II6Q', data, phoff + i * phsize)
        if offset + size > len(data) or size > memsize:
            raise ValueError('ELF segment exceeds its file/memory bounds')
        if kind == 1:
            if align < PAGE_SIZE or align & (align - 1) or offset % PAGE_SIZE != vaddr % PAGE_SIZE:
                raise ValueError('ELF LOAD is not 16 KiB compatible')
            loads.append((offset, vaddr, size, align))
        elif kind == 2:
            dynamic = (offset, size)
    if not loads or dynamic is None:
        raise ValueError('Missing ELF LOAD/dynamic segments')
    tags = []
    offset, size = dynamic
    for at in range(offset, offset + size - 15, 16):
        tag, value = struct.unpack_from('<qQ', data, at)
        if tag == 0:
            break
        tags.append((tag, value))
    else:
        raise ValueError('Unterminated ELF dynamic table')
    strings = dict(tags)
    if 5 not in strings or 10 not in strings:
        raise ValueError('Missing ELF dynamic string table')
    address, length = strings[5], strings[10]
    table = None
    for fileoff, virtual, filesz, _ in loads:
        if virtual <= address and address + length <= virtual + filesz:
            start = fileoff + address - virtual
            table = data[start:start + length]
            break
    if table is None:
        raise ValueError('ELF string table is outside LOAD segments')
    needed = []
    for tag, value in tags:
        if tag == 1:
            if value >= len(table) or b'\0' not in table[value:]:
                raise ValueError('Invalid ELF dependency name')
            needed.append(table[value:table.index(b'\0', value)].decode('ascii'))
    expected = (set(expected_needed) if expected_needed is not None else
                {'libz.so', 'liblog.so', 'libm.so', 'libdl.so', 'libc.so'})
    if set(needed) != expected or len(needed) != len(expected):
        raise ValueError('Unexpected Android native dependencies')
    return {'abi': 'arm64-v8a', 'machine': 'AArch64', 'needed': needed,
            'load_alignment_bytes': [item[3] for item in loads]}


def verified_dependencies(directory):
    """Validate all inputs before staging; return D8 jars, native bytes and provenance."""
    directory = Path(directory)
    for name, info in INPUTS.items():
        path = directory / name
        if not path.is_file() or digest(path.read_bytes()) != info['sha256']:
            raise ValueError('Missing or unexpected DexKit dependency: ' + name)
    with zipfile.ZipFile(directory / 'dexkit-2.2.0.aar') as aar:
        if aar.read('classes.jar') != (directory / 'lib/dexkit-2.2.0.jar').read_bytes():
            raise ValueError('DexKit classes.jar differs from the fixed AAR')
        native = aar.read('jni/arm64-v8a/libdexkit.so')
    if digest(native) != NATIVE_SHA256:
        raise ValueError('DexKit Android library differs from the fixed AAR')
    elf = validate_native_elf(native)
    metadata = {'version': DEXKIT_VERSION, 'inputs': INPUTS, 'java_program_inputs': RUNTIME_JARS,
                'native': {'entry': NATIVE_ENTRY, 'sha256': NATIVE_SHA256, **elf},
                'source': 'https://github.com/LuckyPray/DexKit/tree/2.2.0',
                'source_modified': False, 'core_library_desugaring': False,
                'cxx': 'Published AAR has no shared C++ runtime dependency; no extra libc++_shared.so',
                'kotlin_stdlib_common': 'Metadata-only JAR; no JVM classes to pass to D8',
                'authentication': 'Fixed local SHA256; not detached upstream signature verification'}
    return [directory / name for name in RUNTIME_JARS], native, metadata


def dependency_assets(directory, metadata):
    return [('assets/mosey-dependencies.json', (json.dumps(metadata, indent=2) + '\n').encode()),
            ('assets/third-party/Apache-2.0.txt',
             (directory / 'source/DexKit-2.2.0/LICENSE').read_bytes()),
            ('assets/third-party/DexKit-Core-LGPL-3.0.txt',
             (directory / 'source/DexKit-2.2.0/Core/LICENSE').read_bytes())]


def validate_variant_marker(path, adaptive_test):
    with zipfile.ZipFile(path) as apk:
        count = apk.namelist().count(TEST_MARKER)
        if adaptive_test:
            if count != 1 or apk.read(TEST_MARKER) != TEST_MARKER_BYTES:
                raise ValueError('Adaptive-test APK requires its exact force_adaptive_v1 marker')
        elif count:
            raise ValueError('Release APK must not contain the adaptive-test marker')


def validate_native_layout(path, additional=None):
    """Default remains DexKit-only; the UI build explicitly pins extra JNI inputs."""
    additional = additional or {}
    with zipfile.ZipFile(path) as apk:
        libraries = [name for name in apk.namelist() if name.startswith('lib/')]
        if sorted(libraries) != sorted([NATIVE_ENTRY, *additional]):
            raise ValueError('APK must contain exactly the reviewed arm64 DexKit library')
        info = apk.getinfo(NATIVE_ENTRY)
        native = apk.read(info)
    with Path(path).open('rb') as stream:
        stream.seek(info.header_offset)
        header = stream.read(30)
        if len(header) != 30 or header[:4] != b'PK\x03\x04':
            raise ValueError('Invalid native-library ZIP local header')
        method = struct.unpack_from('<H', header, 8)[0]
        name_length, extra_length = struct.unpack_from('<HH', header, 26)
        if stream.read(name_length) != NATIVE_ENTRY.encode():
            raise ValueError('Native-library local and central ZIP names differ')
        offset = info.header_offset + 30 + name_length + extra_length
        if method != zipfile.ZIP_STORED or info.compress_type != zipfile.ZIP_STORED:
            raise ValueError('Native library must be uncompressed')
        if offset % PAGE_SIZE:
            raise ValueError('Native library must have 16 KiB ZIP alignment')
        stream.seek(offset)
        if stream.read(info.file_size) != native or digest(native) != NATIVE_SHA256:
            raise ValueError('APK native library differs from the fixed Android artifact')
    result = {'compression_method': method, 'data_offset': offset, 'alignment_bytes': PAGE_SIZE,
              'sha256': NATIVE_SHA256, **validate_native_elf(native)}
    if additional:
        layouts = {}
        with zipfile.ZipFile(path) as apk, Path(path).open('rb') as stream:
            for name, expected in additional.items():
                if not name.startswith('lib/arm64-v8a/') or not name.endswith('.so'):
                    raise ValueError('Only reviewed arm64 UI libraries may be added')
                info = apk.getinfo(name)
                data = apk.read(info)
                stream.seek(info.header_offset)
                header = stream.read(30)
                if header[:4] != b'PK\x03\x04':
                    raise ValueError('Invalid UI native-library ZIP header')
                method = struct.unpack_from('<H', header, 8)[0]
                namesize, extrasize = struct.unpack_from('<HH', header, 26)
                if stream.read(namesize) != name.encode():
                    raise ValueError('UI native-library ZIP names differ')
                offset = info.header_offset + 30 + namesize + extrasize
                if method != 0 or info.compress_type != 0 or offset % PAGE_SIZE:
                    raise ValueError('UI native library must be stored with 16 KiB ZIP alignment')
                if digest(data) != expected['sha256']:
                    raise ValueError('UI native library differs from its pinned artifact')
                stream.seek(offset)
                if stream.read(info.file_size) != data:
                    raise ValueError('UI native library local bytes differ')
                layouts[name] = {'sha256': digest(data), 'data_offset': offset,
                                 **validate_native_elf(data, expected_needed=expected['needed'])}
        result['additional_libraries'] = layouts
    return result
