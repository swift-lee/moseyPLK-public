#!/usr/bin/env python3
"""The explicit, text-only publication set shared by every source archive."""
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

from project_paths import ROOT

MANIFEST = 'publication-files.json'
FORBIDDEN_PARTS = {
    '.git', '.aws', '.agents', '.codex', '.gradle', '.venv', '__pycache__',
    'moseyPLK-assets', 'reference-zfold6',
}
FORBIDDEN_SUFFIXES = {
    '.apk', '.apkm', '.apks', '.aab', '.aar', '.jar', '.dex', '.odex', '.vdex',
    '.so', '.ko', '.o', '.a', '.class', '.pyc', '.pyo', '.bin', '.img', '.elf',
    '.zip', '.gz', '.xz', '.bz2', '.zst', '.7z', '.tar', '.db', '.sqlite',
    '.sqlite3', '.log', '.pem', '.key', '.jks', '.keystore', '.p12', '.pfx',
}
FORBIDDEN_NAMES = {
    'password.txt', 'local.properties', '.env',
    'module-src/service.sh', 'module-src/sepolicy.rule', 'module-src/compatibility.sh',
    'scripts/read_device_compat.py', 'scripts/diagnose_mosey_readonly.py',
    'scripts/collect-plk110-compat.sh',
    'scripts/test_module.py', 'scripts/test_startup.py',
}
SECRET_PATTERNS = (
    re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
    re.compile(r'https?://[^\s/@:]+:[^\s/@]+@'),
)


def validate_name(name):
    """Reject traversal, non-canonical paths, assets and private/local files."""
    if (not isinstance(name, str) or not name or '\\' in name or ':' in name
            or any(ord(char) < 32 for char in name)):
        raise ValueError('Invalid publication path')
    path = PurePosixPath(name)
    if path.is_absolute() or str(path) != name or any(p in ('.', '..') for p in path.parts):
        raise ValueError('Non-canonical publication path: ' + name)
    if (set(path.parts) & FORBIDDEN_PARTS or path.suffix.lower() in FORBIDDEN_SUFFIXES
            or name in FORBIDDEN_NAMES or path.name in FORBIDDEN_NAMES
            or path.name.startswith('.env.') or name.startswith('research/device/')
            or name.startswith('research/comparison/')):
        raise ValueError('Restricted publication path: ' + name)
    return path


def validate_text(data, name):
    if b'\0' in data:
        raise ValueError('Binary data in publication file: ' + name)
    try:
        value = data.decode('utf-8')
    except UnicodeDecodeError as error:
        raise ValueError('Non-UTF-8 publication file: ' + name) from error
    if any(pattern.search(value) for pattern in SECRET_PATTERNS):
        raise ValueError('Potential credential in publication file: ' + name)
    return value


def _regular_file(root, name):
    path = root
    for part in validate_name(name).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('Symlink in publication path: ' + name)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('Publication entry is not a regular file: ' + name)
    validate_text(path.read_bytes(), name)
    return path


def source_files(root=ROOT):
    """Return sorted (relative path, Path) pairs; do not depend on a Git index."""
    root = Path(root).resolve()
    manifest = _regular_file(root, MANIFEST)
    data = json.loads(manifest.read_text(encoding='utf-8'))
    names = data.get('files')
    if data.get('schema') != 1 or not isinstance(names, list) or not names:
        raise ValueError('Unsupported or empty publication manifest')
    if any(not isinstance(name, str) for name in names):
        raise ValueError('Publication file names must be strings')
    if names != sorted(set(names)) or MANIFEST not in names:
        raise ValueError('Publication file list must be sorted, unique and include itself')
    return [(name, _regular_file(root, name)) for name in names]


def archive_sources(path, root=ROOT):
    """Archive only reviewed text files; never add staging, donor or local inputs."""
    files = source_files(root)
    path = Path(path)
    if path.resolve() in {file.resolve() for _, file in files}:
        raise ValueError('Source archive would overwrite a publication file')
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, source in files:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.create_system = 3
            archive.writestr(info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=9)
    return path
