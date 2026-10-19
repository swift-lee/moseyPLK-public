#!/usr/bin/env python3
"""Run pinned, host-only DexKit candidate discovery; never downloads or uses ADB."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from project_paths import ASSETS, BUILD_ROOT, ROOT

TOOLS = ASSETS / 'tools/dexkit-research'
SOURCE = ROOT / 'research/dexkit-probe/GmsDexProbe.java'
CLASSES = BUILD_ROOT / 'dexkit-probe/classes'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verified_tools():
    """Check existing runtime artifacts against the local preparation manifest."""
    manifest = json.loads((TOOLS / 'tool-provenance.json').read_text())
    if manifest['version'] != '2.2.0':
        raise ValueError('This probe expects the reviewed DexKit 2.2.0 preparation')
    entries = [manifest['extracted_jar'], manifest['linux_native']]
    entries += [item for item in manifest['downloads'] if item['file'].endswith('.jar')
                and item['file'].startswith('lib/')]
    jars = sorted((TOOLS / 'lib').glob('*.jar'))
    native = TOOLS / 'native-build/libdexkit.so'
    expected = {item['file']: item['sha256'] for item in entries}
    actual = {str(path.relative_to(TOOLS)): sha(path) for path in [native, *jars]}
    if len(jars) != 5 or actual != expected:
        raise ValueError('Runtime files differ from the local preparation manifest')
    # The manifest records download/checksum limits; this is local consistency,
    # not independent signature authentication of upstream artifacts.
    return jars, native


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', required=True, type=Path, help='APK or ZIP of DEX, only parsed as data')
    parser.add_argument('--output', required=True, type=Path, help='New JSON inside ignored assets')
    parser.add_argument('--timeout', default=180, type=int)
    parser.add_argument('--compile', action='store_true', help='Compile host probe before running')
    args = parser.parse_args()
    apk, output = args.apk.resolve(), args.output.resolve()
    if not apk.is_file() or not output.is_relative_to(ASSETS.resolve()) or output.exists():
        parser.error('Require existing input and a new output path inside ignored assets')
    if not 1 <= args.timeout <= 600:
        parser.error('Timeout must be 1..600 seconds')
    try:
        jars, native = verified_tools()
    except (OSError, ValueError, KeyError) as error:
        parser.error(f'DexKit research tools unavailable or changed: {error}')
    classpath = os.pathsep.join(map(str, jars))
    if args.compile:
        CLASSES.mkdir(parents=True, exist_ok=True)
        # javac's module entry does not expand classpath globs on this host.
        # Ignore third-party classfile annotation metadata and Java 25 JNI
        # restricted-method warnings, retaining warnings-as-errors for our code.
        subprocess.run(['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main',
                        '-Xlint:all,-classfile,-restricted', '-Werror', '-cp', classpath,
                        '-d', str(CLASSES), str(SOURCE)], check=True, timeout=60)
        (CLASSES / 'source.sha256').write_text(sha(SOURCE) + '\n')
    stamp = CLASSES / 'source.sha256'
    if not stamp.is_file() or stamp.read_text().strip() != sha(SOURCE):
        parser.error('Compile this exact source first with --compile')
    argv = ['java', '--enable-native-access=ALL-UNNAMED', '-Xmx2g', '-cp',
            str(CLASSES) + os.pathsep + classpath, 'GmsDexProbe', str(native), str(apk)]
    before = sha(apk)
    start = time.perf_counter()
    process = subprocess.run(argv, capture_output=True, text=True, timeout=args.timeout)
    elapsed = time.perf_counter() - start
    output.parent.mkdir(parents=True, exist_ok=True)
    output.with_suffix('.stderr.txt').write_text(process.stderr)
    if process.returncode:
        output.with_suffix('.stdout.txt').write_text(process.stdout)
        raise SystemExit(f'Probe failed: exit={process.returncode}; logs saved alongside requested output')
    report = json.loads(process.stdout)
    if before != sha(apk):
        raise SystemExit('Input changed during read-only analysis')
    report['input'] = {'path': os.path.relpath(apk, ASSETS), 'sha256': before,
                       'bytes': apk.stat().st_size}
    report['host'] = {'elapsed_seconds': elapsed, 'java_max_heap': '2g',
                      'query_threads': 4, 'device_tested': False, 'phone_operations': []}
    report['source_sha256'] = sha(SOURCE)
    report['runner_sha256'] = sha(Path(__file__))
    report['tool_manifest_sha256'] = sha(TOOLS / 'tool-provenance.json')
    report['tool_sha256'] = {str(p.relative_to(TOOLS)): sha(p) for p in [native, *jars]}
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'report': str(output.relative_to(ROOT)), 'elapsed_seconds': round(elapsed, 3),
                      'keys': {k['key']: k['literal_match_count'] for k in report['keys']}}))


if __name__ == '__main__':
    main()
