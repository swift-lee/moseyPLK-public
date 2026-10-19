"""Local APKM inspection; no Android code execution or phone operations."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from project_paths import ASSETS, ROOT
import test_gms_resolver as resolver

LEGACY_V016_SIGNER = '5f2391277b1dbd489000467e4c2fa6af802430080457dce2f618992e9dfb5402'
SDK = ASSETS / 'tools/client-compat/android-16'

def sha(p):
    with p.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error('Do not run with Python optimization; assertions are input checks')
    input_dir, out = args.input_dir.resolve(), args.output_dir.resolve()
    sources = sorted(input_dir.glob('*.apkm'))
    if not input_dir.is_dir() or not sources:
        parser.error('Input directory must contain APKM files')
    if not out.is_relative_to(ASSETS.resolve()) or out.exists():
        parser.error('Output must be a new directory inside ignored assets')
    out.mkdir(parents=True)
    runner_sha = sha(Path(__file__))
    tool_hashes = {str(p.relative_to(ASSETS)): sha(p) for p in (SDK/'aapt2', SDK/'lib/apksigner.jar', ASSETS/'tools/dexkit-research/tool-provenance.json')}
    before = resolver.source_hashes()
    cp, native = resolver.compile_host()
    rows = []
    for source in sources:
        outer_hash = sha(source)
        with zipfile.ZipFile(source) as bundle:
            assert bundle.testzip() is None, 'APKM CRC error'
            assert bundle.namelist().count('info.json') == 1 and bundle.namelist().count('base.apk') == 1, 'Ambiguous bundle entries'
            info = json.loads(bundle.read('info.json'))
            code = str(info['versioncode'])
            assert re.fullmatch(r'[1-9][0-9]{0,9}', code), 'Invalid versionCode path'
            case = out / code
            case.mkdir()
            base = case / 'base.apk'
            base.write_bytes(bundle.read('base.apk'))
            inventory = []
            for entry in bundle.infolist():
                if not entry.filename.endswith('.apk'):
                    continue
                data = bundle.read(entry)
                with zipfile.ZipFile(io.BytesIO(data)) as apk:
                    assert apk.testzip() is None, 'Inner APK CRC error'
                    dex = [n for n in apk.namelist() if re.fullmatch(r'classes(?:\d+)?\.dex', n)]
                    inventory.append({'file':entry.filename, 'bytes':len(data),
                        'sha256':hashlib.sha256(data).hexdigest(), 'dex':dex,
                        'abis':sorted(set(n.split('/')[1] for n in apk.namelist() if n.startswith('lib/') and len(n.split('/')) > 2))})
        signature = subprocess.run(['java', '--enable-native-access=ALL-UNNAMED', '-jar', str(SDK/'lib/apksigner.jar'),
            'verify', '--verbose', '--print-certs', '--min-sdk-version', '36', '--max-sdk-version', '36', str(base)], capture_output=True, text=True, timeout=60)
        (case/'signature.txt').write_text(signature.stdout + signature.stderr)
        certs = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)', signature.stdout)
        assert signature.returncode == 0 and len(certs) == 1, 'Base APK signature invalid'
        badging = subprocess.run([str(SDK/'aapt2'), 'dump', 'badging', str(base)], capture_output=True, text=True, check=True, timeout=30).stdout
        (case/'badging.txt').write_text(badging)
        package = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'",badging)
        assert package and package[1] == 'com.google.android.gms' and package[2] == str(info['versioncode']) and package[3] == info['release_version']
        start = time.monotonic()
        result = resolver.run_host(cp,native,base)
        elapsed = time.monotonic()-start
        (case/'resolver.stdout.txt').write_text(result.stdout)
        (case/'resolver.stderr.txt').write_text(result.stderr)
        row = {'source':str(source.relative_to(ASSETS)) if source.is_relative_to(ASSETS) else source.name, 'bundle_sha256':outer_hash, 'bundle_crc_ok':True,
            'base_sha256':sha(base), 'base_bytes':base.stat().st_size,
            'base_signature_valid':True,'base_signer_sha256':certs[0], 'legacy_v016_signer_match':certs == [LEGACY_V016_SIGNER], 'metadata':info,
            'manifest_package':package[1], 'manifest_version_code':package[2], 'manifest_version_name':package[3],
            'inventory':inventory, 'resolver_exit':result.returncode, 'resolver_stdout':result.stdout.strip(),
            'resolver_stderr':result.stderr.strip(), 'host_elapsed_seconds':round(elapsed,3)}
        if result.returncode == 0:
            audit = resolver.run_host(cp,native,base,case/'semantic-receipt.txt')
            assert audit.returncode == 0, audit.stderr
            row['audit_stdout'] = audit.stdout.strip()
        assert sha(source) == outer_hash
        rows.append(row)
        report = {'host_only':True,'target_code_executed':False,'device_tested':False,'run_complete':False,
            'source_hashes':before,'runner_sha256':runner_sha,'signatures_checked_api':36,
            'tool_sha256':tool_hashes,
            'signature_scope':'base APK only; splits checked for CRC/hash/DEX inventory, not signing',
            'runtime_identity_and_loader_executed':False,'cases':rows}
        (out/'results.json').write_text(json.dumps(report,indent=2)+'\n')
        print(package[3], 'exit='+str(result.returncode), result.stdout.strip() or result.stderr.splitlines()[0],flush=True)
    resolver.require_unchanged_sources(before)
    assert sha(Path(__file__)) == runner_sha
    report['run_complete'] = True
    (out/'results.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__ == '__main__':
    main()
