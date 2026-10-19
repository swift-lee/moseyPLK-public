#!/usr/bin/env python3
"""Compile and exercise the production resolver against DEX data on the host."""
import argparse
import json
import hashlib
import re
import struct
import zipfile
import zlib
import os
from pathlib import Path
import subprocess
import sys

from project_paths import ASSETS, BUILD_ROOT, ROOT

sys.path.insert(0, str(ROOT / 'research/dexkit-probe'))
from run_probe import verified_tools

CLASSES = BUILD_ROOT / 'gms-resolver-v017/classes'
PACKAGE = 'moseyPLK.client'
SOURCES = ROOT / 'client-compat/src/main/java/moseyPLK/client'
APKS = {
    'old': ASSETS / 'research/device/gms-apk-26.33.32-20260914/base.apk',
    'new': ASSETS / 'research/device/discovery-20260920-230533/gms-base.apk',
    'latest': ASSETS / 'research/device/gms-263633035-20260926-180727/gms-base-verified.apk',
    'download_263161029': ASSETS / 'research/gms-download-analysis-20260927/verified-run/263161029/base.apk',
    'download_263367035': ASSETS / 'research/gms-download-analysis-20260927/verified-run/263367035/base.apk',
    'download_263465022': ASSETS / 'research/gms-download-analysis-20260927/verified-run/263465022/base.apk',
    'download_263633004': ASSETS / 'research/gms-download-analysis-20260927/verified-run/263633004/base.apk',
}

REVIEWED_APK_SHA256 = {
    'old': 'bea5f2d75fb0dc65ede26d85cc897329bb233ad2436570c5d7b8b52aebab06b6',
    'new': '95952e63995da8af843a1ab928550a8188046bb57e1918a1e60b9de1ed480f8d',
    'latest': '5767c040931821837bc7d6186b37f02afa2ab0fba7137ab7ea4efcb41f3a5c07',
    'download_263161029': 'de27052354aea2bc33c0996f699c4ceff18f23fe58de2f6c63b7b3c9719cf0f6',
    'download_263367035': '470d1ec0ecdf1aab5f960dbc4acf867366efe629494ea11f7274bcc07db631f3',
    'download_263465022': '1a0a9f65d6e5b881f179f3c4440a103f2267aee352ddffa9039a17cb638a8528',
    'download_263633004': '6ca5dbb09c75319312fabfa1790396fb4135c419a99c3f227a9a9fdd999e32df',
}


def compile_host():
    jars, native = verified_tools()
    classpath = os.pathsep.join(map(str, jars))
    CLASSES.mkdir(parents=True, exist_ok=True)
    sources = [SOURCES / (name + '.java') for name in ('ResolvedGateSet', 'GmsDexFile',
               'GmsSupplierVerifier', 'GmsAdaptiveResolver', 'GmsGateVerifier')]
    sources += sorted(SOURCES.glob('Gms*Proof.java'))
    sources += sorted(SOURCES.glob('GmsResolutionFailure.java'))
    sources += sorted((ROOT / 'client-compat/resolver-tests').rglob('*.java'))
    subprocess.run(['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main',
                    '-Xlint:all,-classfile,-restricted', '-Werror', '-cp', classpath,
                    '-d', str(CLASSES), *map(str, sources)], check=True, timeout=60)
    return str(CLASSES) + os.pathsep + classpath, native


def run_host(classpath, native, apk, audit=None):
    args = ['java', '--enable-native-access=ALL-UNNAMED', '-Xmx128m', '-cp', classpath,
            PACKAGE + '.GmsAdaptiveResolverHarness', str(native), str(apk)]
    if audit:
        args.append(str(audit))
    return subprocess.run(args, text=True, capture_output=True, timeout=120)


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def source_hashes():
    files = [SOURCES / (name + '.java') for name in ('ResolvedGateSet', 'GmsDexFile',
             'GmsSupplierVerifier', 'GmsAdaptiveResolver', 'GmsGateVerifier')]
    files += sorted(SOURCES.glob('Gms*Proof.java'))
    files += sorted(SOURCES.glob('GmsResolutionFailure.java'))
    files += sorted((ROOT / 'client-compat/resolver-tests').rglob('*.java'))
    files += sorted((ROOT / 'client-compat/resolver-tests/fixtures').iterdir())
    files += [Path(__file__).resolve(), ROOT / 'scripts/gms_resolver_fixtures.py']
    return {str(path.relative_to(ROOT)): sha256(path) for path in files}


def require_unchanged_sources(before):
    if source_hashes() != before:
        raise RuntimeError('Resolver or fixture sources changed during verification; rerun against the final sources')


def synthetic_variant(apk, destination, renames, *, supplier_register_swap=False, invert_branch=False, rename_gate_method=False):
    """Host-only DEX byte fixtures; these ZIPs are not signed/installable APKs.

    Equal-length string replacement deliberately avoids an APK reassembler. It
    exercises the data resolver; it does not certify Android DEX verifier input.
    """
    from loguru import logger
    logger.remove()
    from androguard.core.dex import DEX
    with zipfile.ZipFile(apk) as source, zipfile.ZipFile(destination, 'w') as target:
        for info in source.infolist():
            if not re.fullmatch(r'classes(?:[2-9][0-9]*|1[0-9]+)?\.dex', info.filename):
                continue
            data = bytearray(source.read(info))
            if info.filename == 'classes.dex' and (supplier_register_swap or invert_branch):
                parsed = DEX(bytes(data))
                method = next(m for m in parsed.get_class('Lecyv;').get_methods() if m.get_name() == 'ln')
                start = method.get_code_off() + 16
                for offset, instruction in method.get_instructions_idx():
                    op = data[start + offset]
                    if invert_branch and instruction.get_name() == 'if-nez':
                        data[start + offset] = 0x38  # if-eqz: a different truth table
                    if supplier_register_swap:
                        swap = lambda register: {0: 1, 1: 0}.get(register, register)
                        if op in (0x60, 0x62, 0x0a, 0x0c, 0x11, 0x38, 0x39):
                            data[start + offset + 1] = swap(data[start + offset + 1])
                        elif op == 0x12:
                            value = data[start + offset + 1]
                            data[start + offset + 1] = (value & 0xf0) | swap(value & 15)
                        elif op in (0x6e, 0x71, 0x72):
                            # These reviewed supplier calls have exactly one register.
                            assert data[start + offset + 1] >> 4 == 1
                            value = data[start + offset + 4]
                            data[start + offset + 4] = (value & 0xf0) | swap(value & 15)
                        elif op != 0x28:
                            raise AssertionError('unexpected supplier opcode in mutation fixture')
                del method, parsed
            if rename_gate_method:
                count, ids = struct.unpack_from('<II', data, 56)
                strings = []
                for index in range(count):
                    position = struct.unpack_from('<I', data, ids + index * 4)[0]
                    while data[position] & 128:
                        position += 1
                    position += 1
                    end = data.index(0, position)
                    strings.append(bytes(data[position:end]).decode('utf-8', errors='replace'))
                new_name = strings.index('toString')
                type_count, type_offset = struct.unpack_from('<II', data, 64)
                types = [strings[struct.unpack_from('<I', data, type_offset + index * 4)[0]] for index in range(type_count)]
                method_count, method_offset = struct.unpack_from('<II', data, 88)
                for index in range(method_count):
                    position = method_offset + index * 8
                    class_index, _, name_index = struct.unpack_from('<HHI', data, position)
                    if types[class_index] in ('Ljtmb;', 'Ljtma;') and strings[name_index] == 'W':
                        struct.pack_into('<I', data, position + 4, new_name)
            for before, after in renames.items():
                assert len(before) == len(after)
                data = data.replace(before.encode() + b'\0', after.encode() + b'\0')
            data[12:32] = hashlib.sha1(data[32:]).digest()
            struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
            name = {'classes.dex': 'classes3.dex', 'classes3.dex': 'classes.dex'}.get(info.filename, info.filename)
            target.writestr(name, data)


def expect(classpath, native, apk, accepted, label, records, expected_reason=None, expected_expression=None, expected_stage=None):
    result = run_host(classpath, native, apk)
    if accepted:
        if result.returncode or not result.stdout.startswith('VERIFIED '):
            raise AssertionError(label + ': ' + result.stdout + result.stderr)
        if 'scope=phenotype' not in result.stdout or 'supplier=null secondary=null' not in result.stdout:
            raise AssertionError(label + ': resolver did not return the single Phenotype getter contract')
    elif result.returncode == 0 or 'GmsAdaptiveResolver$Rejected:' not in result.stderr:
        raise AssertionError('expected checked rejection for ' + label + ': ' + result.stdout + result.stderr)
    if accepted and expected_expression is not None:
        actual_expression = result.stdout.split('expression=', 1)[1].split(' ', 1)[0]
        if actual_expression != expected_expression:
            raise AssertionError(label + ': expected expression ' + expected_expression + ', got ' + actual_expression)
    reason = result.stdout.strip() if accepted else next(line.strip() for line in result.stderr.splitlines() if 'GmsAdaptiveResolver$Rejected:' in line)
    if expected_reason is not None:
        rejection = reason.split('GmsAdaptiveResolver$Rejected:', 1)[1].strip()
        actual_stage, separator, actual_reason = rejection.partition(':')
        if not separator:
            raise AssertionError(label + ': rejection lacks a stage: ' + rejection)
        if expected_stage is not None and actual_stage != expected_stage:
            raise AssertionError(label + ': expected stage ' + expected_stage + ', got ' + actual_stage)
        if actual_reason != expected_reason:
            raise AssertionError(label + ': expected rejection ' + expected_reason + ', got ' + actual_reason)
    records.append({'case': label, 'accepted': accepted, 'result': reason, 'input_sha256': sha256(apk), 'expected_reason': expected_reason, 'expected_stage': expected_stage})
    print(label, reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--real-only', action='store_true', help='Run only real APK checks, no fixture generation')
    parser.add_argument('--audit-only', action='store_true', help='Write semantic proof receipts after inspection')
    args = parser.parse_args()
    for label, apk in APKS.items():
        if not apk.is_file():
            raise SystemExit('External reviewed GMS APK fixture is missing: ' + label
                             + '; provide the documented local assets explicitly.')
        if sha256(apk) != REVIEWED_APK_SHA256[label]:
            raise SystemExit('reviewed host input hash mismatch: ' + label)
    starting_sources = source_hashes()
    classpath, native = compile_host()
    if args.audit_only:
        for label, apk in APKS.items():
            destination = ASSETS / 'research/dexkit-adaptive-v017-audit' / (label + '-receipt.txt')
            destination.parent.mkdir(parents=True, exist_ok=True)
            result = run_host(classpath, native, apk, destination)
            print(label, result.stdout.strip())
            if result.returncode:
                raise SystemExit(result.stderr)
        require_unchanged_sources(starting_sources)
        return
    unit_result = subprocess.run(['java', '-cp', classpath, PACKAGE + '.GmsGateVerifierTest'], check=True, timeout=30, text=True, capture_output=True)
    print(unit_result.stdout.strip())
    # These retained proof tests cover historical v0.1.6 helpers, not v0.1.7
    # admission. The current resolver does not call memo or connection proofs.
    memo_result = subprocess.run(['java', '--enable-native-access=ALL-UNNAMED', '-Xmx128m', '-cp', classpath,
        PACKAGE + '.GmsMemoProofTest', str(native), str(APKS['new'])], check=True, timeout=60, text=True, capture_output=True)
    print(memo_result.stdout.strip())
    connection_result = subprocess.run(['java', '-Xmx128m', '-cp', classpath,
        PACKAGE + '.GmsConnectionProofTest', str(APKS['new'])], check=True, timeout=60, text=True, capture_output=True)
    print(connection_result.stdout.strip())
    records = []
    for label, apk in APKS.items():
        expect(classpath, native, apk, True, label, records, expected_expression='A')
    if args.real_only:
        require_unchanged_sources(starting_sources)
        return
    # Prove the positive flag chain before mutations. Supplied service, supplier,
    # memo and registry variations deliberately remain outside this contract.
    from gms_resolver_fixtures import build_case, SOURCE as fixture_source
    complete_cases = json.loads((fixture_source / 'cases.json').read_text())
    verified_baselines = set()
    for case in complete_cases:
        if case.get('base') and case['base'] not in verified_baselines:
            raise AssertionError('complete fixture baseline was not VERIFIED: ' + case['base'])
        if not case['accepted'] and (not case.get('stage') or not case.get('reason') or case['reason'] == 'TODO'):
            raise AssertionError('negative fixture must declare an exact stage and reason: ' + case['id'])
        apk = build_case(case)
        expect(classpath, native, apk, case['accepted'], 'complete_' + case['id'], records, case.get('reason'),
               'A' if case['accepted'] else None, case.get('stage'))
        records[-1]['baseline'] = case.get('base')
        records[-1]['coverage_scope'] = case.get('scope', 'phenotype_flag')
        if case['accepted']:
            verified_baselines.add(case['id'])
    fixtures = BUILD_ROOT / 'dexkit-probe/fixtures'
    cases = sorted(fixtures.glob('*/dex.zip'))
    if len(cases) != 12:
        raise SystemExit('expected the existing 12 legacy candidate-discovery fixtures')
    for apk in cases:
        expect(classpath, native, apk, False, 'local_only_' + apk.parent.name, records,
               expected_stage='discovery', expected_reason='getter_candidates_45704091=0')
        records[-1]['coverage_limit'] = 'Legacy fixture lacks the namespace-root and complete flag/cache flow; rejection does not test supplier semantics'
    variants = BUILD_ROOT / 'gms-resolver-v017/variants'
    variants.mkdir(parents=True, exist_ok=True)
    renamed = variants / 'old-renamed-reordered.zip'
    synthetic_variant(APKS['old'], renamed, {'Leabp;': 'LzzBP;', 'Ljpsb;': 'LzzSB;', 'Ljpsa;': 'LzzSA;'})
    expect(classpath, native, renamed, True, 'old_reviewed_class_rename_and_dex_order', records)
    renamed = variants / 'new-renamed-registers-reordered.zip'
    synthetic_variant(APKS['new'], renamed, {'Lecyv;': 'LzzYV;', 'Ljtmb;': 'LzzMB;', 'Ljtma;': 'LzzMA;'}, supplier_register_swap=True, rename_gate_method=True)
    expect(classpath, native, renamed, True, 'new_reviewed_class_and_method_rename_local_registers_and_dex_order', records)
    changed = variants / 'new-changed-branch.zip'
    synthetic_variant(APKS['new'], changed, {}, invert_branch=True)
    expect(classpath, native, changed, True, 'new_changed_supplier_truth_table_outside_phenotype_scope', records,
           expected_expression='A')
    require_unchanged_sources(starting_sources)
    evidence = ASSETS / 'research/dexkit-adaptive-v017-audit/host-results.json'
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps({'host_only': True, 'target_code_executed': False,
        'device_tested': False, 'scope': 'phenotype_getter_only', 'rule_version': 3,
        'synthetic_zip_installable': False, 'normalization_tests': unit_result.stdout.strip(),
        'historical_non_admission_proof_tests': {'memo': memo_result.stdout.strip(), 'connection': connection_result.stdout.strip()},
        'groups': {'real_apks': len(APKS), 'complete_chain_cases': len(complete_cases),
                   'complete_chain_positive': sum(case['accepted'] for case in complete_cases),
                   'complete_chain_negative_exact_stage_reason': sum(not case['accepted'] for case in complete_cases),
                   'legacy_candidate_only': len(cases), 'real_dex_variants': 3}, 'cases': records,
        'source_hashes': starting_sources}, indent=2) + '\n')
    print('Production resolver host checks passed; no target classes executed, no phone operations.')


if __name__ == '__main__':
    main()
