#!/usr/bin/env python3
"""Execute the real probe wrapper using host-only stubs and temporary files.

No ADB, Android binary, donor launcher, or real preload library is executed.
The timeout stub intercepts the nested preload shell before LD_PRELOAD can
reach the host loader; it validates that command and runs a host launcher stub.
Built-artifact checks inspect bytes/ELF metadata only and skip before a build.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
from project_paths import ASSETS
import shlex
import shutil
import subprocess
import tempfile
import unittest
import zipfile

from build_module import DONOR, LAUNCHER, LAUNCHER_SHA, ROOT, SEPOLICY_SHA
from build_load_probe import LIBRARY, OUTPUT, PROBE


def digest(data):
    return hashlib.sha256(data).hexdigest()


class LoadProbeWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mosey-load-probe-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.module = self.root / 'module'
        self.module.mkdir()
        self.stub = self.root / 'host-bin'
        self.stub.mkdir()
        self.logs = self.root / 'records'
        self.probe = self.root / 'mount/odm/bin/mosey_load_probe'
        self.library = self.root / 'mount/odm/lib64/libmosey_load_probe.so'
        self.launcher = self.root / 'mount/vendor/bin/mosey_launcher'
        self.proc = self.root / 'proc'
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        (self.proc / 'sys/kernel/random/boot_id').write_text('fixture-boot\n')
        (self.proc / 'uptime').write_text('200.50 1000.00\n')
        for pid in ['self', '1', '100', '200']:
            directory = self.proc / pid
            (directory / 'attr').mkdir(parents=True)
            (directory / 'attr/current').write_text('u:r:ksu:s0\n')
            (directory / 'ns').mkdir()
            (directory / 'ns/mnt').symlink_to('mnt:[12345]')
            (directory / 'stat').write_text(f'{pid} (fixture) S 0 0 0\n')
        q = lambda p: shlex.quote(str(p))
        self.write_executable(self.probe, f'''#!/bin/sh
[ "${{MOSEY_FIXTURE_ONLY:-}}" = 1 ] || exit 91
case "$1" in baseline|preload) ;; *) exit 92 ;; esac
printf '%s\\n' "$1" >> {q(self.root / 'probe-calls')}
stdout_target=$(readlink /proc/$$/fd/1)
printf '%s\\n' "$stdout_target" >> {q(self.root / 'probe-stdout')}
cat {q(self.root)}/"$1.output"
exit "$(cat {q(self.root)}/"$1.rc")"
''')
        self.write_executable(self.launcher, f'''#!/bin/sh
[ "${{MOSEY_FIXTURE_ONLY:-}}" = 1 ] || exit 93
[ "$#" = 2 ] && [ "$1" = {q(self.probe)} ] || exit 94
printf '%s\\n' "$2" >> {q(self.root / 'launcher-calls')}
case "$2" in baseline|preload) exec "$1" "$2" ;; *) exit 95 ;; esac
''')
        self.library.parent.mkdir(parents=True)
        self.library.write_text('host fixture: never load this file\n')
        self.write_executable(self.stub / 'timeout', f'''#!/bin/sh
[ "$1" = -k ] && [ "$2" = 1 ] && [ "$3" = 8 ] || exit 96
shift 3
if [ "$1" = sh ]; then
    [ "$#" = 7 ] && [ "$2" = -c ] && [ "$4" = sh ] || exit 97
    [ "$5" = {q(self.library)} ] && [ "$6" = {q(self.launcher)} ] && [ "$7" = {q(self.probe)} ] || exit 97
    case "$3" in *'LD_PRELOAD="$1";'*'exec "$2" "$3" preload'*) ;; *) exit 97 ;; esac
    # Deliberately emulate only this environment-setting wrapper. Never export
    # LD_PRELOAD on the host or execute a real Android/ARM file.
    mode=preload
    printf 'PRELOAD_REQUESTED\\n' >> {q(self.root / 'preload-requests')}
    "$6" "$7" "$mode"
    result=$?
else
    [ "$#" = 3 ] && [ "$1" = {q(self.launcher)} ] && [ "$2" = {q(self.probe)} ] && [ "$3" = baseline ] || exit 98
    mode=baseline
    "$@"
    result=$?
fi
override={q(self.root)}/"$mode.timeout-rc"
[ ! -f "$override" ] || result=$(cat "$override")
exit "$result"
''')
        self.write_executable(self.stub / 'ls', f'''#!/bin/sh
case "$1" in
    -Z)
        case "$2" in
            {q(self.probe)}) cat {q(self.root / 'probe.label')} ;;
            {q(self.library)}) cat {q(self.root / 'library.label')} ;;
            {q(self.launcher)}) cat {q(self.root / 'launcher.label')} ;;
            *) exit 99 ;;
        esac ;;
    -lZ) printf 'fixture-view %s\\n' "$2" ;;
    *) exit 99 ;;
esac
''')
        self.write_executable(self.stub / 'id', f'''#!/bin/sh
if [ "$1" = -u ]; then cat {q(self.root / 'uid')}; else echo 'uid=0(root) fixture'; fi
''')
        self.write_executable(self.stub / 'pidof', '#!/bin/sh\necho "100 200"\n')
        self.write_executable(self.stub / 'sleep', '#!/bin/sh\nexit 0\n')
        self.write_executable(self.stub / 'date', '#!/bin/sh\necho 20260914T172655\n')
        # Any accidental Android state-changing operation is rejected, not run.
        for command in ['adb', 'mount', 'umount', 'setprop', 'am', 'pm', 'service', 'reboot', 'ksud']:
            self.write_executable(self.stub / command, '#!/bin/sh\nexit 99\n')
        (self.root / 'uid').write_text('0\n')
        (self.root / 'probe.label').write_text('u:object_r:mosey_server_exec:s0\n')
        (self.root / 'library.label').write_text('u:object_r:vendor_file:s0\n')
        (self.root / 'launcher.label').write_text('u:object_r:vendor_file:s0\n')
        self.output('baseline', 'BASELINE_IDENTITY_OK')
        self.output('preload', 'PRELOAD_OK')
        self.refresh_hashes()
        source = (ROOT / 'experiments/load-probe/module/load-probe.sh').read_text()
        replacements = {
            'MODDIR=${0%/*}': 'MODDIR=' + q(self.module),
            'LOGROOT=/data/adb/mosey-plk110-cn/load-probe': 'LOGROOT=' + q(self.logs),
            'PROBE=/odm/bin/mosey_load_probe': 'PROBE=' + q(self.probe),
            'LIBRARY=/odm/lib64/libmosey_load_probe.so': 'LIBRARY=' + q(self.library),
            'LAUNCHER=/vendor/bin/mosey_launcher': 'LAUNCHER=' + q(self.launcher),
            'PROC_ROOT=/proc': 'PROC_ROOT=' + q(self.proc),
            'PATH=/system/bin:/system/xbin': 'PATH=' + q(f'{self.stub}:/usr/bin:/bin'),
        }
        for old, new in replacements.items():
            self.assertEqual(source.count(old), 1, f'Fixture anchor changed: {old}')
            source = source.replace(old, new)
        # Some BusyBox builds prefer in-process applets to PATH executables.
        # Shell functions take precedence in ash and dash, so the same fixtures
        # stay effective even for BusyBox's id, timeout, ls, pidof, and sleep.
        forwarding = ''.join(f'{path.name}() {{ {q(path)} "$@"; }}\n'
                             for path in sorted(self.stub.iterdir()))
        first_line, rest = source.split('\n', 1)
        source = first_line + '\n' + forwarding + rest
        (self.module / 'load-probe.sh').write_text(source)
        for name in ['service.sh', 'action.sh']:
            shutil.copyfile(ROOT / 'experiments/load-probe/module' / name, self.module / name)

    @staticmethod
    def write_executable(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o755)

    def refresh_hashes(self):
        (self.module / 'payload.sha256').write_text(''.join(
            f'{digest(path.read_bytes())}  system{path}\n'
            for path in [self.probe, self.library, self.launcher]))

    def output(self, mode, result, rc=0, secure=0, **fields):
        values = dict(PROBE_SCHEMA='1', MODE=mode, EXE=str(self.probe), IDENTITY_OK='1',
                      AT_SECURE_VALID='1', AT_SECURE=str(secure), LD_PRELOAD_EXPECTED='1',
                      MARKER_FOUND='1', MARKER_ORIGIN_EXPECTED='1', MARKER_INITIALIZED='1',
                      READ_ERROR_MASK='0', RESULT=result, EXIT_CODE=str(rc))
        values.update(fields)
        (self.root / f'{mode}.output').write_text(''.join(
            f'{key}={value}\n' for key, value in values.items() if value is not None))
        (self.root / f'{mode}.rc').write_text(str(rc) + '\n')

    def run_probe(self, expected, origin='action', via_entrypoint=False):
        busybox = os.environ.get('MOSEY_TEST_BUSYBOX')
        shell = [busybox, 'ash'] if busybox else ['/bin/sh']
        target = self.module / (f'{origin}.sh' if via_entrypoint else 'load-probe.sh')
        env = dict(os.environ, MOSEY_FIXTURE_ONLY='1', PATH='/usr/bin:/bin')
        env.pop('LD_PRELOAD', None)
        env.pop('LD_LIBRARY_PATH', None)
        command = [*shell, str(target), *([] if via_entrypoint else [origin])]
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=10)
        self.assertEqual(result.returncode, 0 if expected == 'PROBE_PRELOAD_CONFIRMED' else 1,
                         result.stdout + result.stderr)
        records = [line.removeprefix('Records: ') for line in result.stdout.splitlines()
                   if line.startswith('Records: ')]
        self.assertEqual(len(records), 1, result.stdout + result.stderr)
        directory = Path(records[0])
        self.assertTrue(directory.is_relative_to(self.logs))
        self.assertEqual((directory / 'result.txt').read_text(), f'RESULT={expected}\n')
        return directory

    def assert_not_started(self):
        self.assertFalse((self.root / 'launcher-calls').exists())
        self.assertFalse((self.root / 'probe-calls').exists())

    def test_success_through_service_and_action(self):
        for origin in ['service', 'action']:
            with self.subTest(origin=origin):
                directory = self.run_probe('PROBE_PRELOAD_CONFIRMED', origin, via_entrypoint=True)
                self.assertIn(f'ORIGIN={origin}\n', (directory / 'context.txt').read_text())
        self.assertEqual((self.root / 'launcher-calls').read_text(), 'baseline\npreload\n' * 2)
        self.assertTrue(all(line.startswith('pipe:[')
                            for line in (self.root / 'probe-stdout').read_text().splitlines()))

    def test_bad_baseline_identity_never_attempts_preload(self):
        self.output('baseline', 'IDENTITY_MISMATCH', rc=10, IDENTITY_OK='0')
        self.run_probe('BASELINE_FAILED')
        self.assertEqual((self.root / 'probe-calls').read_text(), 'baseline\n')
        self.assertFalse((self.root / 'preload-requests').exists())

    def test_baseline_wrong_executable_is_unverified(self):
        self.output('baseline', 'BASELINE_IDENTITY_OK', EXE='/unexpected/probe')
        self.run_probe('BASELINE_UNVERIFIED')
        self.assertFalse((self.root / 'preload-requests').exists())

    def test_baseline_missing_result_is_unverified(self):
        self.output('baseline', None)
        self.run_probe('BASELINE_UNVERIFIED')
        self.assertFalse((self.root / 'preload-requests').exists())

    def test_at_secure_missing_library_classified(self):
        self.output('preload', 'PRELOAD_NOT_LOADED', rc=11, secure=1,
                    LD_PRELOAD_EXPECTED='0', MARKER_FOUND='0',
                    MARKER_ORIGIN_EXPECTED='0', MARKER_INITIALIZED='0')
        self.run_probe('PRELOAD_BLOCKED_AT_SECURE')

    def test_missing_library_without_at_secure_not_misclassified(self):
        self.output('preload', 'PRELOAD_NOT_LOADED', rc=11, secure=0,
                    MARKER_FOUND='0', MARKER_ORIGIN_EXPECTED='0', MARKER_INITIALIZED='0')
        self.run_probe('PRELOAD_UNCONFIRMED')

    def test_launcher_marker_alone_is_not_probe_confirmation(self):
        (self.root / 'preload.output').write_text('MARKER_CONSTRUCTOR_LOADED=1\n')
        self.run_probe('PRELOAD_UNCONFIRMED')

    def test_unverified_marker_fields_never_pass(self):
        for field in ['MARKER_FOUND', 'MARKER_ORIGIN_EXPECTED', 'MARKER_INITIALIZED']:
            for value in ['0', None]:
                with self.subTest(field=field, value=value):
                    self.output('preload', 'PRELOAD_OK', **{field: value})
                    self.run_probe('PRELOAD_UNCONFIRMED')

    def test_preload_wrong_executable_never_passes(self):
        self.output('preload', 'PRELOAD_OK', EXE='/unexpected/probe')
        self.run_probe('PRELOAD_UNCONFIRMED')

    def test_preload_duplicate_or_conflicting_result_never_passes(self):
        for additional in ['RESULT=PRELOAD_OK\n', 'RESULT=READ_ERROR\n']:
            with self.subTest(additional=additional):
                self.output('preload', 'PRELOAD_OK')
                with (self.root / 'preload.output').open('a') as stream:
                    stream.write(additional)
                self.run_probe('PRELOAD_UNCONFIRMED')

    def test_preload_missing_identity_or_schema_never_passes(self):
        for field in ['IDENTITY_OK', 'PROBE_SCHEMA', 'MODE', 'READ_ERROR_MASK', 'EXIT_CODE']:
            with self.subTest(field=field):
                self.output('preload', 'PRELOAD_OK', **{field: None})
                self.run_probe('PRELOAD_UNCONFIRMED')

    def test_preload_nonzero_exit_never_passes_success_text(self):
        for rc in [1, 11, 12, 124, 137]:
            with self.subTest(rc=rc):
                self.output('preload', 'PRELOAD_OK', rc=rc)
                self.run_probe('PRELOAD_UNCONFIRMED')

    def test_timeout_after_success_text_never_passes(self):
        (self.root / 'preload.timeout-rc').write_text('124\n')
        self.run_probe('PRELOAD_UNCONFIRMED')

    def test_baseline_timeout_stops_before_preload(self):
        (self.root / 'baseline.timeout-rc').write_text('124\n')
        self.run_probe('BASELINE_FAILED')
        self.assertFalse((self.root / 'preload-requests').exists())

    def test_loader_error_without_probe_output_never_passes(self):
        (self.root / 'preload.output').write_text('CANNOT LINK EXECUTABLE: fixture loader error\n')
        (self.root / 'preload.rc').write_text('1\n')
        self.run_probe('PRELOAD_UNCONFIRMED')

    def test_each_missing_payload_stops_before_launch(self):
        for path in [self.probe, self.library, self.launcher]:
            with self.subTest(path=path.name):
                stored = path.with_suffix('.stored')
                path.rename(stored)
                try:
                    self.run_probe('FILES_NOT_READY')
                    self.assert_not_started()
                finally:
                    stored.rename(path)

    def test_hash_mismatch_stops_before_launch(self):
        self.library.write_text('tampered fixture\n')
        self.run_probe('PAYLOAD_MISMATCH')
        self.assert_not_started()

    def test_missing_hash_stops_before_launch(self):
        (self.module / 'payload.sha256').write_text('')
        self.run_probe('PAYLOAD_MISMATCH')
        self.assert_not_started()

    def test_wrong_probe_label_stops_before_launch(self):
        (self.root / 'probe.label').write_text('u:object_r:vendor_file:s0\n')
        self.run_probe('PROBE_LABEL_MISMATCH')
        self.assert_not_started()

    def test_wrong_library_label_stops_before_launch(self):
        (self.root / 'library.label').write_text('u:object_r:unlabeled:s0\n')
        self.run_probe('LIBRARY_LABEL_MISMATCH')
        self.assert_not_started()

    def test_wrong_launcher_label_stops_before_launch(self):
        (self.root / 'launcher.label').write_text('u:object_r:unlabeled:s0\n')
        self.run_probe('LAUNCHER_LABEL_MISMATCH')
        self.assert_not_started()

    def test_wrong_caller_domain_stops_before_launch(self):
        (self.proc / 'self/attr/current').write_text('u:r:su:s0\n')
        self.run_probe('CALLER_CONTEXT_UNVERIFIED')
        self.assert_not_started()

    def test_nonroot_stops_before_launch(self):
        (self.root / 'uid').write_text('2000\n')
        self.run_probe('ROOT_REQUIRED')
        self.assert_not_started()

    def test_consecutive_runs_keep_separate_evidence(self):
        first = self.run_probe('PROBE_PRELOAD_CONFIRMED')
        original = (first / 'preload.txt').read_bytes()
        self.output('preload', 'PRELOAD_NOT_LOADED', rc=11, secure=1,
                    MARKER_FOUND='0', MARKER_ORIGIN_EXPECTED='0', MARKER_INITIALIZED='0')
        second = self.run_probe('PRELOAD_BLOCKED_AT_SECURE')
        self.assertNotEqual(first, second)
        self.assertEqual((first / 'preload.txt').read_bytes(), original)
        self.assertNotIn('RESULT=PRELOAD_OK\n', (second / 'preload.txt').read_text())

    def test_concurrent_runs_keep_separate_evidence(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            records = list(pool.map(lambda _: self.run_probe('PROBE_PRELOAD_CONFIRMED'), range(2)))
        self.assertNotEqual(*records)
        for directory in records:
            self.assertTrue((directory / 'baseline.txt').is_file())
            self.assertTrue((directory / 'preload.txt').is_file())


@unittest.skipUnless((ASSETS / 'dist' / OUTPUT).is_file(), 'Optional local load-probe ZIP is absent; no build is started')
class LoadProbeArtifactTests(unittest.TestCase):
    def setUp(self):
        self.archive = zipfile.ZipFile(ASSETS / 'dist' / OUTPUT)
        self.addCleanup(self.archive.close)

    def test_exact_ten_payload_targets_and_original_donor_hashes(self):
        expected = {'system/' + path for path in DONOR} | {LAUNCHER, PROBE, LIBRARY}
        self.assertEqual({name for name in self.archive.namelist() if name.startswith('system/')}, expected)
        for path, sha in DONOR.items():
            self.assertEqual(digest(self.archive.read('system/' + path)), sha, path)
        self.assertEqual(digest(self.archive.read(LAUNCHER)), LAUNCHER_SHA)

    def test_all_recorded_hashes_match_and_six_rules_are_preserved(self):
        manifest = self.archive.read('payload.sha256').decode().splitlines()
        recorded = set()
        for line in manifest:
            sha, path = line.split('  ', 1)
            self.assertNotIn(path, recorded)
            recorded.add(path)
            self.assertEqual(digest(self.archive.read(path)), sha, path)
        installed = {name for name in self.archive.namelist()
                     if not name.startswith('META-INF/') and name != 'payload.sha256'}
        self.assertEqual(recorded, installed)
        policy = self.archive.read('sepolicy.rule')
        self.assertEqual(digest(policy), SEPOLICY_SHA)
        self.assertEqual(len([line for line in policy.decode().splitlines()
                              if line.strip() and not line.startswith('#')]), 6)

    def test_packaged_entrypoints_are_probe_only(self):
        for name in ['service.sh', 'action.sh', 'load-probe.sh']:
            self.assertEqual(self.archive.read(name), (ROOT / 'experiments/load-probe/module' / name).read_bytes())
        self.assertNotIn('post-fs-data.sh', self.archive.namelist())
        for name in ['service.sh', 'action.sh']:
            content = self.archive.read(name).decode()
            self.assertIn('"$MODDIR/load-probe.sh"', content)
            self.assertNotIn('mosey_server', content)

    def check_manager_extraction(self, mutation=None):
        # Reproduce the observed metainstaller: META-INF remains in the ZIP
        # but is not extracted into MODPATH. Run the real payload checker.
        with tempfile.TemporaryDirectory(prefix='mosey-manager-extraction-') as directory:
            self.assertIn('META-INF/com/google/android/update-binary', self.archive.namelist())
            self.assertIn('META-INF/com/google/android/updater-script', self.archive.namelist())
            for name in self.archive.namelist():
                if not name.startswith('META-INF/'):
                    self.archive.extract(name, directory)
            self.assertFalse((Path(directory) / 'META-INF').exists())
            if mutation is not None:
                path, operation = mutation
                target = Path(directory) / path
                if operation == 'remove':
                    target.unlink()
                else:
                    target.write_bytes(target.read_bytes() + b'corrupted')
            return subprocess.run(
                ['/bin/sh', '-c', '. ./common.sh\nmosey_check_payload'],
                cwd=directory, env=os.environ | {'MODDIR': directory},
                capture_output=True, text=True, timeout=10)

    def test_manager_extraction_passes_without_meta_inf(self):
        result = self.check_manager_extraction()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_manager_extraction_still_rejects_missing_or_corrupt_payload(self):
        for path, operation in [('load-probe.sh', 'remove'), (LIBRARY, 'corrupt')]:
            with self.subTest(path=path, operation=operation):
                result = self.check_manager_extraction((path, operation))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f'{path}: FAILED', result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which('readelf'), 'Host readelf unavailable; ELF files are never executed')
    def test_probe_has_no_marker_or_binder_dt_needed(self):
        with tempfile.TemporaryDirectory(prefix='mosey-elf-inspect-') as directory:
            for path in [PROBE, LIBRARY]:
                payload = self.archive.read(path)
                self.assertEqual(payload[:6], b'\x7fELF\x02\x01')
                self.assertEqual(int.from_bytes(payload[18:20], 'little'), 183)
                elf = Path(directory) / Path(path).name
                elf.write_bytes(payload)
                metadata = subprocess.check_output(['readelf', '-d', str(elf)], text=True)
                needed = '\n'.join(line for line in metadata.splitlines() if '(NEEDED)' in line)
                self.assertNotIn('libmosey_load_probe.so', needed)
                self.assertNotIn('libbinder', needed)
                self.assertNotIn('libmosey_daemon_ffi.so', needed)


if __name__ == '__main__':
    unittest.main(verbosity=2)
