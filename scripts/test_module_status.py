#!/usr/bin/env python3
"""Host fixtures for the real passive status checks and observer lifecycle.

No ADB, Android binaries or donor processes are used. All process identities,
Binder replies and ksud responses live in a temporary directory. Set
MOSEY_TEST_BUSYBOX to run the scripts under BusyBox ash as well as /bin/sh.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'experiments/registration-compat/module'
SERVICE = 'com.google.android.moseyservice.IMoseyService/default'
DESCRIPTOR = 'com.google.android.moseyservice.IMoseyService'
PID = '31415'
PROP = ('id=moseyPLK.service\nname=Mosey PLK110\nversion=v-test\n'
        'versionCode=12\nauthor=fixture\n'
        'description=[⚪ Unknown] Native Mosey service for PLK110.\n'
        'updateJson=https://example.invalid/fixture.json\n')

# A single strict dispatcher records all effectful command boundaries. The
# timeout stub models a bounded command failure; it never waits five seconds.
DISPATCH = r'''import json, os, pathlib, subprocess, sys, time
root = pathlib.Path(os.environ['MOSEY_STATUS_FIXTURE'])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / 'calls').open('a') as stream:
    stream.write(json.dumps([name, args, os.environ.get('KSU_MODULE')]) + '\n')
def read(name, default=''):
    p = root / name
    return p.read_text() if p.exists() else default
def write(name, value):
    (root / name).write_text(value)
if name == 'pidof':
    assert args == ['mosey_server'], args
    print(read('pids'), end='')
    sys.exit(int(read('pid-rc', '0')))
elif name == 'timeout':
    assert args[:3] == ['-k', '1', '5'], args
    assert args[3] == 'service' or args[3] == str(root / 'bin/ksud'), args
    rc = int(read('timeout-rc', '0'))
    if rc:
        sys.exit(rc)
    sys.exit(subprocess.run(args[3:], check=False).returncode)
elif name == 'service':
    assert args == ['list'], args
    mode = read('binder-effect')
    proc = root / 'proc/31415'
    if mode == 'replace-token':
        p = proc / 'stat'
        p.write_text(p.read_text().replace('777', '888'))
    elif mode == 'remove-process':
        (proc / 'stat').unlink()
        write('pids', '')
        write('pid-rc', '1')
    elif mode == 'replace-pid':
        write('pids', '27182')
    elif mode == 'wrong-domain':
        (proc / 'attr/current').write_text('u:r:su:s0\n')
    elif mode == 'appearing-process':
        write('pids', '31415')
        write('pid-rc', '0')
    elif mode == 'pid-query-failure':
        write('pid-rc', '2')
    print(read('binder'), end='')
    sys.exit(int(read('binder-rc', '0')))
elif name == 'ksud':
    assert args[:5] == ['module', 'config', 'set', '--temp', 'override.description'], args
    assert len(args) == 6, args
    assert os.environ.get('KSU_MODULE') == 'moseyPLK.service'
    if read('ksud-effect') == 'lose-owner':
        (root / 'module/.status-owner').write_text('another-observer\n')
    rc = int(read('ksud-rc', '0'))
    if not rc:
        write('override', args[5])
    sys.exit(rc)
elif name == 'sleep':
    assert args == ['30'], args
    time.sleep(0.08)
else:
    # Includes shell builtins forwarded below, so even kill cannot escape.
    (root / 'forbidden').open('a').write(name + ' ' + repr(args) + '\n')
    sys.exit(99)
'''


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mosey-status-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.module = self.root / 'module'
        self.module.mkdir()
        self.stub = self.root / 'bin'
        self.stub.mkdir()
        self.proc = self.root / 'proc'
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        (self.proc / 'sys/kernel/random/boot_id').write_text('fixture-boot\n')
        self.binary = '/odm/bin/mosey_server'
        self.children = []
        self.addCleanup(self.assert_no_forbidden)
        self.addCleanup(self.stop_children)
        self.write('pids', PID)
        self.write('pid-rc', '0')
        self.write('binder', f'Found 1 services:\n0\t{SERVICE}: [{DESCRIPTOR}]\n')
        self.write('module/module.prop', PROP)
        self.write('module/.status-owner', 'fixture-owner\n')
        self.donor()
        for name in ['registration-checks.sh', 'status-checks.sh']:
            shutil.copyfile(SOURCE / name, self.module / name)
        dispatch = self.root / 'dispatch.py'
        dispatch.write_text(f'#!{sys.executable}\n' + DISPATCH)
        dispatch.chmod(0o755)
        names = ['pidof', 'timeout', 'service', 'ksud', 'sleep', 'kill', 'killall',
                 'pkill', 'adb', 'mount', 'umount', 'setprop', 'am', 'pm', 'cmd',
                 'reboot', 'mosey_server', 'mosey_launcher', 'start', 'stop']
        for name in names:
            (self.stub / name).symlink_to(dispatch)
        # BusyBox may resolve built-in applets ahead of PATH; functions guarantee
        # each command boundary uses the fixture under either shell.
        q = shlex.quote
        self.forward = ''.join(
            f'{name}() {{ {q(str(self.stub / name))} "$@"; }}\n' for name in names)
        self.shell = ([os.environ['MOSEY_TEST_BUSYBOX'], 'ash']
                      if os.environ.get('MOSEY_TEST_BUSYBOX') else ['/bin/sh'])
        self.env = dict(os.environ, MOSEY_STATUS_FIXTURE=str(self.root),
                        PATH=f'{self.stub}:/usr/bin:/bin', LC_ALL='C')
        for name in ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'MOSEY_REGISTRATION_COMPAT']:
            self.env.pop(name, None)
        self.prefix = self.forward + '\n'.join([
            'set -f', 'MODDIR=' + q(str(self.module)),
            'PROC_ROOT=' + q(str(self.proc)), 'BIN=' + q(self.binary),
            'SERVICE_NAME=' + q(SERVICE), 'KSUD=' + q(str(self.stub / 'ksud')),
            'STATUS_OWNER=fixture-owner', '. "$MODDIR/registration-checks.sh"',
            '. "$MODDIR/status-checks.sh"', '',
        ])

    def write(self, name, text):
        (self.root / name).write_text(text)

    def donor(self):
        proc = self.proc / PID
        (proc / 'attr').mkdir(parents=True, exist_ok=True)
        (proc / 'attr/current').write_text('u:r:mosey_server:s0\n')
        (proc / 'stat').write_text(f'{PID} (mosey_server) S ' + '0 ' * 18 + '777\n')
        (proc / 'status').write_text(
            'Uid: 1000 1000 1000 1000\nGid: 1000 1000 1000 1000\nGroups: 3003\n'
            + ''.join(f'Cap{cap}: 0000000000003000\n' for cap in ['Inh', 'Prm', 'Eff', 'Amb']))
        exe = proc / 'exe'
        exe.unlink(missing_ok=True)
        exe.symlink_to(self.binary)

    def call(self, command, expected_rc=0):
        result = subprocess.run([*self.shell, '-c', self.prefix + command],
                                env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, expected_rc, result.stdout + result.stderr)
        self.assertEqual(result.stderr, '')
        return result.stdout.strip()

    def calls(self, name=None):
        path = self.root / 'calls'
        rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [row for row in rows if name is None or row[0] == name]

    def sample(self, expected):
        self.assertEqual(self.call('mosey_status_sample'), expected)
        self.assertFalse(self.calls('ksud'), 'sampling must not publish or modify configuration')

    def assert_no_forbidden(self):
        path = self.root / 'forbidden'
        self.assertFalse(path.exists(), path.read_text() if path.exists() else '')

    def test_running_requires_full_identity_and_exact_binder(self):
        self.sample('Running')
        self.assertEqual(len(self.calls('pidof')), 2)
        self.assertEqual(self.calls('service')[0][1], ['list'])
        self.assertEqual(self.calls('timeout')[0][1], ['-k', '1', '5', 'service', 'list'])

    def test_stopped_requires_two_absent_process_queries_and_no_binder(self):
        self.write('pids', '')
        self.write('pid-rc', '1')
        self.write('binder', 'Found 0 services:\n')
        self.sample('Stopped')
        self.assertEqual(len(self.calls('pidof')), 2)

    def test_live_correct_process_without_registration_is_unregistered(self):
        self.write('binder', 'Found 0 services:\n')
        self.sample('Unregistered')

    def test_similar_service_name_does_not_count(self):
        self.write('binder', f'Found 1 services:\n0\t{SERVICE}2: [{DESCRIPTOR}]\n')
        self.sample('Unregistered')

    def test_binder_without_process_is_unknown(self):
        self.write('pids', '')
        self.write('pid-rc', '1')
        self.sample('Unknown')

    def test_query_failures_and_timeouts_are_unknown(self):
        for field, codes in [('binder-rc', ['1', '124', '137']), ('timeout-rc', ['124', '137'])]:
            for rc in codes:
                with self.subTest(field=field, rc=rc):
                    self.write(field, rc)
                    self.sample('Unknown')
            self.write(field, '0')

    def test_malformed_or_truncated_binder_output_is_unknown(self):
        for reply in ['', 'permission denied\n', 'Found 1 services:\n',
                      'Found 1 services:\ngarbage\n', 'Found 0 services:\ngarbage\n',
                      f'Found 2 services:\n0\t{SERVICE}: [{DESCRIPTOR}]\n',
                      f'Found 1 services:\n0\t{SERVICE}: [{DESCRIPTOR}] extra\n']:
            with self.subTest(reply=reply):
                self.write('binder', reply)
                self.sample('Unknown')

    def test_wrong_or_duplicate_target_descriptor_is_unknown(self):
        for reply in [f'Found 1 services:\n0\t{SERVICE}: [wrong.interface]\n',
                      f'Found 2 services:\n0\t{SERVICE}: [{DESCRIPTOR}]\n'
                      f'1\t{SERVICE}: [{DESCRIPTOR}]\n']:
            with self.subTest(reply=reply):
                self.write('binder', reply)
                self.sample('Unknown')

    def test_pid_query_failure_multiple_pids_and_invalid_pid_are_unknown(self):
        for pids, rc in [('', '0'), ('', '2'), (PID, '1'), ('31415 27182', '0'), ('oops', '0')]:
            with self.subTest(pids=pids, rc=rc):
                self.write('pids', pids)
                self.write('pid-rc', rc)
                self.sample('Unknown')
        self.assertFalse(self.calls('service'))

    def test_incomplete_or_wrong_identity_is_unknown(self):
        status = self.proc / PID / 'status'
        correct = status.read_text()
        changes = [('Uid: 1000 1000 1000 1000', 'Uid: 0 0 0 0'),
                   ('Gid: 1000 1000 1000 1000', 'Gid: 1000 1000 0 1000'),
                   ('Groups: 3003', 'Groups: 1000'),
                   *[(f'Cap{cap}: 0000000000003000', f'Cap{cap}: 0000000000000000')
                     for cap in ['Inh', 'Prm', 'Eff', 'Amb']]]
        for old, new in changes:
            with self.subTest(field=old):
                status.write_text(correct.replace(old, new))
                self.sample('Unknown')
        status.unlink()
        self.sample('Unknown')
        self.assertFalse(self.calls('service'))

    def test_wrong_domain_executable_or_dead_process_is_unknown(self):
        for mode in ['domain', 'exe', 'zombie', 'gone', 'invalid-token']:
            with self.subTest(mode=mode):
                self.donor()
                proc = self.proc / PID
                if mode == 'domain':
                    (proc / 'attr/current').write_text('u:r:su:s0\n')
                elif mode == 'exe':
                    (proc / 'exe').unlink()
                    (proc / 'exe').symlink_to('/data/local/tmp/mosey_server')
                elif mode == 'zombie':
                    (proc / 'stat').write_text((proc / 'stat').read_text().replace(') S ', ') Z '))
                elif mode == 'gone':
                    (proc / 'stat').unlink()
                else:
                    (proc / 'stat').write_text((proc / 'stat').read_text().replace('777', 'bad'))
                self.sample('Unknown')
        self.assertFalse(self.calls('service'))

    def test_lifetime_changes_during_binder_query_are_unknown(self):
        for effect in ['replace-token', 'remove-process', 'replace-pid', 'wrong-domain', 'pid-query-failure']:
            with self.subTest(effect=effect):
                self.donor()
                self.write('pids', PID)
                self.write('pid-rc', '0')
                self.write('binder-effect', effect)
                self.sample('Unknown')

    def test_process_appearing_during_stopped_snapshot_is_unknown(self):
        self.write('pids', '')
        self.write('pid-rc', '1')
        self.write('binder', 'Found 0 services:\n')
        self.write('binder-effect', 'appearing-process')
        self.sample('Unknown')

    def test_recent_ksud_uses_temporary_override_without_changing_prop(self):
        prop = self.module / 'module.prop'
        original = prop.stat()
        self.call('mosey_status_publish Running')
        self.assertEqual(prop.read_text(), PROP)
        self.assertEqual(prop.stat().st_ino, original.st_ino)
        self.assertEqual(prop.stat().st_mtime_ns, original.st_mtime_ns)
        self.assertEqual((self.root / 'override').read_text(), '[🟢 Running] Native Mosey service for PLK110.')
        self.assertEqual(self.calls('ksud')[0][2], 'moseyPLK.service')

    def test_legacy_ksud_fallback_is_atomic_preserves_fields_and_skips_repeat(self):
        self.write('ksud-rc', '2')
        prop = self.module / 'module.prop'
        before = prop.stat()
        with prop.open() as old_inode:
            self.call('mosey_status_publish Running')
            self.assertEqual(old_inode.read(), PROP, 'old inode must not be edited in place')
        self.assertNotEqual(prop.stat().st_ino, before.st_ino)
        self.assertEqual(prop.read_text(), PROP.replace('[⚪ Unknown]', '[🟢 Running]'))
        self.assertEqual(prop.stat().st_mode & 0o777, 0o644)
        after = prop.stat()
        self.call('mosey_status_publish Running')
        self.assertEqual((prop.stat().st_ino, prop.stat().st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        self.assertFalse(list(self.module.glob('.status-prop.*')))

    def test_ksud_timeout_also_falls_back(self):
        self.write('timeout-rc', '124')
        self.call('mosey_status_publish Stopped')
        self.assertIn('[🔴 Stopped]', (self.module / 'module.prop').read_text())

    def test_fallback_refuses_ambiguous_prop_description(self):
        self.write('ksud-rc', '1')
        for prop in [PROP.replace('description=', 'other='), PROP + 'description=duplicate\n']:
            with self.subTest(prop=prop):
                self.write('module/module.prop', prop)
                self.call('mosey_status_publish Running', expected_rc=1)
                self.assertEqual((self.module / 'module.prop').read_text(), prop)
                self.assertFalse(list(self.module.glob('.status-prop.*')))

    def test_unknown_owner_or_module_id_cannot_publish(self):
        self.write('module/.status-owner', 'new-owner\n')
        self.call('mosey_status_publish Running', expected_rc=1)
        self.write('module/.status-owner', 'fixture-owner\n')
        for module_id in ['some.other.module', 'moseyPLKXservice']:
            with self.subTest(module_id=module_id):
                self.write('module/module.prop', PROP.replace('moseyPLK.service', module_id))
                self.call('mosey_status_publish Running', expected_rc=1)
        self.assertFalse(self.calls('ksud'))

    def test_ownership_change_during_failed_ksud_cancels_fallback(self):
        self.write('ksud-rc', '1')
        self.write('ksud-effect', 'lose-owner')
        self.call('mosey_status_publish Running', expected_rc=1)
        self.assertEqual((self.module / 'module.prop').read_text(), PROP)
        self.assertFalse(list(self.module.glob('.status-prop.*')))

    def test_invalid_status_cannot_publish(self):
        self.call('mosey_status_publish Restarting', expected_rc=1)
        self.assertFalse(self.calls('ksud'))
        self.assertEqual((self.module / 'module.prop').read_text(), PROP)

    def start_monitor(self):
        q = shlex.quote
        source = (SOURCE / 'status-monitor.sh').read_text()
        for old, new in {
            'PROC_ROOT=/proc': 'PROC_ROOT=' + q(str(self.proc)),
            'KSUD=/data/adb/ksud': 'KSUD=' + q(str(self.stub / 'ksud')),
            'PATH=/system/bin:/system/xbin': 'PATH=' + q(self.env['PATH']),
        }.items():
            self.assertEqual(source.count(old), 1, old)
            source = source.replace(old, new)
        first, rest = source.split('\n', 1)
        monitor = self.module / 'status-monitor.sh'
        monitor.write_text(first + '\n' + self.forward + rest)
        # The launcher keeps its PID across exec; only its stat is copied from
        # host /proc so production startup validates a real observer lifetime.
        command = (f'mkdir -p {q(str(self.proc))}/$$\n'
                   f'cat /proc/$$/stat > {q(str(self.proc))}/$$/stat\n'
                   'exec ' + shlex.join([*self.shell, str(monitor)]))
        child = subprocess.Popen([*self.shell, '-c', command], env=self.env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, start_new_session=True)
        self.children.append(child)
        return child

    def until(self, predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail('observer did not reach expected fixture state')

    def override_is(self, state):
        path = self.root / 'override'
        return path.exists() and path.read_text() == f"[{ {'Running': '🟢', 'Stopped': '🔴', 'Unregistered': '🟡', 'Unknown': '⚪'}[state]} {state}] Native Mosey service for PLK110."

    def finish(self, child):
        stdout, stderr = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, stdout + stderr)
        self.assertEqual(stdout + stderr, '')

    def stop_children(self):
        # Only our own temporary fixture process groups can receive host cleanup
        # signals. Wait for them even when an assertion fails mid-observation.
        for child in self.children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
            try:
                child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.communicate(timeout=3)

    def test_monitor_reasserts_temporary_status_and_marks_normal_exit_unknown(self):
        child = self.start_monitor()
        self.until(lambda: self.override_is('Running'))
        self.until(lambda: len(self.calls('sleep')) >= 3)
        self.assertGreaterEqual(len(self.calls('ksud')), 3)
        self.write('binder', 'Found 0 services:\n')
        self.until(lambda: self.override_is('Unregistered'))
        child.terminate()
        self.finish(child)
        self.assertTrue(self.override_is('Unknown'))
        self.assertIn(f':{child.pid}:', (self.module / '.status-owner').read_text())

    def test_legacy_monitor_rechecks_without_rewriting_unchanged_prop(self):
        self.write('ksud-rc', '2')
        prop = self.module / 'module.prop'
        child = self.start_monitor()
        self.until(lambda: '[🟢 Running]' in prop.read_text())
        initial = prop.stat()
        sleeps = len(self.calls('sleep'))
        self.until(lambda: len(self.calls('sleep')) >= sleeps + 3)
        self.assertEqual((prop.stat().st_ino, prop.stat().st_mtime_ns),
                         (initial.st_ino, initial.st_mtime_ns))
        child.terminate()
        self.finish(child)
        self.assertEqual(prop.read_text(), PROP)

    def test_stale_owner_never_blocks_a_fresh_observer(self):
        self.write('module/.status-owner', 'earlier-boot:999999:123\n')
        child = self.start_monitor()
        self.until(lambda: self.override_is('Running'))
        self.assertIn(f'fixture-boot:{child.pid}:', (self.module / '.status-owner').read_text())
        child.terminate()
        self.finish(child)

    def test_replacement_observer_retires_previous_owner(self):
        old = self.start_monitor()
        self.until(lambda: self.override_is('Running'))
        previous = (self.module / '.status-owner').read_text()
        replacement = self.start_monitor()
        self.until(lambda: (self.module / '.status-owner').read_text() != previous)
        self.finish(old)
        self.assertIn(f':{replacement.pid}:', (self.module / '.status-owner').read_text())
        self.assertTrue(self.override_is('Running'), 'old observer must not overwrite new status on exit')
        replacement.terminate()
        self.finish(replacement)
        self.assertIn(f':{replacement.pid}:', (self.module / '.status-owner').read_text())

    def test_disable_remove_update_report_unknown_then_resume_when_cleared(self):
        child = self.start_monitor()
        self.until(lambda: self.override_is('Running'))
        for flag in ['disable', 'remove', 'update']:
            with self.subTest(flag=flag):
                (self.module / flag).touch()
                self.until(lambda: self.override_is('Unknown'))
                count = len(self.calls('service'))
                sleeps = len(self.calls('sleep'))
                self.until(lambda: len(self.calls('sleep')) >= sleeps + 2)
                self.assertEqual(len(self.calls('service')), count)
                (self.module / flag).unlink()
                self.until(lambda: self.override_is('Running'))
        child.terminate()
        self.finish(child)

    def test_boot_change_retires_owner_and_publishes_unknown(self):
        child = self.start_monitor()
        self.until(lambda: self.override_is('Running'))
        (self.proc / 'sys/kernel/random/boot_id').write_text('new-boot\n')
        self.finish(child)
        self.assertTrue(self.override_is('Unknown'))
        self.assertIn(f':{child.pid}:', (self.module / '.status-owner').read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
