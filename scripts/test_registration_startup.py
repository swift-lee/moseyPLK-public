#!/usr/bin/env python3
"""Host-only fixtures for the actual registration wrapper; never use ADB or ELF.

The child-sh fixture validates and intercepts the only LD_PRELOAD command before
it can reach a host loader. A Python process emulates donor /proc/log responses.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
from project_paths import ASSETS
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'experiments/registration-compat/module'
SERVICE = 'com.google.android.moseyservice.IMoseyService/default'
EVENTS = [
    'event=loaded schema=1 experiment=registration_only origin_expected=1',
    'event=identity ok=1 reason=ok read_errors=0',
    'event=intercept target=1 enabled=1 binder_nonnull=1',
    'event=binder local=1 descriptor=1',
    'event=api source=/system/lib64/libbinder_ndk.so verified=1',
    'event=downgrade phase=begin target=1 to=system',
    'event=downgrade phase=returned target=1 to=system',
    'event=add_result target=1 downgraded=1 called=1 code=0 source=platform',
]


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mosey-registration-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.module = self.root / 'module'
        self.module.mkdir()
        self.mount = self.root / 'mount'
        self.logs = self.root / 'logs'
        self.addCleanup(self.wait_background)
        self.stub = self.root / 'host-bin'
        self.stub.mkdir()
        self.proc = self.root / 'proc'
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        (self.proc / 'sys/kernel/random/boot_id').write_text('fixture-boot\n')
        (self.proc / 'uptime').write_text('72.68 100.0\n')
        for pid in ['self', '1', '200']:
            p = self.proc / pid
            (p / 'attr').mkdir(parents=True)
            (p / 'attr/current').write_text('u:r:ksu:s0\n')
            (p / 'ns').mkdir()
            (p / 'ns/mnt').symlink_to('mnt:[fixture]')
            (p / 'stat').write_text(f'{pid} (fixture) S ' + ' '.join(['0'] * 18) + ' 777\n')
            (p / 'root').symlink_to(self.mount)
        self.paths = [
            'odm/bin/mosey_server', 'odm/lib64/libmosey_daemon_ffi.so',
            'odm/etc/init/mosey.rc', 'odm/etc/vintf/manifest/manifest_mosey.xml',
            'system_ext/priv-app/MoseyApp/MoseyApp.apk',
            'system_ext/etc/permissions/privapp-permissions-com.google.android.mosey.xml',
            'system_ext/etc/default-permissions/default-permissions-com.google.android.mosey.xml',
            'vendor/bin/mosey_launcher', 'odm/bin/mosey_load_probe',
            'odm/lib64/libmosey_load_probe.so', 'odm/lib64/libmosey_registration_compat.so',
        ]
        for path in self.paths:
            p = self.mount / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('HOST FIXTURE ONLY; NOT EXECUTABLE\n' + path)
        (self.module / 'payload.sha256').write_text(''.join(
            f'{hashlib.sha256((self.mount / p).read_bytes()).hexdigest()}  system/{p}\n' for p in self.paths))
        self.bin = self.mount / 'odm/bin/mosey_server'
        self.library = self.mount / 'odm/lib64/libmosey_registration_compat.so'
        self.launcher = self.mount / 'vendor/bin/mosey_launcher'
        (self.root / 'mode').write_text('success')
        (self.root / 'events').write_text('\n'.join(EVENTS) + '\n')
        (self.root / 'pids').write_text('')
        (self.root / 'system-pid').write_text('200\n')
        (self.root / 'binder').write_text('Found 0 services:\n')
        (self.root / 'binder-rc').write_text('0')
        (self.root / 'uid').write_text('0')
        (self.root / 'package').write_text('Packages:\n  Package [com.google.android.mosey] (123):\n'
            '    flags=[ SYSTEM HAS_CODE UPDATED_SYSTEM_APP ]\n'
            '    privateFlags=[ PRIVILEGED SYSTEM_EXT ]\n')
        q = lambda p: shlex.quote(str(p))
        self.executable(self.module / 'load-probe.sh', f'''#!/bin/sh
echo invoked >> {q(self.root / 'probe-calls')}
[ "$(cat {q(self.root / 'mode')})" != gate_failed ] || exit 42
if [ "$(cat {q(self.root / 'mode')})" = concurrent ]; then
    while [ ! -f {q(self.root / 'release-gate')} ]; do /bin/sleep 0.01; done
fi
echo RESULT=BASELINE_IDENTITY_OK
echo RESULT=PRELOAD_OK
echo RESULT=PROBE_PRELOAD_CONFIRMED
if [ "$(cat {q(self.root / 'mode')})" = changed_after_probe ]; then
    sed -i 's/777/888/' {q(self.proc / '200/stat')}
fi
''')
        self.executable(self.stub / 'id', f'#!/bin/sh\nif [ "$1" = -u ]; then cat {q(self.root / "uid")}; else echo fixture; fi\n')
        self.executable(self.stub / 'pidof', f'''#!/bin/sh
if [ "$1" = system_server ] && [ "$(cat {q(self.root / 'mode')})" = late_system ]; then
    count=0; [ ! -f {q(self.root / 'system-count')} ] || count=$(cat {q(self.root / 'system-count')})
    count=$((count + 1)); echo "$count" > {q(self.root / 'system-count')}
    if [ "$count" -lt 3 ]; then exit 0; fi
    echo '74.49 100.0' > {q(self.proc / 'uptime')}
fi
case "$1" in system_server) cat {q(self.root / 'system-pid')} ;; mosey_server) cat {q(self.root / 'pids')} ;; *) exit 99 ;; esac
''')
        self.executable(self.stub / 'ls', f'''#!/bin/sh
[ "$1" = -Z ] || exit 99
[ ! -f {q(self.root / 'bad-label')} ] || {{ echo wrong_label; exit; }}
case "$2" in
 */odm/bin/*) echo u:object_r:mosey_server_exec:s0 ;;
 */odm/etc/*) echo u:object_r:vendor_configs_file:s0 ;;
 */system_ext/*) echo u:object_r:system_file:s0 ;;
 *) echo u:object_r:vendor_file:s0 ;;
esac
''')
        self.executable(self.stub / 'sleep', '#!/bin/sh\nexec /bin/sleep 0.025\n')
        self.executable(self.stub / 'timeout', f'''#!/bin/sh
[ "$1" = -k ] && [ "$2" = 1 ] || exit 99
shift 3
case "$1" in
 dumpsys)
    [ "$2 $3" = 'package com.google.android.mosey' ] || exit 99
    if [ "$(cat {q(self.root / 'mode')})" = late_package ] && [ ! -f {q(self.root / 'package-seen')} ]; then
        touch {q(self.root / 'package-seen')}; echo 'Package manager starting'; exit 0
    fi
    if [ "$(cat {q(self.root / 'mode')})" = changed_in_package ] && [ ! -f {q(self.root / 'package-seen')} ]; then
        touch {q(self.root / 'package-seen')}; sed -i 's/777/888/' {q(self.proc / '200/stat')}
    fi
    cat {q(self.root / 'package')} ;;
 service)
    [ "$2" = list ] || exit 99
    if [ "$(cat {q(self.root / 'mode')})" = late_binder ] && [ ! -f {q(self.root / 'binder-seen')} ]; then
        touch {q(self.root / 'binder-seen')}; exit 124
    fi
    if [ "$(cat {q(self.root / 'mode')})" = late_truncated_binder ] && [ ! -f {q(self.root / 'binder-seen')} ]; then
        touch {q(self.root / 'binder-seen')}; printf 'Found 1 services:\\n'; exit 0
    fi
    if [ "$(cat {q(self.root / 'mode')})" = changed_in_binder ] && [ ! -f {q(self.root / 'binder-seen')} ]; then
        touch {q(self.root / 'binder-seen')}; sed -i 's/777/888/' {q(self.proc / '200/stat')}
    fi
    if [ "$(cat {q(self.root / 'mode')})" = changed_in_final_binder ]; then
        count=0
        [ ! -f {q(self.root / 'final-binder-count')} ] || count=$(cat {q(self.root / 'final-binder-count')})
        count=$((count + 1)); echo "$count" > {q(self.root / 'final-binder-count')}
        if [ "$count" = 3 ]; then
            touch {q(self.root / 'final-binder-changed')}; sed -i 's/777/888/' {q(self.proc / '200/stat')}
        fi
    fi
    cat {q(self.root / 'binder')}; exit "$(cat {q(self.root / 'binder-rc')})" ;;
 *) exit 99 ;;
esac
''')
        self.executable(self.stub / 'kill', f'#!/bin/sh\nprintf "%s\\n" "$*" >> {q(self.root / "signals")}\n')
        for command in ['adb', 'mount', 'umount', 'setprop', 'am', 'pm', 'reboot', 'ksud']:
            self.executable(self.stub / command, '#!/bin/sh\nexit 99\n')
        # Emulated donor with its actual host PID/token, isolated fake /proc,
        # and an anonymous-pipe stdout. It exits quickly without outside signals.
        self.runner = self.root / 'runner.py'
        self.runner.write_text('''import os, pathlib, sys, time
root, out, binary = map(pathlib.Path, sys.argv[1:])
pid = os.getpid()
mode = (root / 'mode').read_text()
token = pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
out.joinpath('child.txt').write_text(f'{pid} {token}\\n')
(root / 'launch-calls').open('a').write('launched\\n')
(root / 'stdout-target').write_text(os.readlink('/proc/self/fd/1'))
p = root / 'proc' / str(pid)
(p / 'attr').mkdir(parents=True)
(p / 'attr/current').write_text('u:r:ksu:s0' if mode == 'wrong_identity' else 'u:r:mosey_server:s0')
(p / 'exe').symlink_to(binary)
(p / 'stat').write_text(f'{pid} (mosey_server) S ' + ' '.join(['0'] * 18) + ' ' + token)
(p / 'status').write_text('Uid: 1000 1000 1000 1000\\nGid: 1000 1000 1000 1000\\nGroups: 3003\\n' + ''.join(f'Cap{x}: 0000000000003000\\n' for x in ['Inh','Prm','Eff','Amb']))
(root / 'pids').write_text(str(pid))
if mode == 'exit':
    print('FRESH_DONOR_FAILURE', flush=True)
else:
    if mode == 'long_log':
        print('X' * 2000000, flush=True)
    for event in (root / 'events').read_text().splitlines():
        print(f'MOSEY_REGCOMPAT pid={pid} {event}', flush=True)
    if mode != 'no_binder':
        (root / 'binder').write_text('Found 1 services:\\n0\\tcom.google.android.moseyservice.IMoseyService/default: [interface]\\n')
    if mode == 'changed_pid':
        (p / 'stat').write_text(f'{pid} (mosey_server) S ' + ' '.join(['0'] * 18) + ' 999999')
if mode != 'exit':
    # Keep the emulated donor alive until the observer publishes this attempt's
    # result. A fixed lifetime races the bounded host rounds in both directions.
    deadline = time.monotonic() + 8
    while not out.joinpath('result.txt').exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    # Successful entrypoints must return while the detached donor is still live.
    time.sleep(1)
(p / 'stat').write_text(f'{pid} (mosey_server) Z ' + ' '.join(['0'] * 18) + ' ' + token)
(root / 'pids').write_text('')
sys.exit(42 if mode == 'exit' else 0)
''')
        self.executable(self.stub / 'sh', f'''#!/bin/sh
if [ "$1" != -c ]; then exec /bin/sh "$@"; fi
[ "$#" = 7 ] && [ "$3" = sh ] || exit 97
[ "$5" = {q(self.library)} ] && [ "$6" = {q(self.launcher)} ] && [ "$7" = {q(self.bin)} ] || exit 97
case "$2" in *'LD_PRELOAD="$2"; MOSEY_REGISTRATION_COMPAT=1'*'exec "$3" "$4"'*) ;; *) exit 97 ;; esac
# Do not execute the supplied Android command or export LD_PRELOAD on the host.
exec /usr/bin/python3 {q(self.runner)} {q(self.root)} "$4" "$7"
''')
        source = (SOURCE / 'registration-compat.sh').read_text()
        replacements = {
            'MODDIR=${0%/*}': 'MODDIR=' + q(self.module),
            'LOGROOT=/data/adb/mosey-plk110-cn/registration-compat': 'LOGROOT=' + q(self.logs),
            'PROC_ROOT=/proc': 'PROC_ROOT=' + q(self.proc),
            'BIN=/odm/bin/mosey_server': 'BIN=' + q(self.bin),
            'LIBRARY=/odm/lib64/libmosey_registration_compat.so': 'LIBRARY=' + q(self.library),
            'LAUNCHER=/vendor/bin/mosey_launcher': 'LAUNCHER=' + q(self.launcher),
            'PATH=/system/bin:/system/xbin': 'PATH=' + q(f'{self.stub}:/usr/bin:/bin'),
            'then prefix=; else': 'then prefix=' + q(self.mount) + '; else',
        }
        for old, new in replacements.items():
            self.assertEqual(source.count(old), 0 if old.startswith(('LIBRARY=', 'LAUNCHER=')) else 1, old)
            source = source.replace(old, new)
        forward = ''.join(f'{p.name}() {{ {q(p)} "$@"; }}\n' for p in sorted(self.stub.iterdir()))
        first, rest = source.split('\n', 1)
        (self.module / 'registration-compat.sh').write_text(first + '\n' + forward + rest)
        shutil.copyfile(SOURCE / 'registration-checks.sh', self.module / 'registration-checks.sh')
        # Test the finite registration observer directly; public boot/UI control
        # and its shared lock are covered by test_service_control.py.
        for name in ['service', 'retry']:
            (self.module / f'{name}.sh').write_text('#!/bin/sh\nexec sh ' +
                q(self.module / 'registration-compat.sh') + ' service\n')
        supervisor = (SOURCE / 'donor-supervisor.sh').read_text()
        for old, new in replacements.items():
            if old in supervisor:
                supervisor = supervisor.replace(old, new)
        supervisor = supervisor.replace('= 0:700', '= ' + str(os.getuid()) + ':700')
        first, rest = supervisor.split('\n', 1)
        (self.module / 'donor-supervisor.sh').write_text(first + '\n' + forward + rest)

    @staticmethod
    def executable(path, content):
        path.write_text(content)
        path.chmod(0o755)

    def run_wrapper(self, expected, origin='service'):
        busybox = os.environ.get('MOSEY_TEST_BUSYBOX')
        shell = [busybox, 'ash'] if busybox else ['/bin/sh']
        env = dict(os.environ)
        env.pop('LD_PRELOAD', None)
        env.pop('LD_LIBRARY_PATH', None)
        p = subprocess.run([*shell, str(self.module / f'{origin}.sh')],
            env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0 if expected == 'SHIM_REGISTERED_PROCESS_RUNNING' else 1,
            p.stdout + p.stderr)
        paths = [line.removeprefix('Records: ') for line in p.stdout.splitlines() if line.startswith('Records: ')]
        self.assertEqual(len(paths), 1, p.stdout + p.stderr)
        out = Path(paths[0])
        self.assertEqual((out / 'result.txt').read_text(), f'RESULT={expected}\n', p.stdout + p.stderr)
        return out

    def mode(self, value):
        (self.root / 'mode').write_text(value)

    def wait_background(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            attempts = [p.parent for p in self.logs.glob('*/child.txt')]
            if all((p / 'daemon-exit.txt').exists() for p in attempts):
                return
            time.sleep(0.01)

    def no_launch(self):
        self.assertFalse((self.root / 'launch-calls').exists())

    def test_registration_attempts_use_detached_anonymous_pipe(self):
        for origin in ['service', 'retry']:
            with self.subTest(origin=origin):
                (self.root / 'binder').write_text('Found 0 services:\n')
                out = self.run_wrapper('SHIM_REGISTERED_PROCESS_RUNNING', origin)
                self.assertTrue((self.root / 'stdout-target').read_text().startswith('pipe:['))
                self.assertEqual(len((out / 'mounts.txt').read_text().splitlines()), 33)
                self.assertIn('OWNED_STARTTIME=', (out / 'context.txt').read_text())
                self.assertFalse((out / 'daemon-exit.txt').exists(), 'entrypoint waited for donor exit')
                self.wait_background()
        self.assertEqual((self.root / 'launch-calls').read_text().splitlines(), ['launched', 'launched'])

    def test_private_mount_view_is_deferred_without_probe_or_launch(self):
        (self.proc / '1/root').unlink()
        (self.proc / '1/root').symlink_to(self.root / 'unmounted')
        self.run_wrapper('DEFERRED_MOUNT_HASH_MISMATCH')
        self.assertFalse((self.root / 'probe-calls').exists())
        self.no_launch()

    def test_distinct_private_mount_namespace_with_matching_views_can_start(self):
        (self.proc / 'self/ns/mnt').unlink()
        (self.proc / 'self/ns/mnt').symlink_to('mnt:[private]')
        out = self.run_wrapper('SHIM_REGISTERED_PROCESS_RUNNING')
        context = (out / 'context.txt').read_text()
        self.assertIn('CALLER_MNT=mnt:[private]', context)
        self.assertEqual((self.root / 'launch-calls').read_text().splitlines(), ['launched'])

    def test_softboot_entry_before_system_server_waits_then_starts_once(self):
        self.mode('late_system')
        out = self.run_wrapper('SHIM_REGISTERED_PROCESS_RUNNING')
        self.assertIn('READINESS_RETRIES=2', (out / 'context.txt').read_text())
        self.assertEqual((self.root / 'launch-calls').read_text().splitlines(), ['launched'])

    def test_package_manager_readiness_waits_without_start_retry(self):
        self.mode('late_package')
        out = self.run_wrapper('SHIM_REGISTERED_PROCESS_RUNNING')
        self.assertIn('READINESS_RETRIES=1', (out / 'context.txt').read_text())
        self.assertEqual((self.root / 'launch-calls').read_text().splitlines(), ['launched'])

    def test_binder_timeout_during_readiness_waits_then_starts_once(self):
        self.mode('late_binder')
        out = self.run_wrapper('SHIM_REGISTERED_PROCESS_RUNNING')
        self.assertIn('READINESS_RETRIES=1', (out / 'context.txt').read_text())
        self.assertEqual((self.root / 'launch-calls').read_text().splitlines(), ['launched'])

    def test_truncated_successful_binder_reply_is_retried_not_treated_as_absent(self):
        self.mode('late_truncated_binder')
        out = self.run_wrapper('SHIM_REGISTERED_PROCESS_RUNNING')
        self.assertIn('READINESS_RETRIES=1', (out / 'context.txt').read_text())
        self.assertEqual((self.root / 'launch-calls').read_text().splitlines(), ['launched'])

    def test_system_server_change_during_readiness_resamples_identity(self):
        self.mode('changed_in_package')
        out = self.run_wrapper('SHIM_REGISTERED_PROCESS_RUNNING')
        self.assertIn('READINESS_RETRIES=1', (out / 'context.txt').read_text())

    def test_system_server_change_during_binder_query_resamples_identity(self):
        self.mode('changed_in_binder')
        out = self.run_wrapper('SHIM_REGISTERED_PROCESS_RUNNING')
        self.assertIn('READINESS_RETRIES=1', (out / 'context.txt').read_text())

    def test_system_server_change_after_loading_probe_defers(self):
        self.mode('changed_after_probe')
        self.run_wrapper('DEFERRED_SYSTEM_SERVER_CHANGED')
        self.no_launch()

    def test_system_server_change_during_final_binder_query_defers(self):
        self.mode('changed_in_final_binder')
        out = self.run_wrapper('DEFERRED_SYSTEM_SERVER_CHANGED')
        self.assertEqual((self.root / 'final-binder-count').read_text().strip(), '3')
        self.assertTrue((self.root / 'final-binder-changed').exists())
        self.assertIn('BINDER_QUERY=ready RC=0', (out / 'context.txt').read_text())
        self.no_launch()

    def test_corrupt_mount_or_missing_new_library_is_deferred(self):
        self.library.unlink()
        self.run_wrapper('DEFERRED_MOUNT_HASH_MISMATCH')
        self.no_launch()

    def test_wrong_mount_label_is_deferred(self):
        (self.root / 'bad-label').touch()
        self.run_wrapper('DEFERRED_MOUNT_LABEL_MISMATCH')
        self.no_launch()

    def test_hidden_system_app_cannot_substitute_for_active_flags(self):
        (self.root / 'package').write_text('Packages:\n  Package [com.google.android.mosey] (123):\n'
            '    flags=[ HAS_CODE ]\n    privateFlags=[ ]\n'
            'Hidden system packages:\n  Package [com.google.android.mosey] (456):\n'
            '    flags=[ SYSTEM ]\n    privateFlags=[ PRIVILEGED ]\n')
        self.run_wrapper('DEFERRED_SYSTEM_APP_NOT_READY')
        self.no_launch()

    def test_existing_process_is_never_claimed_or_killed(self):
        (self.root / 'pids').write_text('123 456')
        (self.root / 'binder').write_text(f'Found 1 services:\n0\t{SERVICE}: []\n')
        self.run_wrapper('EXISTING_PROCESS_NOT_STARTED')
        self.no_launch()
        self.assertFalse((self.root / 'signals').exists())

    def test_existing_binder_is_never_claimed(self):
        (self.root / 'binder').write_text(f'Found 1 services:\n0\t{SERVICE}: []\n')
        self.run_wrapper('EXISTING_BINDER_NOT_STARTED')
        self.no_launch()

    def test_binder_query_error_is_not_absence(self):
        (self.root / 'binder-rc').write_text('124')
        self.run_wrapper('DEFERRED_BINDER_QUERY_FAILED')
        self.no_launch()

    def test_persistently_truncated_binder_reply_is_not_absence(self):
        (self.root / 'binder').write_text('Found 1 services:\n')
        self.run_wrapper('DEFERRED_BINDER_QUERY_FAILED')
        self.no_launch()

    def test_probe_failure_prevents_real_daemon(self):
        self.mode('gate_failed')
        self.run_wrapper('LOADING_GATE_FAILED')
        self.no_launch()

    def test_wrong_caller_prevents_mount_or_start_work(self):
        (self.proc / 'self/attr/current').write_text('u:r:shell:s0')
        self.run_wrapper('CALLER_CONTEXT_UNVERIFIED')
        self.no_launch()

    def test_shim_success_without_binder_is_not_success(self):
        self.mode('no_binder')
        self.run_wrapper('SHIM_REGISTRATION_UNCONFIRMED')
        self.assertFalse((self.root / 'signals').exists())

    def test_binder_without_interception_is_not_success(self):
        (self.root / 'events').write_text(EVENTS[0] + '\n')
        self.run_wrapper('SHIM_INTERCEPT_NOT_OBSERVED')

    def test_nonzero_registration_return_is_recorded(self):
        (self.root / 'events').write_text('\n'.join(EVENTS).replace('code=0', 'code=-2147483648') + '\n')
        self.run_wrapper('SHIM_ADD_SERVICE_FAILED')

    def test_oversized_log_is_bounded_but_pipe_keeps_draining(self):
        self.mode('long_log')
        out = self.run_wrapper('SHIM_LOG_TRUNCATED')
        self.assertLessEqual((out / 'daemon.log').stat().st_size, 1048576 + 22)
        self.assertIn('MOSEY_LOG_TRUNCATED=1', (out / 'daemon.log').read_text())
        self.wait_background()
        self.assertEqual((out / 'daemon-exit.txt').read_text(), 'DAEMON_EXIT_CODE=0\n')

    def test_failed_new_identity_is_not_signalled_without_full_identity(self):
        self.mode('wrong_identity')
        out = self.run_wrapper('DONOR_IDENTITY_FAILED')
        self.assertTrue((out / 'child.txt').is_file())
        self.assertFalse((self.root / 'signals').exists())

    def test_recycled_pid_is_never_signalled(self):
        self.mode('changed_pid')
        self.run_wrapper('OWNED_PROCESS_CHANGED')
        self.assertFalse((self.root / 'signals').exists())

    def test_exit_status_and_logs_belong_to_this_attempt(self):
        self.mode('exit')
        out = self.run_wrapper('DONOR_PROCESS_EXITED')
        self.assertIn('FRESH_DONOR_FAILURE', (out / 'daemon.log').read_text())
        self.assertEqual((out / 'daemon-exit.txt').read_text(), 'DAEMON_EXIT_CODE=42\n')

    def test_stale_lock_is_recorded_and_never_deleted(self):
        lock = self.logs / 'lock-fixture-boot'
        lock.mkdir(parents=True)
        (lock / 'owner').write_text('PID=123 STARTTIME=456\n')
        (lock / 'record').write_text('old-record\n')
        self.run_wrapper('ATTEMPT_LOCKED')
        self.assertTrue(lock.is_dir())
        self.no_launch()

    def test_concurrent_entries_launch_at_most_one_daemon(self):
        self.mode('concurrent')
        def run(origin):
            return subprocess.run(['/bin/sh', str(self.module / f'{origin}.sh')],
                capture_output=True, text=True, timeout=10)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(run, 'service')
            deadline = time.monotonic() + 5
            while not (self.root / 'probe-calls').exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            second = pool.submit(run, 'retry').result()
            (self.root / 'release-gate').touch()
            results = [first.result(), second]
        combined = ''.join(p.stdout + p.stderr for p in results)
        self.assertIn('RESULT=SHIM_REGISTERED_PROCESS_RUNNING', combined)
        self.assertIn('RESULT=ATTEMPT_LOCKED', combined)
        self.assertEqual((self.root / 'launch-calls').read_text().splitlines(), ['launched'])


class RegistrationLogTests(unittest.TestCase):
    def check(self, events, expected=True):
        with tempfile.TemporaryDirectory(prefix='mosey-registration-log-') as directory:
            path = Path(directory) / 'events'
            path.write_text(''.join(f'MOSEY_REGCOMPAT pid=123 {event}\n' for event in events))
            p = subprocess.run(['/bin/sh', '-c', '. "$1"\nregistration_shim_success "$2" 123',
                'sh', str(SOURCE / 'registration-checks.sh'), str(path)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0 if expected else 1, p.stderr)

    def test_complete_success_contract(self):
        self.check(EVENTS)

    def test_real_child_shell_records_pid_before_exec_with_empty_host_preload(self):
        # Exercise the production sh -c text as well as the wrapper fixture.
        # An empty LD_PRELOAD and two tiny host shell scripts keep this local.
        source = (SOURCE / 'donor-supervisor.sh').read_text()
        command, = re.findall(r"    sh -c '(.*?)' sh \"\$OUT\"", source, re.S)
        with tempfile.TemporaryDirectory(prefix='mosey-child-shell-') as directory:
            out = Path(directory)
            launcher = out / 'launcher'
            app = out / 'app'
            launcher.write_text('#!/bin/sh\nexec "$1"\n')
            app.write_text('#!/bin/sh\nprintf "PID=%s\\nOPTIN=%s\\n" "$$" "$MOSEY_REGISTRATION_COMPAT"\n'
                           'readlink /proc/$$/fd/1\nexit 42\n')
            launcher.chmod(0o755)
            app.chmod(0o755)
            env = dict(os.environ)
            env.pop('LD_PRELOAD', None)
            env.pop('LD_LIBRARY_PATH', None)
            p = subprocess.run(['/bin/sh', '-c', command, 'sh', str(out), '', str(launcher), str(app)],
                               env=env, capture_output=True, text=True)
            self.assertEqual(p.returncode, 42, p.stderr)
            pid, token = (out / 'child.txt').read_text().split()
            self.assertTrue(pid.isdecimal() and token.isdecimal())
            self.assertIn(f'PID={pid}\nOPTIN=1\npipe:[', p.stdout)

    def test_missing_or_duplicate_event_never_confirms_success(self):
        for i in range(len(EVENTS)):
            with self.subTest(i=i):
                self.check(EVENTS[:i] + EVENTS[i + 1:], False)
                self.check(EVENTS + [EVENTS[i]], False)

    def test_failure_or_spoofed_extra_field_never_confirms_success(self):
        self.check(EVENTS + ['event=blocked reason=identity'], False)
        self.check(EVENTS[:-1] + [EVENTS[-1] + ' code=-1'], False)
        self.check([line.replace('target=1', 'target=0') for line in EVENTS], False)

    def test_complete_device_package_dump_uses_active_system_flags(self):
        busybox = os.environ.get('MOSEY_TEST_BUSYBOX')
        shell = [busybox, 'ash'] if busybox else ['/bin/sh']
        for path, expected in [('registration-abi-20260914/package.txt', 0),
                               ('v04-diagnosis-20260914-045446/current-package.txt', 1)]:
            with self.subTest(path=path):
                package = ASSETS / 'research/device' / path
                if not package.exists():
                    self.skipTest('device research is intentionally omitted from source archives')
                # exec-out capture can include CRLF; on-device redirection is LF.
                with tempfile.TemporaryDirectory(prefix='mosey-package-dump-') as directory:
                    normalized = Path(directory) / 'package.txt'
                    normalized.write_text(package.read_text())
                    command = [*shell, '-c', '. "$1"\nregistration_system_app "$2"',
                               'sh', str(SOURCE / 'registration-checks.sh'), str(normalized)]
                    p = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(p.returncode, expected, p.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
