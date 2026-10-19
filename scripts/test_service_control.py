#!/usr/bin/env python3
"""Host-only production control protocol and pidfd tests; never invokes ADB.

Shell tests use explicit path/UID fixtures and intercepted Android commands.
Native tests signal only sleep children created by this test; fake /proc supplies
Android identities, while pidfds and deadline/session behavior use Linux itself.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

from project_paths import ROOT

SOURCE = ROOT / 'experiments/registration-compat/module'
SERVICE = 'com.google.android.moseyservice.IMoseyService/default'
UID = os.getuid()

DISPATCH = r'''import json, os, pathlib, subprocess, sys, time
root = pathlib.Path(os.environ['CONTROL_FIXTURE'])
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with (root/'calls').open('a') as f: f.write(json.dumps([name,args])+'\n')
def read(name, default=''):
 p=root/name
 return p.read_text() if p.exists() else default
def write(name,value): (root/name).write_text(value)
if name == 'id': print(read('uid','0')); sys.exit(0)
if name == 'pidof':
 assert args == ['mosey_server'], args
 pid=read('pids'); print(pid,end='');sys.exit(0 if pid else 1)
if name == 'timeout':
 assert args[:2]==['-k','1'],args
 assert args[3] in ('service','log'),args
 sys.exit(subprocess.run(args[3:]).returncode)
if name == 'service':
 assert args==['list'],args
 if read('mode')=='replace-during-stop' and (root/'term-sent').exists():
  write('proc/415/stat','415 (mosey_server) S '+'0 '*18+'999999\n')
 print(read('binder','Found 0 services:\n'),end='');sys.exit(0)
if name == 'log': sys.exit(int(read('log-rc','0')))
if name == 'sleep':
 # Fake elapsed boot clock advances while wall wait stays small.
 now=int(read('proc/uptime').split()[0]);write('proc/uptime',str(now+3)+' 0\n')
 time.sleep(.01);sys.exit(0)
if name == 'mosey_service_control':
 mode=read('mode')
 if args==['terminate']:
  write('term-sent','1')
  if mode=='pidfd-unsupported':sys.exit(69)
  if mode not in ('term-timeout','replace-during-stop','binder-remains'):
   (root/'proc/415/stat').unlink(missing_ok=True);write('pids','');write('binder','Found 0 services:\n')
  if mode=='binder-remains':
   (root/'proc/415/stat').unlink(missing_ok=True);write('pids','')
  sys.exit(0)
 assert len(args)==2 and args[0]=='run-start' and 1<=int(args[1])<=180,args
 write('start-called',args[1])
 if mode=='start-timeout':sys.exit(124)
 if mode=='start-failed':print('RESULT=LOADING_GATE_FAILED');sys.exit(1)
 # Emulate a newly owned donor; no Android binary is executed.
 write('proc/415/stat','415 (mosey_server) S '+'0 '*18+'777\n')
 write('pids','415');write('binder','Found 1 services:\n0\tcom.google.android.moseyservice.IMoseyService/default: [com.google.android.moseyservice.IMoseyService]\n')
 binary=(root/'mosey_server').stat()
 write('control/owned',f'1 fixture-boot 415 777 {binary.st_dev} {binary.st_ino}\n');(root/'control/owned').chmod(0o600)
 sys.exit(0)
raise RuntimeError((name,args))
'''


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mosey-control-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.module = self.root/'module'
        self.module.mkdir()
        self.bin = self.root/'bin'
        self.bin.mkdir()
        self.proc = self.root/'proc'
        (self.proc/'sys/kernel/random').mkdir(parents=True)
        (self.proc/'sys/kernel/random/boot_id').write_text('fixture-boot\n')
        (self.proc/'uptime').write_text('100 0\n')
        for pid in ('self','1'):
            (self.proc/pid/'attr').mkdir(parents=True)
            (self.proc/pid/'attr/current').write_text('u:r:ksu:s0\n')
            (self.proc/pid/'ns').mkdir()
            (self.proc/pid/'ns/mnt').symlink_to('mnt:[1]')
        (self.root/'mosey_server').write_text('host data, never executed')
        (self.module/'module.prop').write_text('id=moseyPLK.service\nversion=v0.6.0\nversionCode=13\n')
        self.control = self.root/'control'
        self.control.mkdir(mode=0o700)
        self.events = self.root/'events'
        dispatch = self.root/'dispatch.py'
        dispatch.write_text('#!/usr/bin/python3\n'+DISPATCH)
        dispatch.chmod(0o755)
        names=['id','pidof','timeout','service','log','sleep']
        for name in names:(self.bin/name).symlink_to(dispatch)
        (self.module/'mosey_service_control').symlink_to(dispatch)
        self.env = dict(os.environ, CONTROL_FIXTURE=str(self.root))
        path=f'{self.bin}:/usr/bin:/bin'
        forward=''.join(f'{name}() {{ {shlex.quote(str(self.bin/name))} "$@"; }}\n' for name in names)
        for name in ['service.sh','control.sh','control-common.sh','control-worker.sh','registration-checks.sh','status-checks.sh','event-log.sh']:
            text=(SOURCE/name).read_text()
            text=text.replace('/data/adb/mosey-plk110-cn/control',str(self.control))
            text=text.replace('/data/adb/mosey-plk110-cn/events',str(self.events))
            text=text.replace('PROC_ROOT=/proc','PROC_ROOT='+shlex.quote(str(self.proc)))
            text=text.replace('BIN=/odm/bin/mosey_server','BIN='+shlex.quote(str(self.root/'mosey_server')))
            text=text.replace('PATH=/system/bin:/system/xbin','PATH='+shlex.quote(path))
            text=text.replace('= 0:700',f'= {UID}:700').replace('= 0:600',f'= {UID}:600')
            if name=='registration-checks.sh':
                text=text.replace('registration_token()','fixture_token()').replace('registration_alive()','fixture_alive()')
                text+='''\nregistration_token() {
 if [ "$1" = 415 ]; then fixture_token "$1"; else sed 's/^.*) //' /proc/"$1"/stat 2>/dev/null | awk '{print $20}'; fi
}
registration_alive() {
 if [ "$1" = 415 ]; then fixture_alive "$1"; else [ -r /proc/"$1"/stat ]; fi
}
'''
            first,rest=text.split('\n',1)
            (self.module/name).write_text(first+'\n'+forward+rest)
        (self.module/'status-monitor.sh').write_text(
            '#!/bin/sh\nprintf "started\\n" >> '+shlex.quote(str(self.root/'monitor-calls'))+'\n')
        self.donor(False)
        self.addCleanup(self.wait_workers)

    def write(self, name, value):
        (self.root/name).write_text(value)

    def donor(self, present=True):
        p=self.proc/'415'
        (p/'attr').mkdir(parents=True,exist_ok=True)
        (p/'attr/current').write_text('u:r:mosey_server:s0\n')
        (p/'status').write_text('Uid: 1000 1000 1000 1000\nGid: 1000 1000 1000 1000\nGroups: 3003\n'+''.join(f'Cap{x}: 0000000000003000\n' for x in ('Inh','Prm','Eff','Amb')))
        if not (p/'exe').exists():(p/'exe').symlink_to(self.root/'mosey_server')
        if present:
            (p/'stat').write_text('415 (mosey_server) S '+'0 '*18+'777\n')
            self.write('pids','415')
            self.write('binder',f'Found 1 services:\n0\t{SERVICE}: [com.google.android.moseyservice.IMoseyService]\n')
            binary=(self.root/'mosey_server').stat()
            (self.control/'owned').write_text(f'1 fixture-boot 415 777 {binary.st_dev} {binary.st_ino}\n')
            (self.control/'owned').chmod(0o600)
        else:
            self.write('pids','');self.write('binder','Found 0 services:\n')

    def call(self,*args):
        p=subprocess.run(['/bin/sh',str(self.module/'control.sh'),*args],env=self.env,text=True,capture_output=True,timeout=10)
        self.assertEqual(p.stderr,'')
        value=json.loads(p.stdout)
        self.assertEqual(value['schema'],1)
        return value

    def until_done(self):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            status=self.call('status')
            operation=status.get('lastOperation')
            if operation and operation['state']!='running':return status
            time.sleep(.025)
        self.fail('worker did not complete')

    def wait_workers(self):
        deadline=time.monotonic()+3
        while (self.control/'lock').exists() and time.monotonic()<deadline:time.sleep(.02)

    def test_capabilities_version_and_read_only_status(self):
        capabilities=self.call('capabilities')
        self.assertEqual(capabilities['timeouts'],dict(status=10,start=180,stop=30,restart=210))
        self.assertEqual(capabilities['versionCode'],13)
        status=self.call('status')
        self.assertEqual(status['state'],'Stopped')
        self.assertFalse(status['owned'])
        self.assertFalse((self.control/'operation').exists())

    def test_no_root_or_wrong_domain_and_arbitrary_commands_refused(self):
        self.write('uid','2000');self.assertEqual(self.call('stop')['reason'],'ROOT_REQUIRED')
        self.write('uid','0')
        (self.proc/'self/attr/current').write_text('u:r:su:s0')
        self.assertEqual(self.call('start')['reason'],'CALLER_CONTEXT_UNVERIFIED')
        (self.proc/'self/attr/current').write_text('u:r:ksu:s0')
        for args in [('kill','415'),('stop','415'),('am force-stop',),()]:
            self.assertEqual(self.call(*args)['reason'],'INVALID_COMMAND')
        self.assertFalse((self.control/'operation').exists())

    def test_private_namespace_can_observe_but_not_public_control(self):
        (self.proc/'self/ns/mnt').unlink();(self.proc/'self/ns/mnt').symlink_to('mnt:[2]')
        self.assertFalse(self.call('status')['mountNamespaceVerified'])
        self.assertEqual(self.call('start')['reason'],'MOUNT_NAMESPACE_UNVERIFIED')

    def test_boot_private_namespace_uses_direct_registration_and_serializes_control(self):
        (self.proc/'self/ns/mnt').unlink();(self.proc/'self/ns/mnt').symlink_to('mnt:[2]')
        binary=(self.root/'mosey_server').stat()
        q=shlex.quote
        registration=self.module/'registration-compat.sh'
        registration.write_text(f'''#!/bin/sh
printf '%s\\n' "$*" >> {q(str(self.root/'registration-calls'))}
[ "$#" = 2 ] && [ "$1" = service ] && [ "$2" = 180 ] || exit 64
while [ ! -f {q(str(self.root/'release-registration'))} ]; do /bin/sleep 0.01; done
printf '%s\\n' '415 (mosey_server) S {'0 '*18}777' > {q(str(self.proc/'415/stat'))}
printf '415' > {q(str(self.root/'pids'))}
printf '%s\\n' 'Found 1 services:' '0\t{SERVICE}: [com.google.android.moseyservice.IMoseyService]' > {q(str(self.root/'binder'))}
printf '%s\\n' '1 fixture-boot 415 777 {binary.st_dev} {binary.st_ino}' > {q(str(self.control/'owned'))}
chmod 0600 {q(str(self.control/'owned'))}
printf 'RESULT=SHIM_REGISTERED_PROCESS_RUNNING\\n'
''')
        service=subprocess.Popen(['/bin/sh',str(self.module/'service.sh')],env=self.env,
            text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+5
            while not (self.root/'registration-calls').exists() and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue((self.root/'registration-calls').exists(),'boot registration did not start')
            # Model the later init-namespace KSU invocation seen on device. It
            # must observe the live boot owner rather than start a second donor.
            (self.proc/'self/ns/mnt').unlink();(self.proc/'self/ns/mnt').symlink_to('mnt:[1]')
            competing=self.call('start')
            self.assertFalse(competing['ok'])
            self.assertEqual(competing['reason'],'OPERATION_BUSY_OR_UNTRUSTED_LOCK')
        finally:
            (self.root/'release-registration').touch()
        stdout,stderr=service.communicate(timeout=5)
        self.assertEqual(service.returncode,0,stdout+stderr)
        self.assertEqual(stderr,'')
        self.assertIn('RESULT=SHIM_REGISTERED_PROCESS_RUNNING',stdout)
        self.assertEqual((self.root/'registration-calls').read_text().splitlines(),['service 180'])
        self.assertEqual(self.call('status')['state'],'Running')
        self.assertTrue(self.call('status')['owned'])
        self.assertFalse((self.control/'lock').exists())
        self.assertFalse((self.root/'start-called').exists())

    def test_failed_boot_registration_releases_shared_control_lock(self):
        registration=self.module/'registration-compat.sh'
        registration.write_text('''#!/bin/sh
[ "$#" = 2 ] && [ "$1" = service ] && [ "$2" = 180 ] || exit 64
printf 'RESULT=DEFERRED_SYSTEM_SERVER_UNAVAILABLE\\n'
exit 1
''')
        result=subprocess.run(['/bin/sh',str(self.module/'service.sh')],env=self.env,
            text=True,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertEqual(result.stderr,'')
        self.assertIn('RESULT=DEFERRED_SYSTEM_SERVER_UNAVAILABLE',result.stdout)
        self.assertFalse((self.control/'lock').exists())
        self.assertFalse((self.root/'start-called').exists())

    def test_async_start_and_owned_stop(self):
        accepted=self.call('start');self.assertTrue(accepted['ok'])
        status=self.until_done();self.assertEqual(status['lastOperation']['state'],'succeeded')
        self.assertEqual(status['state'],'Running');self.assertTrue(status['owned'])
        self.assertEqual(status['lastOperation']['id'],accepted['operation']['id'])
        self.assertTrue(self.call('stop')['ok'])
        status=self.until_done();self.assertEqual(status['state'],'Stopped')
        self.assertEqual(status['lastOperation']['reason'],'STOPPED')

    def test_restart_confirms_stop_then_starts(self):
        self.donor();self.assertTrue(self.call('restart')['ok'])
        status=self.until_done();self.assertEqual(status['state'],'Running')
        calls=[json.loads(x) for x in (self.root/'calls').read_text().splitlines()]
        native=[c[1][0] for c in calls if c[0]=='mosey_service_control']
        self.assertEqual(native,['terminate','run-start'])

    def test_unknown_or_reused_process_not_adopted(self):
        self.donor();(self.control/'owned').unlink()
        self.call('stop');status=self.until_done()
        self.assertEqual(status['lastOperation']['reason'],'OWNERSHIP_UNVERIFIED')
        self.assertFalse((self.root/'term-sent').exists())
        self.donor();(self.proc/'415/stat').write_text('415 (mosey_server) S '+'0 '*18+'888\n')
        self.call('restart');self.assertEqual(self.until_done()['lastOperation']['reason'],'OWNERSHIP_UNVERIFIED')
        self.assertFalse((self.root/'start-called').exists())

    def test_failed_stop_never_starts_replacement(self):
        for mode,reason in [('pidfd-unsupported','PIDFD_UNAVAILABLE'),('replace-during-stop','PROCESS_REPLACED'),('binder-remains','STATE_UNCONFIRMED'),('term-timeout','STOP_TIMEOUT')]:
            with self.subTest(mode=mode):
                self.donor();self.write('mode',mode);(self.root/'term-sent').unlink(missing_ok=True)
                self.call('restart');status=self.until_done()
                self.assertEqual(status['lastOperation']['reason'],reason)
                self.assertFalse((self.root/'start-called').exists())
                self.wait_workers()

    def test_start_failure_and_timeout_terminal_without_retry(self):
        for mode,reason,state in [('start-failed','LOADING_GATE_FAILED','failed'),('start-timeout','START_TIMEOUT','unconfirmed')]:
            self.write('mode',mode);self.call('start');status=self.until_done()
            self.assertEqual(status['lastOperation']['reason'],reason)
            self.assertEqual(status['lastOperation']['state'],state)
            self.wait_workers()

    def test_concurrent_public_starts_never_duplicate_donor(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:self.call('start'),range(2)))
        self.assertTrue(any(r['ok'] for r in results))
        self.until_done();self.wait_workers()
        calls=[json.loads(x) for x in (self.root/'calls').read_text().splitlines()]
        self.assertEqual(sum(row[0]=='mosey_service_control' and row[1][0]=='run-start' for row in calls),1)

    def test_untrusted_lock_refused_and_dead_owner_recovers(self):
        lock=self.control/'lock';lock.mkdir(mode=0o700)
        (lock/'owner').write_text('arbitrary\n');(lock/'owner').chmod(0o600)
        self.assertEqual(self.call('start')['reason'],'OPERATION_BUSY_OR_UNTRUSTED_LOCK')
        (lock/'owner').write_text('1 fixture-boot 9999999 123 old active 1\n')
        self.assertTrue(self.call('start')['ok']);self.assertEqual(self.until_done()['state'],'Running')

    def test_live_lock_or_recent_handoff_never_stolen(self):
        lock=self.control/'lock';lock.mkdir(mode=0o700)
        pid=os.getpid();token=Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[19]
        owner=lock/'owner';owner.write_text(f'1 fixture-boot {pid} {token} live active 1\n');owner.chmod(0o600)
        self.assertFalse(self.call('start')['ok'])
        owner.write_text('1 fixture-boot 9999999 123 pending starting 100\n')
        self.assertFalse(self.call('start')['ok'])

    def test_stale_or_malformed_operation_not_running(self):
        op=self.control/'operation';op.write_text('1 other-boot test start running ACCEPTED 1 200\n');op.chmod(0o600)
        self.assertIsNone(self.call('status')['lastOperation'])
        op.write_text('1 fixture-boot test start running ACCEPTED 1 90\n')
        self.assertEqual(self.call('status')['lastOperation']['state'],'unconfirmed')
        op.write_text('1 fixture-boot evil" start running ACCEPTED 1 200\n')
        self.assertIsNone(self.call('status')['lastOperation'])

    def test_start_result_symlink_cannot_truncate_external_file(self):
        external=self.root/'unrelated';external.write_text('preserve')
        (self.control/'start-result').symlink_to(external)
        self.call('start');self.until_done()
        self.assertEqual(external.read_text(),'preserve')
        self.assertEqual(self.call('status')['lastOperation']['reason'],'STATE_WRITE_FAILED')
        self.assertFalse((self.root/'start-called').exists())

    def test_state_symlink_to_directory_never_writes_outside_control(self):
        external=self.root/'external';external.mkdir()
        for name in ['operation','start-result']:
            with self.subTest(name=name):
                link=self.control/name;link.unlink(missing_ok=True);link.symlink_to(external,target_is_directory=True)
                result=self.call('start')
                if result['ok']: self.until_done()
                self.assertEqual(list(external.iterdir()),[])
                self.assertFalse((self.root/'start-called').exists())
                link.unlink();self.wait_workers()

    def test_logcat_survives_unavailable_file_sink(self):
        self.events.symlink_to(self.root/'missing')
        self.call('start');self.assertEqual(self.until_done()['lastOperation']['state'],'succeeded')
        calls=[json.loads(x) for x in (self.root/'calls').read_text().splitlines()]
        self.assertTrue(any(row[0]=='log' for row in calls))

    def test_log_rotation_is_private_bounded_and_failures_isolated(self):
        self.events.mkdir(mode=0o700)
        for suffix in ('','.1','.2'):
            file=self.events/('events.log'+suffix);file.write_bytes(b'x'*1048576);file.chmod(0o600)
        self.write('log-rc','1');self.call('start');self.until_done()
        for file in self.events.glob('events.log*'):
            self.assertLessEqual(file.stat().st_size,1048576);self.assertEqual(file.stat().st_mode&0o777,0o600)
        self.assertEqual(len(list(self.events.glob('events.log*'))),3)


class NativeControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='mosey-pidfd-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.proc=self.root/'proc';self.control=self.root/'control';self.control.mkdir(mode=0o700)
        (self.proc/'sys/kernel/random').mkdir(parents=True);(self.proc/'sys/kernel/random/boot_id').write_text('host-boot\n')
        (self.proc/'self/attr').mkdir(parents=True);(self.proc/'self/attr/current').write_text('u:r:ksu:s0\n')
        for pid in ['self','1']:
            (self.proc/pid/'ns').mkdir(parents=True);(self.proc/pid/'ns/mnt').symlink_to('mnt:[1]')
        self.target=self.root/'mosey_server';self.target.write_text('fixture executable identity')
        self.module=self.root/'module';self.module.mkdir()
        self.helper=self.root/'control'
        self.helper=self.root/'native-helper'
        flags=['-std=c11','-Wall','-Wextra','-Werror','-Wconversion','-Wshadow','-Wpedantic',f'-DCONTROL_OWNER_UID={UID}']
        for name,path in [('ROOT',self.control),('PROC',self.proc),('EXE',self.target),('MODULE',self.module),('SHELL',Path('/bin/sh'))]:flags.append(f'-DCONTROL_{name}="{path}"')
        subprocess.run(['cc',*flags,str(ROOT/'native/service-control/control.c'),str(ROOT/'native/load-probe/probe_parse.c'),'-o',str(self.helper)],check=True,capture_output=True)
        self.child=subprocess.Popen(['sleep','20']);self.addCleanup(self.cleanup_child)
        self.pid=self.child.pid;self.token=Path(f'/proc/{self.pid}/stat').read_text().rsplit(') ',1)[1].split()[19]
        p=self.proc/str(self.pid);(p/'attr').mkdir(parents=True)
        (p/'exe').symlink_to(self.target);(p/'attr/current').write_text('u:r:mosey_server:s0\n')
        (p/'stat').write_text(f'{self.pid} (fixture) S '+'0 '*18+self.token+'\n')
        (p/'status').write_text('Uid: 1000 1000 1000 1000\nGid: 1000 1000 1000 1000\nGroups: 3003\n'+''.join(f'Cap{x}: 0000000000003000\n' for x in ('Inh','Prm','Eff','Amb')))
        self.record(f'1 host-boot {self.pid} {self.token} {self.target.stat().st_dev} {self.target.stat().st_ino}\n')

    def record(self,text):
        (self.control/'owned').write_text(text);(self.control/'owned').chmod(0o600)
    def cleanup_child(self):
        if self.child.poll() is None:self.child.terminate()
        self.child.wait(timeout=3)
    def call(self,*args):return subprocess.run([str(self.helper),*args],capture_output=True,text=True,timeout=5).returncode
    def test_pidfd_terminates_only_verified_owned_child(self):
        self.assertEqual(self.call('probe'),0);self.assertEqual(self.call('terminate'),0)
        self.assertEqual(self.child.wait(timeout=2),-signal.SIGTERM)
    def test_changed_token_domain_or_inode_cannot_signal(self):
        p=self.proc/str(self.pid)
        original=(p/'stat').read_text();(p/'stat').write_text(original.replace(self.token,'99999999'))
        self.assertEqual(self.call('terminate'),66);self.assertIsNone(self.child.poll());(p/'stat').write_text(original)
        (p/'attr/current').write_text('u:r:su:s0');self.assertEqual(self.call('terminate'),66);self.assertIsNone(self.child.poll())
        (p/'attr/current').write_text('u:r:mosey_server:s0');self.record(f'1 host-boot {self.pid} {self.token} 0 1\n')
        self.assertEqual(self.call('terminate'),66)
    def test_record_permissions_symlinks_and_extra_arguments_refused(self):
        (self.control/'owned').chmod(0o644);self.assertEqual(self.call('terminate'),65)
        self.assertEqual(self.call('terminate',str(self.pid)),64)
        file=self.control/'owned';file.rename(self.control/'other');file.symlink_to(self.control/'other')
        self.assertEqual(self.call('terminate'),65);self.assertIsNone(self.child.poll())
    def test_wrong_caller_domain_is_rejected_before_signal(self):
        (self.proc/'self/attr/current').write_text('u:r:su:s0\n')
        self.assertEqual(self.call('terminate'),78);self.assertIsNone(self.child.poll())
    def test_private_caller_mount_namespace_is_rejected(self):
        (self.proc/'self/ns/mnt').unlink();(self.proc/'self/ns/mnt').symlink_to('mnt:[2]')
        self.assertEqual(self.call('terminate'),79);self.assertIsNone(self.child.poll())
    def test_run_start_timeout_leaves_detached_daemon_alive(self):
        script=self.module/'registration-compat.sh'
        daemon=self.root/'daemon.pid'
        script.write_text('#!/bin/sh\nsetsid sh -c '+shlex.quote('echo $$ > '+shlex.quote(str(daemon))+'; exec sleep 3')+' </dev/null >/dev/null 2>&1 &\nsleep 10\n')
        before=time.monotonic();self.assertEqual(self.call('run-start','1'),124);self.assertLess(time.monotonic()-before,2)
        pid=int(daemon.read_text());self.assertTrue(Path(f'/proc/{pid}/stat').exists())
        os.kill(pid,signal.SIGTERM)
    def test_run_start_has_fixed_target_and_bounded_budget(self):
        (self.module/'registration-compat.sh').write_text('#!/bin/sh\n[ "$1" = control ] || exit 99\nexit 42\n')
        self.assertEqual(self.call('run-start','180'),42)
        for value in ['0','181','-1','1;reboot','']:
            self.assertEqual(self.call('run-start',value),64)

if __name__=='__main__':unittest.main(verbosity=2)
