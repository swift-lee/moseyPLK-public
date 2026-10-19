#!/usr/bin/env python3
"""Offline invariants and metainstall extraction for the registration ZIP."""
import hashlib
import json
import os
from pathlib import Path
from project_paths import ASSETS
import shutil
import subprocess
import tempfile
import unittest
import zipfile

from build_registration import (ROOT, MODULE_ID, OUTPUT, VERSION, VERSION_CODE, DONOR,
                                LAUNCHER, LAUNCHER_SHA, RETAINED_RELEASES)
from build_registration import SEPOLICY_SHA, PROBE, PROBE_LIBRARY, LIBRARY
from public_sources import source_files


def digest(data):
    return hashlib.sha256(data).hexdigest()


class RegistrationMigrationTests(unittest.TestCase):
    """Exercise installer refusal using temporary host directories only."""

    def installer_check(self, legacy_root=None, marker=None, dangling=False, existing_new=False):
        with tempfile.TemporaryDirectory(prefix='mosey-registration-migration-') as directory:
            root = Path(directory)
            stage = root / 'stage'
            stage.mkdir()
            # Reaching the base installer is sufficient: target/SELinux checks
            # belong to its own tests and cannot execute on this Linux host.
            (stage / 'customize-base.sh').write_text("printf 'BASE_INSTALLER_ENTERED\\n'\nexit 0\n")
            for tree in ['modules', 'modules_update']:
                (root / tree).mkdir()
                if existing_new:
                    (root / tree / MODULE_ID).mkdir()
            if legacy_root:
                legacy = root / legacy_root / 'mosey-plk110-cn'
                if dangling:
                    legacy.symlink_to(root / 'missing-module')
                else:
                    legacy.mkdir()
                    if marker:
                        (legacy / marker).touch()
            source = (ROOT / 'experiments/registration-compat/module/customize.sh').read_text()
            source = source.replace('/data/adb/', str(root) + '/')
            command = 'abort() { printf "%s\\n" "$*" >&2; exit 77; }\n' + source
            result = subprocess.run(['/bin/sh', '-c', command],
                                    env=os.environ | {'MODPATH': str(stage)},
                                    capture_output=True, text=True, timeout=10)
            if legacy_root:
                self.assertTrue(legacy.exists() or legacy.is_symlink(), 'Installer must preserve the old module')
            return result

    def test_fresh_install_and_same_id_update_reach_base_checks(self):
        for existing_new in [False, True]:
            with self.subTest(existing_new=existing_new):
                result = self.installer_check(existing_new=existing_new)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('BASE_INSTALLER_ENTERED', result.stdout)

    def test_legacy_active_pending_disabled_or_removing_module_blocks_install(self):
        for tree in ['modules', 'modules_update']:
            for marker in [None, 'disable', 'remove']:
                with self.subTest(tree=tree, marker=marker):
                    result = self.installer_check(tree, marker)
                    self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                    self.assertNotIn('BASE_INSTALLER_ENTERED', result.stdout)
                    self.assertIn('Uninstall the old mosey-plk110-cn module and reboot', result.stderr)

    def test_dangling_legacy_module_link_also_blocks_install(self):
        result = self.installer_check('modules', dangling=True)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertNotIn('BASE_INSTALLER_ENTERED', result.stdout)

    def test_previously_verified_registration_release_is_retained(self):
        missing = [name for name in RETAINED_RELEASES if not (ASSETS / 'dist' / name).is_file()]
        if missing:
            self.skipTest('Historical release regression requires externally retained KSU ZIP/source archives.')
        for name, expected in RETAINED_RELEASES.items():
            with self.subTest(artifact=name):
                path = ASSETS / 'dist' / name
                self.assertTrue(path.is_file(), name)
                self.assertEqual(digest(path.read_bytes()), expected)


@unittest.skipUnless((ASSETS / 'dist' / OUTPUT).is_file(), 'Optional local registration ZIP is absent; no build is started')
class RegistrationPackageTests(unittest.TestCase):
    def setUp(self):
        self.archive = zipfile.ZipFile(ASSETS / 'dist' / OUTPUT)
        self.addCleanup(self.archive.close)

    def test_exact_eleven_targets_and_unchanged_originals(self):
        mounted = {'system/' + path for path in DONOR} | {LAUNCHER, PROBE, PROBE_LIBRARY, LIBRARY}
        self.assertEqual({p for p in self.archive.namelist() if p.startswith('system/')}, mounted)
        for name, expected in DONOR.items():
            self.assertEqual(digest(self.archive.read('system/' + name)), expected, name)
        self.assertEqual(digest(self.archive.read(LAUNCHER)), LAUNCHER_SHA)
        self.assertEqual(digest(self.archive.read('sepolicy.rule')), SEPOLICY_SHA)
        self.assertEqual(self.archive.read('load-probe.sh'),
                         (ROOT / 'experiments/load-probe/module/load-probe.sh').read_bytes())

    def test_non_generated_payload_delta_is_exactly_v070_release_sync(self):
        generated = {'module.prop', 'provenance.json', 'payload.sha256'}
        # 0.7.0 changes only the shared release identity and the packaged
        # handoff. All executable payload remains byte-identical to 0.6.7.
        allowed_changes = {'README.md'}
        previous_path = ASSETS / 'dist' / 'moseyPLK.service-v0.6.7.zip'
        if not previous_path.is_file():
            self.skipTest('Historical payload comparison requires the externally retained v0.6.7 ZIP.')
        with zipfile.ZipFile(previous_path) as previous:
            current_names = set(self.archive.namelist()) - generated
            previous_names = set(previous.namelist()) - generated
            self.assertEqual(current_names, previous_names)
            changed = {name for name in current_names
                       if self.archive.read(name) != previous.read(name)}
            self.assertEqual(changed, allowed_changes)

    def test_source_archive_matches_the_publication_allowlist(self):
        path = ASSETS / 'dist' / f'{MODULE_ID}-v{VERSION}-sources.zip'
        self.assertTrue(path.is_file())
        with zipfile.ZipFile(path) as sources:
            expected = source_files(root=ROOT)
            self.assertEqual(sources.namelist(), [name for name, _ in expected])
            for name, source in expected:
                self.assertEqual(sources.read(name), source.read_bytes(), name)

    def test_previously_verified_probe_binaries_are_identical(self):
        # Known bytes from the v0.4.2.1 device-verified artifact. A clean build
        # does not need to retain the old distribution ZIP just to compare them.
        expected = {
            PROBE: 'f736d6e9048ed0d80c3211fed3d2d159c347a017d5666be6104472596fb8ed9d',
            PROBE_LIBRARY: '49a82dcf873cadb5f78a01d698b6f6bef5067c07dbd362e5e463b1f583d2d671',
        }
        for path, checksum in expected.items():
            self.assertEqual(digest(self.archive.read(path)), checksum, path)

    def test_manifest_covers_every_installed_file(self):
        recorded = set()
        for line in self.archive.read('payload.sha256').decode().splitlines():
            expected, path = line.split('  ', 1)
            self.assertNotIn(path, recorded)
            recorded.add(path)
            self.assertEqual(digest(self.archive.read(path)), expected, path)
        installed = {p for p in self.archive.namelist()
                     if not p.startswith('META-INF/') and p != 'payload.sha256'}
        self.assertEqual(recorded, installed)

    def test_packaged_scripts_match_the_reviewed_sources(self):
        for file in (ROOT / 'experiments/registration-compat/module').iterdir():
            if file.is_file():
                self.assertEqual(self.archive.read(file.name), file.read_bytes(), file.name)
        self.assertEqual(self.archive.read('collect-registration-readonly.sh'),
                         (ROOT / 'scripts/collect-registration-readonly.sh').read_bytes())

    def manager_check(self, mutation=None):
        with tempfile.TemporaryDirectory(prefix='mosey-registration-extract-') as directory:
            self.assertIn('META-INF/com/google/android/update-binary', self.archive.namelist())
            self.assertIn('META-INF/com/google/android/updater-script', self.archive.namelist())
            for path in self.archive.namelist():
                if not path.startswith('META-INF/'):
                    self.archive.extract(path, directory)
            if mutation:
                file = Path(directory) / LIBRARY
                if mutation == 'missing':
                    file.unlink()
                else:
                    file.write_bytes(file.read_bytes() + b'corrupt')
            return subprocess.run(['/bin/sh', '-c', '. ./common.sh\nmosey_check_payload'],
                                  cwd=directory, env=os.environ | {'MODDIR': directory},
                                  capture_output=True, text=True, timeout=10)

    def test_manager_extraction_and_corruption_detection(self):
        result = self.manager_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for mutation in ['missing', 'corrupt']:
            with self.subTest(mutation=mutation):
                result = self.manager_check(mutation)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'{LIBRARY}: FAILED', result.stdout + result.stderr)

    def test_experiment_metadata_and_file_modes(self):
        props = self.archive.read('module.prop').decode()
        self.assertIn(f'id={MODULE_ID}\n', props)
        self.assertIn(f'version=v{VERSION}\n', props)
        self.assertIn(f'versionCode={VERSION_CODE}\n', props)
        self.assertIn('description=[⚪ Unknown] Native Mosey service for PLK110.\n', props)
        provenance = json.loads(self.archive.read('provenance.json'))
        self.assertEqual(provenance['module_id'], MODULE_ID)
        self.assertEqual(provenance['version_code'], VERSION_CODE)
        self.assertTrue(provenance['starts_donor'])
        for key in ['client_adaptation', 'component_state_changes', 'database_changes',
                    'system_library_replacement', 'servicemanager_injection', 'device_registration_tested']:
            self.assertFalse(provenance[key], key)
        self.assertEqual(provenance['manager_status'], {
            'preferred_field': 'temporary module config override.description',
            'fallback_field': 'module.prop:description', 'poll_interval_seconds': 30,
            'binder_probe': 'passive service list', 'device_tested': False, 'webui': False,
        })
        self.assertEqual(provenance['runtime_mutable_files'], ['module.prop'])
        self.assertEqual(provenance['payload_checksum_phase'],
                         'installer extraction, before runtime status updates')
        self.assertNotIn('action.sh', self.archive.namelist())
        self.assertNotIn('action.sh', self.archive.read('customize-base.sh').decode())
        self.assertEqual(provenance['control']['signal'], 'pidfd SIGTERM only')
        self.assertEqual(provenance['control']['public_start_preflight'], {
            'caller_mount_namespace': 'must match init',
            'observed_state': 'exactly Stopped',
            'unknown_is_stopped': False,
        })
        self.assertEqual(provenance['boot_start'], {
            'entrypoint': 'service.sh',
            'registration_command': 'registration-compat.sh service 180',
            'registration_budget_seconds': 180,
            'readiness_retry_window_seconds': 60,
            'bounded_queries_seconds': {'package': 8, 'binder': 5},
            'query_timeouts_are_independent': True,
            'complete_binder_list_required': True,
            'system_server_identity_rechecked_after_queries': True,
            'payload_mount_views': ['caller', 'init', 'system_server'],
            'caller_mount_namespace_may_differ_from_init': True,
            'uses_public_control_start': False,
            'shared_control_lock': True,
            'restarts_system_processes': False,
            'device_tested': False,
        })
        self.assertEqual((self.archive.getinfo('mosey_service_control').external_attr >> 16) & 0o777, 0o755)
        self.assertNotIn('post-fs-data.sh', self.archive.namelist())
        self.assertFalse(any(path.startswith('webroot/') for path in self.archive.namelist()))
        self.assertEqual((self.archive.getinfo(PROBE).external_attr >> 16) & 0o777, 0o755)
        self.assertEqual((self.archive.getinfo(LIBRARY).external_attr >> 16) & 0o777, 0o644)
        for script in ['status-monitor.sh', 'status-checks.sh']:
            self.assertEqual((self.archive.getinfo(script).external_attr >> 16) & 0o777, 0o755, script)

    @unittest.skipUnless(shutil.which('readelf'), 'Host readelf required; ARM code is not executed')
    def test_compat_library_has_only_versioned_interposer_export(self):
        with tempfile.TemporaryDirectory(prefix='mosey-registration-elf-') as directory:
            elf = Path(directory) / 'compat.so'
            elf.write_bytes(self.archive.read(LIBRARY))
            data = elf.read_bytes()
            self.assertEqual(data[:6], b'\x7fELF\x02\x01')
            self.assertEqual(int.from_bytes(data[18:20], 'little'), 183)
            symbols = subprocess.check_output(['readelf', '--dyn-syms', '-W', str(elf)], text=True)
            exports = [line.split()[-1] for line in symbols.splitlines()
                       if ' FUNC ' in line and ' GLOBAL ' in line and ' UND ' not in line]
            self.assertEqual(exports, ['AServiceManager_addService@@LIBBINDER_NDK'])
            dynamic = subprocess.check_output(['readelf', '-d', str(elf)], text=True)
            needed = '\n'.join(line for line in dynamic.splitlines() if '(NEEDED)' in line)
            for name in ['libbinder', 'libc++', 'libmosey_daemon_ffi', 'libmosey_load_probe']:
                self.assertNotIn(name, needed)


if __name__ == '__main__':
    unittest.main(verbosity=2)
