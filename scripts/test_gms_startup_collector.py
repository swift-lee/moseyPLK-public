#!/usr/bin/env python3
"""Exercise the real read-only collector on host command fakes, never ADB."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from project_paths import ROOT


class StartupCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mosey-log-reader-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.trace = self.work / 'trace'
        fake = self.work / 'command'
        fake.write_text('''#!/bin/sh
name=${0##*/}
printf '%s' "$name" >> "$MOSEY_TEST_TRACE"
for arg do printf ' <%s>' "$arg" >> "$MOSEY_TEST_TRACE"; done
printf '\\n' >> "$MOSEY_TEST_TRACE"
case "$name" in
  id) printf '%s\\n' "${MOSEY_TEST_UID:-0}" ;;
  getprop) printf '%s\\n' "${MOSEY_TEST_MODEL:-PLK110}" ;;
  am)
    printf '%s\\n' "${MOSEY_TEST_USER:-0}"
    exit "${MOSEY_TEST_USER_RC:-0}" ;;
  timeout)
    [ "$1" = -k ] || exit 90
    shift 3
    case "$*" in
      'am get-current-user')
        [ "${MOSEY_TEST_USER_TIMEOUT_RC:-0}" = 0 ] || exit "$MOSEY_TEST_USER_TIMEOUT_RC"
        "$@" ;;
      'logcat -b main -g')
        [ "${MOSEY_TEST_CAPACITY_TIMEOUT_RC:-0}" = 0 ] || exit "$MOSEY_TEST_CAPACITY_TIMEOUT_RC"
        "$@" ;;
      *' -T 1 '*)
        "$@"
        exit "${MOSEY_TEST_READER_RC:-124}" ;;
      *) "$@" ;;
    esac ;;
  logcat)
    if [ "$*" = '-b main -g' ]; then exit "${MOSEY_TEST_CAPACITY_RC:-0}"; fi ;;
  date|cat|ps|service|dumpsys) : ;;
  pidof) exit 1 ;;
  *) exit 91 ;;
esac
''')
        fake.chmod(0o755)
        for name in ('id', 'getprop', 'am', 'timeout', 'logcat', 'date', 'cat',
                     'ps', 'service', 'dumpsys', 'pidof'):
            (self.work / name).symlink_to(fake)
        (self.work / 'grep').symlink_to('/usr/bin/grep')

    def run_collector(self, script='collect-gms-startup-readonly.sh', **extra):
        self.trace.unlink(missing_ok=True)
        env = {**os.environ, 'PATH': str(self.work),
               'MOSEY_TEST_TRACE': str(self.trace), **extra}
        result = subprocess.run(['/bin/sh', str(ROOT / 'scripts' / script)],
                                env=env, capture_output=True, text=True, timeout=5)
        calls = self.trace.read_text().splitlines() if self.trace.exists() else []
        return result, calls

    def test_duration_rejected_before_device_reads(self):
        for duration in ('0', '301', '-1', '1;reboot', 'abc', '99999999999999999999'):
            with self.subTest(duration=duration):
                result, calls = self.run_collector(MOSEY_CAPTURE_SECONDS=duration)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(calls, [])

    def test_identity_mismatch_never_starts_reader(self):
        for setting, value, code in (('MOSEY_TEST_UID', '2000', 3),
                                    ('MOSEY_TEST_MODEL', 'other', 4), ('MOSEY_TEST_USER', '999', 5)):
            with self.subTest(setting=setting):
                self.trace.unlink(missing_ok=True)
                result, calls = self.run_collector(**{setting: value})
                self.assertEqual(result.returncode, code)
                self.assertNotIn('STARTUP_CAPTURE_READY', result.stdout)
                self.assertFalse(any(row.startswith('logcat') for row in calls))
                self.assertFalse(any('<-T>' in row for row in calls))

    def test_bounded_read_only_stream_and_expected_timeout(self):
        for duration in ('1', '180', '300'):
            with self.subTest(duration=duration):
                self.trace.unlink(missing_ok=True)
                result, calls = self.run_collector(MOSEY_CAPTURE_SECONDS=duration)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'STARTUP_CAPTURE_READY duration={duration}', result.stdout)
                self.assertIn('STARTUP_CAPTURE_END reader_rc=124', result.stdout)
                reader = [row for row in calls if row.startswith('timeout') and '<-T>' in row]
                self.assertEqual(len(reader), 1)
                self.assertTrue(reader[0].startswith(f'timeout <-k> <1> <{duration}> <logcat>'))
                self.assertIn('<-T> <1>', reader[0])
                for forbidden in ('<-c>', '<-G>', '<-f>', '<start>', '<force-stop>'):
                    self.assertNotIn(forbidden, '\n'.join(calls))
                self.assertTrue(all(row.split()[0] in
                                    {'id', 'getprop', 'am', 'date', 'cat', 'logcat', 'timeout'}
                                    for row in calls))
                self.assertIn('am <get-current-user>', calls)
                self.assertIn('timeout <-k> <1> <5> <am> <get-current-user>', calls)
                self.assertIn('timeout <-k> <1> <5> <logcat> <-b> <main> <-g>', calls)

    def test_reader_failure_is_not_reported_as_success(self):
        result, _ = self.run_collector(MOSEY_TEST_READER_RC='7')
        self.assertEqual(result.returncode, 7)
        self.assertIn('STARTUP_CAPTURE_END reader_rc=7', result.stdout)

    def assert_preflight_rejected(self, code, marker, **extra):
        result, calls = self.run_collector(**extra)
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertIn(marker, result.stderr)
        self.assertNotIn('STARTUP_CAPTURE_READY', result.stdout)
        self.assertNotIn('STARTUP_CAPTURE_END', result.stdout)
        self.assertFalse(any('<-T>' in row for row in calls), calls)
        return calls

    def test_user_query_failure_cannot_pass_with_printed_user_zero(self):
        calls = self.assert_preflight_rejected(5, 'CURRENT_USER_QUERY_FAILED rc=7',
                                              MOSEY_TEST_USER='0', MOSEY_TEST_USER_RC='7')
        self.assertIn('am <get-current-user>', calls)
        self.assertFalse(any('<logcat>' in row or row.startswith('logcat') for row in calls))

    def test_user_query_timeout_never_announces_ready(self):
        for code in ('124', '137'):
            with self.subTest(timeout_rc=code):
                calls = self.assert_preflight_rejected(5, f'CURRENT_USER_QUERY_FAILED rc={code}',
                                                      MOSEY_TEST_USER_TIMEOUT_RC=code)
                self.assertIn('timeout <-k> <1> <5> <am> <get-current-user>', calls)
                self.assertNotIn('am <get-current-user>', calls)
                self.assertFalse(any('<logcat>' in row for row in calls))

    def test_capacity_query_failure_never_announces_ready(self):
        calls = self.assert_preflight_rejected(6, 'MAIN_BUFFER_CAPACITY_FAILED rc=8',
                                              MOSEY_TEST_CAPACITY_RC='8')
        self.assertIn('logcat <-b> <main> <-g>', calls)

    def test_capacity_query_timeout_never_announces_ready(self):
        for code in ('124', '137'):
            with self.subTest(timeout_rc=code):
                calls = self.assert_preflight_rejected(6, f'MAIN_BUFFER_CAPACITY_FAILED rc={code}',
                                                      MOSEY_TEST_CAPACITY_TIMEOUT_RC=code)
                self.assertIn('timeout <-k> <1> <5> <logcat> <-b> <main> <-g>', calls)
                self.assertNotIn('logcat <-b> <main> <-g>', calls)

    def test_snapshot_reports_preflight_errors_and_continues(self):
        for user_setting, capacity_setting, code in (
                ('MOSEY_TEST_USER_RC', 'MOSEY_TEST_CAPACITY_RC', '7'),
                ('MOSEY_TEST_USER_TIMEOUT_RC', 'MOSEY_TEST_CAPACITY_TIMEOUT_RC', '124'),
                ('MOSEY_TEST_USER_TIMEOUT_RC', 'MOSEY_TEST_CAPACITY_TIMEOUT_RC', '137')):
            with self.subTest(result_code=code):
                result, calls = self.run_collector('collect-client-readonly.sh',
                                                  **{user_setting: code, capacity_setting: code})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'CURRENT_USER_QUERY_FAILED rc={code}', result.stdout)
                self.assertIn(f'MAIN_BUFFER_CAPACITY_FAILED rc={code}', result.stdout)
                self.assertIn('END_CLIENT_READ_ONLY', result.stdout)
                self.assertIn('timeout <-k> <1> <5> <am> <get-current-user>', calls)
                self.assertIn('timeout <-k> <1> <5> <logcat> <-b> <main> <-g>', calls)
                self.assertTrue(any(row.startswith('dumpsys <package>') for row in calls))
                self.assertNotIn('STARTUP_CAPTURE_READY', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
