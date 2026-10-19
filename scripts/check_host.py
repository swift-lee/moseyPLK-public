#!/usr/bin/env python3
"""Run the public host checks in sequence; never fetch assets, build an APK or use ADB."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from project_paths import ASSETS, ROOT

CHECKS = (
    ('publication-files', ('scripts/check_public.py',)),
    ('documentation', ('scripts/check_harness.py',)),
    ('publication', ('scripts/test_public_sources.py',)),
    ('build-inputs', ('scripts/test_public_build_inputs.py',)),
    ('firmware-extraction', ('scripts/test_firmware_extraction.py',)),
    ('startup-collector', ('scripts/test_gms_startup_collector.py',)),
    ('load-probe-workflow', ('scripts/test_load_probe.py', 'LoadProbeWorkflowTests')),
    ('registration-startup', ('scripts/test_registration_startup.py',)),
    ('module-status', ('scripts/test_module_status.py',)),
    ('service-control', ('scripts/test_service_control.py',)),
    ('hook-state', ('scripts/test_hook_state.py',)),
    ('gms-observer', ('scripts/test_gms_observer.py',)),
    ('native-load-probe', ('native/load-probe/test_host.py',)),
    ('native-registration', ('native/registration-compat/test_host.py',)),
)
BUSYBOX_CHECKS = ('scripts/test_load_probe.py', 'scripts/test_registration_startup.py',
                  'scripts/test_module_status.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logs-dir', type=Path, help='New directory for host-only reports')
    parser.add_argument('--busybox', type=Path, help='Also run shell fixtures with this BusyBox ash')
    args = parser.parse_args()
    for tool in ('java', os.environ.get('CC', 'cc'), 'readelf', 'sh'):
        if shutil.which(tool) is None:
            raise SystemExit('Missing host test dependency: ' + tool)
    if args.busybox and not args.busybox.is_file():
        raise SystemExit('Missing BusyBox executable')
    if args.logs_dir:
        logs = args.logs_dir.resolve()
        logs.mkdir(parents=True, exist_ok=False)
    else:
        parent = ASSETS / 'build/public-host-checks'
        parent.mkdir(parents=True, exist_ok=True)
        logs = Path(tempfile.mkdtemp(prefix='run-', dir=parent))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    env.pop('PYTHONOPTIMIZE', None)
    env.pop('MOSEY_TEST_BUSYBOX', None)
    jobs = [(label, arguments, {}) for label, arguments in CHECKS]
    if args.busybox:
        for name in BUSYBOX_CHECKS:
            arguments = (name, 'LoadProbeWorkflowTests') if 'test_load_probe' in name else (name,)
            jobs.append((Path(name).stem + '-ash', arguments,
                         {'MOSEY_TEST_BUSYBOX': str(args.busybox.resolve())}))
    results = []
    for label, arguments, overrides in jobs:
        started = time.monotonic()
        command = [sys.executable, '-B', *arguments]
        try:
            result = subprocess.run(command, cwd=ROOT, env=env | overrides,
                                    capture_output=True, text=True, timeout=300)
            output, code = result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            output = 'Host test exceeded 300 seconds.\n'
            output += (error.stdout or b'').decode(errors='replace') if isinstance(error.stdout, bytes) else (error.stdout or '')
            output += (error.stderr or b'').decode(errors='replace') if isinstance(error.stderr, bytes) else (error.stderr or '')
            code = 124
        (logs / (label + '.txt')).write_text(output, encoding='utf-8')
        results.append({'check': label, 'command': list(arguments), 'returncode': code,
                        'seconds': round(time.monotonic() - started, 3)})
        print(('PASS ' if code == 0 else 'FAIL ') + label, flush=True)
    summary = {'host_only': True, 'device_tested': False, 'results': results}
    (logs / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('Host reports: ' + str(logs))
    if any(result['returncode'] != 0 for result in results):
        raise SystemExit(1)
    print(f'All {len(results)} host check commands passed. Inspect reports for asset-specific skips.')


if __name__ == '__main__':
    main()
