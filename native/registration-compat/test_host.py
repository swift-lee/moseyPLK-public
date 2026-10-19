#!/usr/bin/env python3
"""Real host LD_PRELOAD/versioned-symbol tests with a fake Binder ABI.

Credentials are simulated in a separate host-only object; the production
identity reader/predicate is also exercised without any simulated credentials.
No Android Binder, phone access, privileged execution, or system writes.
"""
import errno
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent
PARSER = SOURCE.parent / 'load-probe' / 'probe_parse.c'


def run(command, **kwargs):
    result = subprocess.run(command, text=True, capture_output=True, **kwargs)
    assert result.returncode == 0, (command, result.stdout, result.stderr)
    return result


def main():
    with tempfile.TemporaryDirectory(prefix='mosey-registration-host-') as temporary:
        build = Path(temporary)
        common = [os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-Wall', '-Wextra',
                  '-Werror', '-Wconversion', '-Wshadow', '-Wpedantic']
        identity_test = build / 'test_identity'
        run(common + [str(SOURCE / 'identity.c'), str(SOURCE / 'test_identity.c'),
                      str(PARSER), '-o', str(identity_test)])
        print(run([str(identity_test)]).stdout.strip())

        library = build / 'libbinder_ndk.so'
        app = build / 'mosey_server'
        shim = build / 'libmosey_registration_compat.so'
        macros = ['-DMOSEY_REGCOMPAT_EXPECTED_EXE="' + str(app) + '"',
                  '-DMOSEY_REGCOMPAT_BINDER_LIBRARY="' + str(library) + '"',
                  '-DMOSEY_REGCOMPAT_EXPECTED_LIBRARY="' + str(shim) + '"']
        variants = {}
        for missing in [None, 'ADD', 'REMOTE', 'CLASS', 'DESCRIPTOR', 'DOWNGRADE']:
            label = missing or 'complete'
            path = build / f'binder-{label}.so'
            run(common + ['-fPIC', '-shared'] + ([f'-DOMIT_{missing}'] if missing else []) +
                [str(SOURCE / 'fixture_binder.c'), '-Wl,-soname,libbinder_ndk.so',
                 '-Wl,--version-script=' + str(SOURCE / 'fixture.map'), '-o', str(path)])
            variants[label] = path
        wrong_map = build / 'wrong-version.map'
        wrong_map.write_text((SOURCE / 'fixture.map').read_text().replace('LIBBINDER_NDK31', 'WRONG_VERSION'))
        variants['VERSION'] = build / 'binder-VERSION.so'
        run(common + ['-fPIC', '-shared', str(SOURCE / 'fixture_binder.c'),
                      '-Wl,-soname,libbinder_ndk.so', '-Wl,--version-script=' + str(wrong_map),
                      '-o', str(variants['VERSION'])])
        shutil.copyfile(variants['complete'], library)
        run(common + [str(SOURCE / 'fixture_app.c'), '-L' + str(build), '-lbinder_ndk',
                      '-Wl,-rpath,' + str(build), '-o', str(app)])
        identity_object = build / 'identity.o'
        run(common + macros + ['-fPIC', '-fvisibility=hidden',
            '-Dregcompat_read_identity=regcompat_read_identity_actual',
            '-Dregcompat_target_executable=regcompat_target_executable_actual',
            '-c', str(SOURCE / 'identity.c'), '-o', str(identity_object)])
        run(common + macros + ['-DMOSEY_REGCOMPAT_HOST_TEST', '-fPIC', '-shared',
            '-fvisibility=hidden', str(SOURCE / 'compat.c'), str(SOURCE / 'fixture_identity.c'),
            str(identity_object), str(PARSER), '-ldl', '-pthread', '-Wl,--no-undefined',
            '-Wl,--version-script=' + str(SOURCE / 'exports.map'), '-o', str(shim)])
        symbols = run(['readelf', '--dyn-syms', '--wide', str(shim)]).stdout
        assert 'AServiceManager_addService@@LIBBINDER_NDK' in symbols, symbols
        assert 'AServiceManager_addService@LIBBINDER_NDK' in run(
            ['readelf', '--dyn-syms', '--wide', str(app)]).stdout
        assert 'regcompat_read_identity' not in symbols and 'fixture_' not in symbols

        environment = os.environ.copy()
        for name in list(environment):
            if name.startswith('HOST_') or name in ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'MOSEY_REGISTRATION_COMPAT']:
                environment.pop(name)
        environment.update(LD_PRELOAD=str(shim), LD_BIND_NOW='1', MOSEY_REGISTRATION_COMPAT='1')
        scenarios = 0

        def execute(mode='ok', *, binary=app, variant='complete', **changes):
            nonlocal scenarios
            shutil.copyfile(variants[variant], library)
            env = environment | {key: value for key, value in changes.items() if value is not None}
            for key, value in changes.items():
                if value is None:
                    env.pop(key, None)
            result = run([str(binary), mode], env=env)
            events = []
            for line in result.stderr.splitlines():
                assert line.startswith('MOSEY_REGCOMPAT '), result.stderr
                pairs = [item.split('=', 1) for item in line.split()[1:]]
                assert len({key for key, _ in pairs}) == len(pairs), line
                events.append(dict(pairs))
            assert len({event['pid'] for event in events}) <= 1
            stats = [line for line in result.stdout.splitlines() if line.startswith('FIXTURE adds=')]
            data = dict(item.split('=', 1) for item in stats[0].split()[1:]) if stats else {}
            if data:
                assert data['order_error'] == '0', result.stdout
            scenarios += 1
            return result, events, data

        def event_rows(events, name):
            return [event for event in events if event['event'] == name]

        def blocked(mode='ok', **kwargs):
            result, events, data = execute(mode, **kwargs)
            assert data['adds'] == data['downgrades'] == '0', result.stdout
            end, = event_rows(events, 'add_result')
            assert end['target'] == '1' and end['called'] == end['downgraded'] == '0' and end['source'] == 'shim', events
            assert end['code'] == '-5' and event_rows(events, 'blocked'), events
            assert not event_rows(events, 'downgrade'), events
            assert f'FIXTURE returned=-5 errno={errno.EDOM}' in result.stdout, result.stdout
            return result, events, data

        result, events, data = execute()
        assert data == dict(adds='1', remotes='1', classes='1', descriptors='1', downgrades='1', order_error='0'), result.stdout
        assert [row['event'] for row in events] == ['loaded', 'intercept', 'identity', 'api', 'binder', 'downgrade', 'downgrade', 'add_result'], events
        assert event_rows(events, 'loaded')[0]['origin_expected'] == '1'
        assert event_rows(events, 'api')[0]['source'] == str(library)
        assert event_rows(events, 'identity')[0]['ok'] == '1'
        assert event_rows(events, 'add_result')[0]['code'] == '0'
        assert event_rows(events, 'add_result')[0]['source'] == 'platform'
        assert f'FIXTURE returned=0 errno={errno.EBUSY}' in result.stdout
        assert result.stdout.index('FIXTURE event=downgrade') < result.stdout.index('FIXTURE event=add')

        result, events, data = execute('failure')
        assert data['adds'] == data['downgrades'] == '1'
        assert event_rows(events, 'add_result')[0]['code'] == '-129'
        assert f'FIXTURE returned=-129 errno={errno.EBUSY}' in result.stdout

        for mode in ['remote', 'null', 'descriptor', 'class', 'null_descriptor']:
            _, _, data = blocked(mode)
            if mode in ['remote', 'null']:
                assert data['classes'] == data['descriptors'] == '0'
            if mode == 'class':
                assert data['descriptors'] == '0'
        for fault in ['uid', 'gid', 'caps', 'inet', 'selinux', 'read', 'real']:
            _, _, data = blocked(HOST_IDENTITY_FAULT=fault)
            assert data['remotes'] == data['classes'] == data['descriptors'] == '0'
        for variant in ['ADD', 'REMOTE', 'CLASS', 'DESCRIPTOR', 'DOWNGRADE', 'VERSION']:
            blocked(variant=variant)

        for value in [None, '0', '01', '1 ']:
            _, events, data = execute(MOSEY_REGISTRATION_COMPAT=value)
            assert data['adds'] == '1' and data['downgrades'] == data['remotes'] == '0'
            assert not events
        for mode in ['name', 'null_name']:
            _, events, data = execute(mode)
            assert data['adds'] == '1' and data['downgrades'] == data['remotes'] == '0'
            assert [row['event'] for row in events] == ['loaded']

        launcher = build / 'mosey_launcher'
        shutil.copyfile(app, launcher)
        launcher.chmod(0o755)
        for mode in ['ok', 'loadonly']:
            _, events, data = execute(mode, binary=launcher)
            assert not events
            if data:
                assert data['adds'] == '1' and data['downgrades'] == data['remotes'] == '0'
        # Launcher-like executable without any Binder dependency must still load.
        result = run(['/bin/true'], env=environment)
        assert result.stdout == result.stderr == ''
        scenarios += 1
        _, events, data = execute('loadonly')
        assert not data and [row['event'] for row in events] == ['loaded']

        other = build / 'other-origin'
        other.mkdir()
        shutil.copyfile(variants['complete'], other / 'libbinder_ndk.so')
        blocked(LD_LIBRARY_PATH=str(other))
        other_shim = other / shim.name
        shutil.copyfile(shim, other_shim)
        _, events, _ = blocked(LD_PRELOAD=str(other_shim))
        assert event_rows(events, 'loaded')[0]['origin_expected'] == '0'
        # A following preload with the same versioned APIs is rejected by dladdr.
        blocked(LD_PRELOAD=str(shim) + ':' + str(other / 'libbinder_ndk.so'))

        _, events, data = execute('twice')
        assert data['adds'] == data['downgrades'] == '2'
        assert len(event_rows(events, 'add_result')) == 2
        print(f'registration versioned LD_PRELOAD: {scenarios} scenarios passed')


if __name__ == '__main__':
    main()
