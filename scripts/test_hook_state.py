#!/usr/bin/env python3
"""Host-only tests of real bounded snapshot persistence and independent hook logging."""
import json
from pathlib import Path
import tempfile
import textwrap
from test_gms_observer import STUBS
from project_paths import BUILD_ROOT
from test_gms_adaptive import SOURCE, FIXTURES, TESTS, compile_java, run_java


def main():
    output = []
    with tempfile.TemporaryDirectory(prefix='mosey-hook-state-') as temporary:
        stage = Path(temporary)
        sources = [SOURCE / (name + '.java') for name in ('HookLog', 'HookStateStore', 'HookTelemetry', 'MoseyHook', 'ClientPolicy', 'RecoverySchedule')]
        stubs = FIXTURES / 'runtime-stubs'
        for group in ('android', 'de/robv/android/xposed'):
            sources.extend(sorted((stubs / group).rglob('*.java')))
        sources.extend([stubs / 'moseyPLK/client/ModuleBuild.java', TESTS / 'HookStateTest.java',
                        TESTS / 'MoseyHookStateTest.java'])
        helper = stage / 'XposedHelpers.java'
        helper.write_text(textwrap.dedent(STUBS['de/robv/android/xposed/XposedHelpers.java']))
        sources.append(helper)
        compile_java(sources, stage / 'classes', output)
        work = stage / 'work'
        work.mkdir()
        try:
            run_java(stage / 'classes', 'HookStateTest', [work], output)
        except Exception:
            print(''.join(output), end='')
            raise
        data = json.loads((work / 'adapter/adapter-result.json').read_text())
        assert data['schema'] == 1 and data['targetPackage'] == 'com.google.android.gms'
        assert data['installation'] == 'active' and data['resolution'] == 'verified'
        assert data['naturalHit'] is True and isinstance(data['starttime'], int)
        assert data['starttime'] > 0 and data['bootCount'] == 1
        output.append('PASS independent JSON parser and process identity shape\n')
        mosey = stage / 'mosey'
        mosey.mkdir()
        try:
            run_java(stage / 'classes', 'MoseyHookStateTest', [mosey], output)
        except Exception:
            print(''.join(output), end='')
            raise
    result = ''.join(output)
    destination = BUILD_ROOT / 'client-compat-v0.6.0/hook-state-tests.txt'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(result)
    print(result, end='')


if __name__ == '__main__':
    main()
