#!/usr/bin/env python3
"""Host-only parser and loader-contract tests. No phone access."""
import os
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent


def run(command, **kwargs):
    return subprocess.run(command, check=True, text=True, capture_output=True, **kwargs)


def fields(result):
    lines = result.stdout.splitlines()
    assert all("=" in line for line in lines), result.stdout
    pairs = [line.split("=", 1) for line in lines]
    assert len({key for key, _ in pairs}) == len(pairs), result.stdout
    return dict(pairs)


def main():
    with tempfile.TemporaryDirectory(prefix="mosey-probe-host-") as temporary:
        build = Path(temporary)
        compiler = os.environ.get("CC", "cc")
        common = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wconversion", "-Wshadow", "-Wpedantic"]
        parser_test = build / "test_parse"
        run(common + [str(SOURCE / "probe_parse.c"), str(SOURCE / "test_parse.c"), "-o", str(parser_test)])
        print(run([str(parser_test)]).stdout.strip())
        library = build / "libmosey_load_probe.so"
        wrong_library = build / "wrong-marker-source.so"
        probe = build / "mosey_load_probe"
        macro = '-DMOSEY_PROBE_EXPECTED_LIBRARY="' + str(library) + '"'
        run(common + ["-fPIC", "-shared", "-fvisibility=hidden", str(SOURCE / "marker.c"), "-o", str(library)])
        wrong_library.write_bytes(library.read_bytes())
        run(common + [macro, str(SOURCE / "probe.c"), str(SOURCE / "probe_parse.c"), "-ldl", "-o", str(probe)])
        environment = os.environ.copy()
        environment.pop("LD_PRELOAD", None)
        result = subprocess.run([str(probe), "baseline"], env=environment, text=True, capture_output=True)
        data = fields(result)
        assert result.returncode in (10, 12), data
        assert data["IDENTITY_OK"] == "0", data
        assert data["MARKER_FOUND"] == "NOT_CHECKED", data
        assert data["LD_PRELOAD_EXPECTED"] == "0", data

        result = subprocess.run([str(probe), "preload"], env=environment, text=True, capture_output=True)
        data = fields(result)
        assert result.returncode in (10, 12), data
        assert data["MARKER_FOUND"] == "0", data
        assert data["MARKER_INITIALIZED"] == "0", data

        environment["LD_PRELOAD"] = str(library)
        result = subprocess.run([str(probe), "preload"], env=environment, text=True, capture_output=True)
        data = fields(result)
        assert result.returncode in (10, 12), data  # Correct loading cannot override wrong host identity.
        assert data["LD_PRELOAD_EXPECTED"] == "1", data
        assert data["MARKER_FOUND"] == data["MARKER_ORIGIN_EXPECTED"] == data["MARKER_INITIALIZED"] == "1", data

        environment["LD_PRELOAD"] = str(wrong_library)
        result = subprocess.run([str(probe), "preload"], env=environment, text=True, capture_output=True)
        data = fields(result)
        assert result.returncode in (10, 12), data
        assert data["MARKER_FOUND"] == "1", data
        assert data["MARKER_ORIGIN_EXPECTED"] == data["MARKER_INITIALIZED"] == "0", data
        assert data["LD_PRELOAD_EXPECTED"] == "0", data

        for arguments in ([], ["unknown"], ["baseline", "unexpected"]):
            result = subprocess.run([str(probe), *arguments], env=environment, text=True, capture_output=True)
            assert result.returncode == 64 and fields(result)["RESULT"] == "USAGE_ERROR"
        print("host loader contract: 7 scenarios passed")


if __name__ == "__main__":
    main()
