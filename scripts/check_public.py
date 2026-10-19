#!/usr/bin/env python3
"""Verify the explicit publication set and reject accidental extra files."""
import argparse
from pathlib import Path
import subprocess

from project_paths import ROOT
from public_sources import source_files

LOCAL_ONLY = {'moseyPLK-assets', '__pycache__', '.gradle', '.venv'}


def check(root=ROOT, *, strict=False):
    root = Path(root).resolve()
    entries = dict(source_files(root))
    errors = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(root)
            name = relative.as_posix()
            if relative.parts[0] == '.git' and not path.is_symlink():
                continue
            if not strict and not path.is_symlink() and (
                    relative.parts[0] in LOCAL_ONLY or '__pycache__' in relative.parts):
                continue
            if path.is_symlink():
                errors.append('Symlink outside publication set: ' + name)
            elif path.is_dir():
                pending.append(path)
            elif name not in entries:
                errors.append('Unreviewed file: ' + name)
    if (root / '.git').is_dir():
        tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
        errors.extend('Tracked file outside publication set: ' + name
                      for name in tracked if name and name not in entries)
    return len(entries), errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict', action='store_true', help='also reject local assets and caches')
    args = parser.parse_args()
    try:
        count, errors = check(strict=args.strict)
    except (ValueError, OSError) as error:
        print('ERROR ' + str(error))
        raise SystemExit(1) from None
    for error in errors:
        print('ERROR ' + error)
    if errors:
        raise SystemExit(1)
    print(f'Publication checks passed: {count} reviewed UTF-8 text files; no credential pattern found.')
    print('Automated checks supplement the recorded source and document review.')


if __name__ == '__main__':
    main()
