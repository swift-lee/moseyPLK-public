#!/usr/bin/env python3
"""Check public Markdown links against the publication set, without Git or ADB."""
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

from project_paths import ROOT
from public_sources import source_files

REQUIRED = {
    'README.md', 'AGENTS.md', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md',
    'docs/README.md', 'docs/current-state.md', 'docs/workflow.md',
    'docs/architecture.md', 'docs/build.md', 'docs/gms-configuration.md',
    'docs/testing.md', 'docs/publication.md', 'docs/verification.md',
}
LINK = re.compile(r'\[[^\]\n]+\]\((<[^>\n]+>|[^\s]+?)(?:\s+"[^"\n]*")?\)')


def check(root=ROOT):
    root = Path(root).resolve()
    entries = dict(source_files(root))
    errors = ['Missing public entry: ' + name for name in sorted(REQUIRED - entries.keys())]
    documents = links = 0
    for name, path in entries.items():
        if path.suffix != '.md':
            continue
        documents += 1
        fence = None
        for lineno, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            marker = re.match(r'^\s*(`{3,}|~{3,})', line)
            if marker:
                value = marker.group(1)
                if fence is None:
                    fence = value
                elif value[0] == fence[0] and len(value) >= len(fence):
                    fence = None
                continue
            if fence:
                continue
            for match in LINK.finditer(line):
                parts = urlsplit(match.group(1).strip('<>'))
                if parts.scheme or parts.netloc or not parts.path:
                    continue
                links += 1
                target = (path.parent / unquote(parts.path)).resolve()
                if not target.is_relative_to(root) or target.relative_to(root).as_posix() not in entries:
                    errors.append(f'Unpublished local link: {name}:{lineno}')
    return documents, links, errors


def main():
    documents, links, errors = check()
    print(f'Checked {documents} public Markdown files and {links} local links.')
    for error in errors:
        print('ERROR ' + error)
    if errors:
        raise SystemExit(1)
    print('Public documentation paths OK; remote URLs, anchors and device behavior are not checked.')


if __name__ == '__main__':
    main()
