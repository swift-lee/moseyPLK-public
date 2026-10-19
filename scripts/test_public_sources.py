#!/usr/bin/env python3
"""Host-only publication tests; all fixtures are synthetic temporary files."""
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from check_public import check
from public_sources import MANIFEST, archive_sources, source_files


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='mosey-public-tests-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'tree'
        self.root.mkdir()
        (self.root / 'README.md').write_text('Synthetic public source.\n')
        self.manifest(['README.md', MANIFEST])

    def manifest(self, names):
        (self.root / MANIFEST).write_text(json.dumps({'schema': 1, 'files': sorted(names)}))

    def test_archive_matches_manifest_and_ignores_private_work_area(self):
        assets = self.root / 'moseyPLK-assets'
        assets.mkdir()
        (assets / 'synthetic.db').write_bytes(b'\0not real device data')
        output = Path(self.temporary.name) / 'sources.zip'
        archive_sources(output, self.root)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.namelist(), ['README.md', MANIFEST])
            self.assertEqual(archive.read('README.md'), (self.root / 'README.md').read_bytes())
        self.assertEqual(check(self.root)[1], [])
        self.assertTrue(check(self.root, strict=True)[1])

    def test_unknown_file_is_rejected(self):
        (self.root / 'unexpected.txt').write_text('unreviewed')
        self.assertEqual(check(self.root, strict=True)[1], ['Unreviewed file: unexpected.txt'])

    def test_traversal_and_restricted_paths_are_rejected(self):
        for name in ('../outside.txt', '/absolute.txt', 'a/../escape.txt', 'a//b.txt',
                     'moseyPLK-assets/input.xml', 'reference-zfold6/service.sh',
                     '.aws/config', 'module-src/sepolicy.rule', 'vendor.apk', 'secret.pem'):
            with self.subTest(name=name):
                self.manifest([MANIFEST, name])
                with self.assertRaises(ValueError):
                    source_files(self.root)

    def test_symlink_file_and_ancestor_are_rejected(self):
        outside = Path(self.temporary.name) / 'outside'
        outside.mkdir()
        (outside / 'source.txt').write_text('outside')
        (self.root / 'linked.txt').symlink_to(outside / 'source.txt')
        self.manifest([MANIFEST, 'linked.txt'])
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            source_files(self.root)
        (self.root / 'linked.txt').unlink()
        (self.root / 'linked').symlink_to(outside, target_is_directory=True)
        self.manifest([MANIFEST, 'linked/source.txt'])
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            source_files(self.root)

    def test_binary_and_non_utf8_are_rejected(self):
        for data in (b'ELF\0fixture', b'\xff\xfe'):
            (self.root / 'README.md').write_bytes(data)
            with self.assertRaises(ValueError):
                source_files(self.root)

    def test_private_material_is_rejected_without_echoing_it(self):
        material = '-----BEGIN ' + 'PRIVATE KEY-----\nsynthetic fixture only\n'
        (self.root / 'README.md').write_text(material)
        with self.assertRaisesRegex(ValueError, 'Potential credential') as failure:
            source_files(self.root)
        self.assertNotIn(material, str(failure.exception))

    def test_duplicates_and_missing_files_are_rejected(self):
        self.manifest([MANIFEST, MANIFEST])
        with self.assertRaisesRegex(ValueError, 'sorted, unique'):
            source_files(self.root)
        self.manifest([MANIFEST, 'missing.txt'])
        with self.assertRaises(FileNotFoundError):
            source_files(self.root)

    def test_archive_cannot_overwrite_its_own_source(self):
        with self.assertRaisesRegex(ValueError, 'overwrite'):
            archive_sources(self.root / 'README.md', self.root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
