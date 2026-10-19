#!/usr/bin/env python3
"""Host-only failure-boundary checks for preparing local firmware assets."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import extract_firmware as extractor


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='mosey-extraction-test-')
        self.root = Path(self.temporary.name)
        self.assets = self.root / 'assets'
        self.assets.mkdir()
        self.override = patch.object(extractor, 'ASSETS', self.assets)
        self.override.start()

    def tearDown(self):
        self.override.stop()
        self.temporary.cleanup()

    def test_output_cannot_escape_assets_or_follow_symlink(self):
        for relative in ('../outside', '/absolute'):
            with self.assertRaises(ValueError):
                extractor.destination(relative)
        (self.assets / 'escape').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            extractor.destination('escape/outside')
        (self.assets / 'dangling').symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError):
            extractor.destination('dangling')

    def test_bad_existing_input_is_rejected_without_overwriting(self):
        original = self.assets / 'input'
        original.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            extractor.missing_inputs('.', {'input': hashlib.sha256(b'expected').hexdigest()})
        self.assertEqual(original.read_bytes(), b'changed')

    def test_verified_input_is_reused_and_missing_input_reported(self):
        (self.assets / 'input').write_bytes(b'expected')
        digest = hashlib.sha256(b'expected').hexdigest()
        self.assertEqual(extractor.missing_inputs('.', {'input': digest, 'absent': digest}), ['absent'])

    def test_publication_refuses_replacement_and_preserves_executable_mode(self):
        staged = self.root / 'file-0'
        staged.write_bytes(b'new')
        extractor.publish(staged, 'reference/service.sh')
        result = self.assets / 'reference/service.sh'
        self.assertEqual(result.stat().st_mode & 0o777, 0o755)
        other = self.root / 'file-1'
        other.write_bytes(b'replacement')
        with self.assertRaises(FileExistsError):
            extractor.publish(other, 'reference/service.sh')
        self.assertEqual(result.read_bytes(), b'new')


if __name__ == '__main__':
    unittest.main(verbosity=2)
