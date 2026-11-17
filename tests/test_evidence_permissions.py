import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from migrate_evidence_permissions import migrate


@unittest.skipUnless(os.name == 'posix', 'POSIX permission migration')
class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'evidence'
        self.root.mkdir(mode=0o755)
        self.root.chmod(0o755)
        self.file = self.root / 'raw.json'
        self.file.write_bytes(b'private evidence\x00\n')
        self.file.chmod(0o644)

    def test_dry_run_apply_idempotence_and_byte_retention(self):
        child = self.root / 'history'
        child.mkdir(mode=0o755)
        (child / 'report.html').write_text('private draft')
        before = {p.relative_to(self.root): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in self.root.rglob('*') if p.is_file()}
        self.assertFalse(migrate(self.root)['applied'])
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o644)
        self.assertTrue(migrate(self.root, True)['applied'])
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(child.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(migrate(self.root, True)['permission_changes'], 0)
        after = {p.relative_to(self.root): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_symlink_and_hardlink_refused_without_changes(self):
        outside = Path(self.temp.name) / 'outside'
        outside.write_text('untouched')
        outside.chmod(0o644)
        link = self.root / 'link'
        for hard in (False, True):
            os.link(outside, link) if hard else link.symlink_to(outside)
            with self.assertRaises((ValueError, OSError)):
                migrate(self.root, True)
            self.assertEqual(outside.stat().st_mode & 0o777, 0o644)
            self.assertEqual(self.root.stat().st_mode & 0o777, 0o755)
            link.unlink()

    def test_symlink_ancestor_and_special_files_refused(self):
        alias = Path(self.temp.name) / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            migrate(alias, True)
        os.mkfifo(self.root / 'pipe')
        with self.assertRaises(ValueError):
            migrate(self.root, True)
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o644)

    def test_limits_foreign_owner_and_os_failure_close_descriptors(self):
        with self.assertRaises(ValueError):
            migrate(self.root, True, max_entries=1)
        with patch('migrate_evidence_permissions.os.getuid', return_value=-1):
            with self.assertRaises(ValueError):
                migrate(self.root, True)
        with patch('migrate_evidence_permissions.os.fchmod', side_effect=OSError('failure')):
            with self.assertRaises(OSError):
                migrate(self.root, True)
        self.assertFalse(migrate(self.root)['applied'])
