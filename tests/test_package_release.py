"""Verify standalone CLI artifacts contain only runtime files and version metadata."""

import hashlib
import json
import runpy
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PackageReleaseTest(unittest.TestCase):
    """Exercise the actual release packager without network access."""

    def test_versioned_archive_contains_no_user_configuration(self):
        """The release version and every file checksum match packaged bytes."""
        package = runpy.run_path(str(ROOT / 'scripts/package_release.py'))['package_release']
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            package(ROOT, '1.0.42', output)
            archive_path = output / 'sing-macos.tar.gz'
            with tarfile.open(archive_path) as archive:
                self.assertEqual(set(archive.getnames()), {
                    'bin/sing', 'share/select.py', 'proxychains/sing.conf', 'VERSION', 'release.json'})
                self.assertEqual(archive.extractfile('VERSION').read(), b'1.0.42\n')
                manifest = json.load(archive.extractfile('release.json'))
                for name, digest in manifest['files'].items():
                    self.assertEqual(hashlib.sha256(archive.extractfile(name).read()).hexdigest(), digest)
            first = archive_path.read_bytes()
            package(ROOT, '1.0.42', output)
            self.assertEqual(archive_path.read_bytes(), first)
