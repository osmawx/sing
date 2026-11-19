"""Verify version reporting never starts the proxy."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class VersionTest(unittest.TestCase):
    """Exercise the public CLI version command without installed dependencies."""

    def test_reports_source_version(self):
        """A source install reports its explicit version without sing-box."""
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as home:
            result = subprocess.run(['/bin/bash', str(root / 'bin/sing'), '--version'],  # noqa: S603 - fixed repository test script
                                    env={**os.environ, 'HOME': home}, capture_output=True,
                                    text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'sing ' + (root / 'VERSION').read_text().strip())
