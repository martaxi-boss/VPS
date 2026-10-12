"""Prevent pre-model GitHub Actions inline Python publisher-import failures."""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class PreflightPublisherImportTests(unittest.TestCase):
    def test_inline_python_can_load_publisher_with_adjacent_guard(self):
        workflow = (ROOT / ".github/workflows/codex-autonomous.yml").read_text(
            encoding="utf-8")
        gate = workflow.split(
            "      - name: Verify actual Git branch publication permission without model calls", 1
        )[1].split(
            "      - name: Pin Owner-provided SSH host key", 1
        )[0]
        self.assertIn("sys.path.insert(0, str(f.parent.resolve()))", gate)
        script = """import importlib.util, sys
from pathlib import Path
f = Path('ops/codex-autonomous-publish.py')
sys.path.insert(0, str(f.parent.resolve()))
spec = importlib.util.spec_from_file_location('trusted_publisher', f)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
assert callable(publisher.verify_git_publication_dry_run)
"""
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=ROOT, capture_output=True,
            text=True, check=False, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
