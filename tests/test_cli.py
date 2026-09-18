import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cli import run_analysis


class TestCLIFallbackAndErrors(unittest.TestCase):

    def setUp(self):
        self.sample_project = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "samples", "sample_flask_app")
        )

    def test_empty_requirements_no_dummy_fallback(self):
        """Verify that an empty requirements file results in empty targets, never dummy fallback."""
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
            f.write("")  # empty file
            empty_req_path = f.name

        try:
            parser, graph, entry_points, results = run_analysis(
                project_path=self.sample_project,
                requirements_file=empty_req_path,
            )
            # Must be empty and must not contain dummy_vuln_lib.unsafe_deserialize
            self.assertEqual(results, [])
            for r in results:
                self.assertNotEqual(r.target_symbol, "dummy_vuln_lib.unsafe_deserialize")
                self.assertNotEqual(r.advisory_id, "DEMO-001")
        finally:
            Path(empty_req_path).unlink(missing_ok=True)

    def test_unparseable_requirements_no_dummy_fallback(self):
        """Verify that a requirements file with no recognizable packages does not trigger dummy fallback."""
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
            f.write("# This is a comment\n\n# Another comment\n")
            unparseable_req = f.name

        try:
            parser, graph, entry_points, results = run_analysis(
                project_path=self.sample_project,
                requirements_file=unparseable_req,
            )
            self.assertEqual(results, [])
        finally:
            Path(unparseable_req).unlink(missing_ok=True)

    def test_cli_empty_requirements_exit_code_2(self):
        """Verify CLI exits cleanly with exit code 2 when requirements file has no packages."""
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
            f.write("")
            empty_req = f.name

        try:
            proc = subprocess.run(
                [sys.executable, "cli.py", "--path", self.sample_project, "--requirements", empty_req],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("Warning: Requirements file", proc.stderr)
            self.assertIn("parsed but contained no recognizable packages", proc.stderr)
            self.assertIn("nothing to check", proc.stderr)
        finally:
            Path(empty_req).unlink(missing_ok=True)

    def test_cli_nonexistent_requirements_exit_code_2(self):
        """Verify CLI warns and exits with code 2 on nonexistent requirements file."""
        nonexistent = "nonexistent_requirements_file_12345.txt"
        proc = subprocess.run(
            [sys.executable, "cli.py", "--path", self.sample_project, "--requirements", nonexistent],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not found or unreadable", proc.stderr)
        self.assertIn("nothing to check", proc.stderr)

    def test_cli_no_args_no_requirements_exit_code_2(self):
        """Verify CLI handles no CLI args on a directory without requirements.txt."""
        with tempfile.TemporaryDirectory() as empty_dir:
            # Create a simple python file without requirements.txt
            app_file = os.path.join(empty_dir, "app.py")
            with open(app_file, "w") as f:
                f.write("def hello(): pass\n")

            proc = subprocess.run(
                [sys.executable, "cli.py", "--path", empty_dir],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("No target function specified and no requirements.txt found", proc.stderr)


if __name__ == "__main__":
    unittest.main()
