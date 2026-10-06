"""The beginner-facing helpers: demo script, health check, and the Windows .bat files."""
import contextlib
import importlib.util
import io
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "scripts", name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DemoTests(unittest.TestCase):
    def test_demo_runs_offline_and_flags_the_bad_samples(self):
        demo = _load("demo")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            demo.main()
        text = out.getvalue()
        self.assertEqual(text.count("HIGH RISK"), 5)
        self.assertEqual(text.count("no red flags found"), 2)
        text.encode("ascii")  # old Windows consoles: the demo must stay plain ASCII


class CheckSetupTests(unittest.TestCase):
    def test_analyzer_self_test_passes_and_output_has_no_secrets(self):
        check = _load("check_setup")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            check._problems.clear()
            check.check_analyzer()
        self.assertEqual(check._problems, [])
        self.assertIn("self-test passed", out.getvalue())


class BatchFileTests(unittest.TestCase):
    def test_bat_files_use_windows_line_endings(self):
        names = [n for n in os.listdir(ROOT) if n.endswith(".bat")]
        self.assertTrue({"setup.bat", "run_alerts.bat", "run_dashboard.bat", "demo.bat", "check_setup.bat"} <= set(names))
        for name in names:
            with open(os.path.join(ROOT, name), "rb") as f:
                data = f.read()
            self.assertNotIn(b"\n", data.replace(b"\r\n", b""), f"{name} has bare LF line endings")
            data.decode("ascii")


if __name__ == "__main__":
    unittest.main()
