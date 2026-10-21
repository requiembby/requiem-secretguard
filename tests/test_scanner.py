import json
import tempfile
import unittest
from pathlib import Path

from secretguard.cli import main
from secretguard.report import html_report
from secretguard.scanner import scan


class ScannerTests(unittest.TestCase):
    def test_findings_never_include_raw_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = "ghp_" + "Q" * 36
            (Path(tmp) / "config.py").write_text('GITHUB_TOKEN = "' + token + '"\n', encoding="utf-8")
            report = scan(tmp)
            self.assertGreaterEqual(report["findings_count"], 1)
            self.assertIn("github-token", [f["rule_id"] for f in report["findings"]])
            self.assertNotIn(token, json.dumps(report))
            self.assertNotIn(token, html_report(report))

    def test_ignores_symlinks_and_vendor_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "node_modules").mkdir()
            (base / "node_modules" / "bad.txt").write_text("sk_live_" + "Z" * 20)
            (base / "safe.txt").write_text("hello world")
            external = base / "outside.txt"
            external.write_text("sk_live_" + "Z" * 20)
            try:
                (base / "link.txt").symlink_to(external)
            except (NotImplementedError, OSError):
                pass
            report = scan(base)
            self.assertEqual(report["findings_count"], 1)
            self.assertEqual(report["findings"][0]["file"], "outside.txt")

    def test_incomplete_on_file_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "1.txt").write_text("hello")
            (Path(tmp) / "2.txt").write_text("hello")
            report = scan(tmp, max_files=1)
            self.assertTrue(report["incomplete"])
            self.assertEqual(report["verdict"], "INCOMPLETE")

    def test_placeholder_filtered(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".env").write_text("api_key=YOUR_EXAMPLE_PLACEHOLDER\n")
            report = scan(tmp)
            self.assertEqual(report["findings_count"], 0)

    def test_html_escapes_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            filename = '<img src=x onerror=alert(1)>.txt'
            (Path(tmp) / filename).write_text("sk_live_" + "K" * 20)
            report = scan(tmp)
            html = html_report(report)
            self.assertIn("&lt;img", html)
            self.assertNotIn("<img src=x", html)

    def test_cli_output_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "env.txt").write_text("sk_live_" + "L" * 20)
            out = Path(tmp) / "out.json"
            code = main([tmp, "--format", "json", "--output", str(out)])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out.read_text())["severity_counts"]["critical"], 1)

if __name__ == "__main__":
    unittest.main()
