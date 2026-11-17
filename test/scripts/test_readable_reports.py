# Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "readable_reports", Path(__file__).resolve().parents[2] / "scripts/readable_reports.py")
REPORTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORTS)


class ReadableReportsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "reports"
        self.source.mkdir()
        self.output = Path(self.temp.name) / "evidence"
        self.statuses = {t[1]: "success" for t in REPORTS.TOOLS}

    def write(self, name, data):
        (self.source / name).write_text(json.dumps(data), encoding="utf-8")

    def empty_reports(self):
        self.write("semgrep.json", {"results": [], "errors": []})
        self.write("trivy-sca.json", {"Results": []})
        self.write("checkov.json", {"results": {"failed_checks": []}})

    def generate(self):
        return REPORTS.generate(self.source, self.output, {
            "Commit": "abc123", "Job DefectDojo": "success",
        }, self.statuses)

    def test_readable_findings_and_byte_identical_originals(self):
        self.write("semgrep.json", {"results": [{
            "check_id": "sql-injection", "path": "routes/login.ts",
            "start": {"line": 34}, "end": {"line": 35},
            "extra": {"severity": "ERROR", "message": "SQL inseguro"},
        }]})
        self.write("trivy-sca.json", {"Results": [{
            "Target": "frontend/package-lock.json", "Vulnerabilities": [{
                "VulnerabilityID": "TEST-1", "PkgName": "demo", "Severity": "CRITICAL",
                "InstalledVersion": "1.0", "FixedVersion": "2.0", "Title": "Ejemplo",
            }],
        }]})
        self.write("checkov.json", [{"results": {"failed_checks": [{
            "check_id": "TEST_DOCKER", "check_name": "Comprobación de ejemplo",
            "file_path": "/Dockerfile", "file_line_range": [1, 5],
        }]}}])
        self.assertFalse(self.generate())
        for _, name, htmlfile in REPORTS.TOOLS:
            self.assertEqual((self.source / name).read_bytes(),
                             (self.output / "originales" / name).read_bytes())
            html = (self.output / htmlfile).read_text(encoding="utf-8")
            self.assertIn("Hallazgo 1", html)
            self.assertIn("abc123", html)
            self.assertIn("SHA256", html)
        self.assertIn("Sin especificar", (self.output / "IaC-Checkov.html").read_text(encoding="utf-8"))
        self.assertIn("2.0", (self.output / "SCA-Trivy.html").read_text(encoding="utf-8"))

    def test_missing_and_invalid_are_not_zero_findings(self):
        (self.source / "semgrep.json").write_text("{broken", encoding="utf-8")
        self.write("checkov.json", {})
        self.assertTrue(self.generate())
        html = (self.output / "resumen.html").read_text(encoding="utf-8")
        self.assertEqual(html.count("No evaluable"), 3)
        self.assertIn("No disponible", html)
        self.assertIn("Informe inválido", html)

    def test_valid_empty_reports_show_zero(self):
        self.empty_reports()
        self.assertFalse(self.generate())
        html = (self.output / "SAST-Semgrep.html").read_text(encoding="utf-8")
        self.assertIn("Hallazgos: 0", html)
        self.assertIn("no certifica", html)

    def test_scanner_errors_and_job_failures_are_visible(self):
        self.empty_reports()
        self.write("semgrep.json", {"results": [], "errors": [{"message": "partial"}]})
        self.statuses["trivy-sca.json"] = "failure"
        self.assertTrue(self.generate())
        self.assertIn("Semgrep comunicó errores", (self.output / "SAST-Semgrep.html").read_text(encoding="utf-8"))
        self.assertIn("failure", (self.output / "SCA-Trivy.html").read_text(encoding="utf-8"))

    def test_untrusted_content_is_escaped(self):
        self.empty_reports()
        self.write("checkov.json", {"results": {"failed_checks": [{
            "check_id": "TEST", "file_path": '<img src=x onerror="alert(1)">',
            "check_name": "<script>alert(1)</script>", "guideline": "javascript:alert(1)",
        }]}})
        self.generate()
        html = (self.output / "IaC-Checkov.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img", html)
        self.assertNotIn('href="javascript:', html)
        self.assertIn("&lt;script&gt;", html)

    def test_checkov_multiple_reports_and_parsing_errors(self):
        findings, warnings = REPORTS.parse_report("checkov.json", [
            {"results": {"failed_checks": [], "parsing_errors": ["Dockerfile"]}},
            {"results": {"failed_checks": [{"check_id": "TEST", "file_path": "Dockerfile"}]}},
        ])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], "unknown")
        self.assertTrue(warnings)

    def test_malformed_finding_does_not_silently_disappear(self):
        self.empty_reports()
        self.write("semgrep.json", {"results": [{"check_id": "TEST"}]})
        self.assertTrue(self.generate())
        self.assertIn("No evaluable", (self.output / "SAST-Semgrep.html").read_text(encoding="utf-8"))

    def test_output_cannot_overwrite_sources(self):
        with self.assertRaises(ValueError):
            REPORTS.generate(self.source, self.source, {}, {})

    def test_trivy_null_is_empty_but_wrong_type_is_invalid(self):
        findings, warnings = REPORTS.parse_report("trivy-sca.json", {
            "Results": [{"Target": "package-lock.json", "Vulnerabilities": None}],
        })
        self.assertEqual(findings, [])
        self.assertEqual(warnings, [])
        with self.assertRaises(ValueError):
            REPORTS.parse_report("trivy-sca.json", {"Results": [{"Vulnerabilities": {}}]})


if __name__ == "__main__":
    unittest.main()
