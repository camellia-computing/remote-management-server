"""Unit and negative contracts for branch/module/diff coverage enforcement."""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ci_coverage_contract", ROOT / ".github/scripts/ci_coverage_contract.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load coverage contract")
coverage_contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage_contract)


class CoverageContractTests(unittest.TestCase):
    def test_changed_line_parser_handles_added_ranges_and_zero_count(self):
        diff = """diff --git a/api/views_api.py b/api/views_api.py
--- a/api/views_api.py
+++ b/api/views_api.py
@@ -1,0 +2,3 @@
+a
+b
+c
@@ -9,2 +12,0 @@
"""
        self.assertEqual(coverage_contract.changed_line_numbers(diff), {"api/views_api.py": {2, 3, 4}})

    def test_malformed_diff_fails_closed(self):
        for diff in ("@@ -1 +1 @@\n+x\n", "+++ b/api/views_api.py\n+not-a-hunk\n", "+++ /dev/null\n@@ -1 +0 @@\n"):
            with self.subTest(diff=diff), self.assertRaises(coverage_contract.CoverageContractError):
                coverage_contract.changed_line_numbers(diff)

    def test_deleted_file_is_valid_and_does_not_create_obligations(self):
        diff = """diff --git a/api/old.py b/api/old.py
deleted file mode 100644
--- a/api/old.py
+++ /dev/null
@@ -1,2 +0,0 @@
-old()
"""
        self.assertEqual(coverage_contract.changed_line_numbers(diff), {})

    def test_changed_executable_lines_require_hits_but_ignore_non_executable_and_tests(self):
        changed = {
            "api/views_api.py": {10, 11, 12},
            "api/test_response_contract.py": {2},
            "api/migrations/0040_gate.py": {3},
        }
        with self.assertRaises(coverage_contract.CoverageContractError):
            coverage_contract.check_changed_lines(changed, {"api/views_api.py": {10: 1, 11: 0}})
        # Line 12 has no executable record and is therefore a comment/blank
        # line; it must not make the diff gate fail.
        coverage_contract.check_changed_lines(changed, {"api/views_api.py": {10: 1, 11: 1}})

    def test_changed_production_file_without_xml_evidence_fails_closed(self):
        with self.assertRaises(coverage_contract.CoverageContractError):
            coverage_contract.check_changed_lines({"api/new_boundary.py": {1}}, {})

    def test_module_floor_rejects_branch_regression(self):
        with self.assertRaises(coverage_contract.CoverageContractError):
            coverage_contract.check_module_floors(
                {
                    module: (line_floor + 1, branch_floor - 1)
                    for module, (line_floor, branch_floor) in coverage_contract.MODULE_FLOORS.items()
                }
            )

    def test_xml_parser_requires_branch_evidence(self):
        xml = """<coverage branch-rate=\"0.6\"><packages><package name=\"api\"><classes><class filename=\"api/views_api.py\" line-rate=\"0.8\" branch-rate=\"0.7\"><methods/><lines><line number=\"10\" hits=\"1\"/></lines></class></classes></package></packages></coverage>"""
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "coverage.xml"
            path.write_text(xml, encoding="utf-8")
            hits, rates, branch = coverage_contract.parse_coverage_xml(path, root=ROOT)
        self.assertEqual(hits["api/views_api.py"][10], 1)
        self.assertEqual(rates["api/views_api.py"], (80.0, 70.0))
        self.assertEqual(branch, 60.0)

    def test_global_branch_floor_rejects_missing_or_low_evidence(self):
        with self.assertRaises(coverage_contract.CoverageContractError):
            coverage_contract.verify(
                root=ROOT,
                coverage_xml=self._coverage_xml(branch_rate="0.1"),
                base="0" * 40,
                head="1" * 40,
            )

    def test_module_floor_reports_missing_critical_evidence(self):
        with self.assertRaises(coverage_contract.CoverageContractError):
            coverage_contract.check_module_floors({})

    def test_xml_parse_errors_are_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "coverage.xml"
            path.write_text("<coverage>", encoding="utf-8")
            with self.assertRaises(ET.ParseError):
                coverage_contract.parse_coverage_xml(path, root=ROOT)

    @staticmethod
    def _coverage_xml(*, branch_rate):
        temporary = tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8")
        temporary.write(
            f'<coverage branch-rate="{branch_rate}"><packages><package><classes>'
            '<class filename="api/views_api.py" line-rate="0.8" branch-rate="0.7">'
            '<lines><line number="10" hits="1"/></lines></class>'
            "</classes></package></packages></coverage>"
        )
        temporary.close()
        return pathlib.Path(temporary.name)


if __name__ == "__main__":
    unittest.main()
