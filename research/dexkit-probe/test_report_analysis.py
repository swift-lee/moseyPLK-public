#!/usr/bin/env python3
"""Use the existing 12 DexKit fixture reports; do not rebuild or run DexKit."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from analyze_report import ASSETS, ROOT, analyze, output_path, sha256

FIXTURES = ASSETS / "build/dexkit-probe/fixtures"
EXPECTED = {
    "pure_a": "PURE_A", "pure_a_renamed": "PURE_A", "or_ab": "A_OR_B",
    "and_ab": "unsupported", "not_a": "unsupported",
    "duplicate_other_namespace": "PURE_A", "duplicate_same_namespace": "unsupported",
    "supplier_side_effect": "unsupported", "getter_side_effect": "unsupported",
    "constant_false": "unsupported", "constant_true": "unsupported",
    "discard_a_constant_false": "unsupported",
}


class ExistingDexKitFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing assets fail explicitly: a skipped suite is not a fixture pass.
        cls.reports = {name: analyze(FIXTURES / name / "dex.zip",
                                     FIXTURES / name / "probe.json") for name in EXPECTED}

    def test_no_result_approves_profile_or_device_behavior(self):
        for name, report in self.reports.items():
            with self.subTest(case=name):
                self.assertIs(report["report_only"], True)
                self.assertIs(report["hook_profile_approved"], False)
                self.assertIs(report["device_tested"], False)
                self.assertIs(report["gms_code_executed"], False)
                self.assertEqual(report["phone_operations"], [])
                self.assertTrue(report["host"]["androguard_version"])
                self.assertEqual(report["input"]["apk"]["sha256"], sha256(FIXTURES / name / "dex.zip"))
                self.assertEqual(report["input"]["discovery"]["sha256"], sha256(FIXTURES / name / "probe.json"))
                self.assertEqual(len(report["input"]["source_sha256"]), 3)

    def test_renaming_preserves_expression_without_name_allowlist(self):
        before, renamed = (self.reports[name] for name in ("pure_a", "pure_a_renamed"))
        self.assertNotEqual(before["getters"]["A"]["selected"], renamed["getters"]["A"]["selected"])
        self.assertNotEqual(before["suppliers"][0]["descriptor"], renamed["suppliers"][0]["descriptor"])
        self.assertEqual(before["suppliers"][0]["semantics"]["cases"], renamed["suppliers"][0]["semantics"]["cases"])

    def test_or_is_verified_by_truth_table_and_short_circuit_trace(self):
        report = self.reports["or_ab"]
        cases = report["suppliers"][0]["semantics"]["cases"]
        self.assertEqual([case["result"] for case in cases], [False, True, True, True])
        self.assertEqual([case["getters"] for case in cases], [["A", "B"], ["A", "B"], ["A"], ["A"]])

    def test_namespace_filters_do_not_select_first_ambiguous_candidate(self):
        different = self.reports["duplicate_other_namespace"]["getters"]["A"]
        same = self.reports["duplicate_same_namespace"]["getters"]["A"]
        self.assertEqual(different["raw_getter_count"], 2)
        self.assertEqual(different["namespace_candidate_count"], 1)
        self.assertTrue(different["namespace_is_filter_only"])
        self.assertEqual(same["namespace_candidate_count"], 2)
        self.assertEqual(same["status"], "ambiguous")
        self.assertIsNone(same["selected"])
        self.assertEqual(self.reports["duplicate_same_namespace"]["dex"]["fully_parsed_entries"], [])

    def test_constants_are_not_supplier_candidates(self):
        for name in ("constant_false", "constant_true"):
            self.assertEqual(self.reports[name]["supplier_candidate_descriptors"], [])
            self.assertEqual(self.reports[name]["suppliers"], [])

    def test_shape_and_receiver_assumptions_remain_explicit(self):
        report = self.reports["pure_a"]
        self.assertFalse(report["getters"]["A"]["candidates"][0]["getter_shape"]["dataflow_proved"])
        supplier = report["suppliers"][0]
        self.assertFalse(supplier["assumptions_independently_proved"])
        self.assertFalse(supplier["constructor_field_dataflow_proved"])
        self.assertEqual(supplier["semantics"]["assumptions"]["service_initialization_fields"], [])
        self.assertTrue(supplier["semantics"]["assumptions"]["receiver_accessors"])
        self.assertTrue(supplier["semantics"]["assumptions"]["receiver_fields"])
        self.assertEqual(report["dex"]["fully_parsed_entries"], ["classes.dex"])


def fixture_test(name, classification):
    def check(self):
        report = self.reports[name]
        self.assertEqual(report["classification"], classification, report["reason"])
        self.assertEqual(report["local_expression_accepted"], classification != "unsupported")
    return check


for _name, _classification in EXPECTED.items():
    setattr(ExistingDexKitFixtures, "test_fixture_" + _name, fixture_test(_name, _classification))


class ReportBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="report-analysis-test-", dir=ASSETS / "build")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.apk = FIXTURES / "pure_a/dex.zip"
        self.discovery = json.loads((FIXTURES / "pure_a/probe.json").read_text())

    def modified_report(self, report):
        path = self.directory / "discovery.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def test_declared_apk_hash_mismatch_rejects(self):
        self.discovery["input"] = {"sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "hash does not match"):
            analyze(self.apk, self.modified_report(self.discovery))

    def test_declared_apk_hash_match_is_recorded(self):
        self.discovery["input"] = {"sha256": sha256(self.apk)}
        report = analyze(self.apk, self.modified_report(self.discovery))
        self.assertIs(report["input"]["discovery_declared_apk_hash_matches"], True)
        self.assertFalse(report["hook_profile_approved"])

    def test_cross_dex_duplicate_supplier_class_rejects_before_parsing(self):
        with zipfile.ZipFile(self.apk) as archive:
            dex = archive.read("classes.dex")
        duplicate = self.directory / "duplicate.zip"
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("classes.dex", dex)
            archive.writestr("classes2.dex", dex)
        report = analyze(duplicate, self.modified_report(self.discovery))
        self.assertFalse(report["local_expression_accepted"])
        self.assertIn("ambiguous across", report["reason"])
        self.assertEqual(report["dex"]["fully_parsed_entries"], [])

    def test_multiple_supplier_candidates_reject_before_parsing(self):
        suppliers = self.discovery["keys"][0]["matches"][0]["getters"][0]["supplier_candidates"]
        other = copy.deepcopy(suppliers[0])
        other["descriptor"] = "Lother;->call()Ljava/lang/Object;"
        suppliers.append(other)
        report = analyze(self.apk, self.modified_report(self.discovery))
        self.assertFalse(report["local_expression_accepted"])
        self.assertIn("candidate count is not one", report["reason"])
        self.assertEqual(report["dex"]["fully_parsed_entries"], [])

    def test_no_namespace_candidate_rejects(self):
        self.discovery["keys"][0]["matches"][0]["namespace_graph_evidence"] = []
        report = analyze(self.apk, self.modified_report(self.discovery))
        self.assertFalse(report["local_expression_accepted"])
        self.assertEqual(report["getters"]["A"]["status"], "absent")

    def test_stale_supplier_opcodes_reject(self):
        supplier = self.discovery["keys"][0]["matches"][0]["getters"][0]["supplier_candidates"][0]
        supplier["opcodes"].append("nop")
        report = analyze(self.apk, self.modified_report(self.discovery))
        self.assertFalse(report["local_expression_accepted"])
        self.assertIn("does not match APK", report["reason"])

    def test_output_only_new_json_in_assets(self):
        self.assertEqual(output_path(self.directory / "result.json"), self.directory / "result.json")
        with self.assertRaisesRegex(ValueError, "under moseyPLK-assets"):
            output_path(ROOT / "research/dexkit-probe/result.json")
        with self.assertRaisesRegex(ValueError, "under moseyPLK-assets"):
            output_path(self.directory / "result.txt")
        existing = self.directory / "existing.json"
        existing.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "already exists"):
            output_path(existing)
        escape = self.directory / "escape"
        escape.symlink_to(ROOT / "research", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "under moseyPLK-assets"):
            output_path(escape / "result.json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
