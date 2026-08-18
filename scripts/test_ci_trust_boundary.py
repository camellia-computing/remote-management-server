"""Fast negative contracts for workflow classification and trust policy."""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"
TRUST = ROOT / ".github/workflows/ci-trust.yml"
POLICY_SPEC = importlib.util.spec_from_file_location("ci_trust_policy", ROOT / ".github/scripts/ci_trust_policy.py")
if POLICY_SPEC is None or POLICY_SPEC.loader is None:
    raise RuntimeError("unable to load CI trust policy")
ci_trust_policy = importlib.util.module_from_spec(POLICY_SPEC)
POLICY_SPEC.loader.exec_module(ci_trust_policy)
TrustPolicyError = ci_trust_policy.TrustPolicyError
classify_paths = ci_trust_policy.classify_paths
validate_ci_workflow = ci_trust_policy.validate_ci_workflow
validate_workflow_safety = ci_trust_policy.validate_workflow_safety
verify_candidate = ci_trust_policy.verify_candidate


class ChangeClassificationTests(unittest.TestCase):
    def test_workflow_only_is_runtime_automation_and_dependency(self):
        self.assertEqual(
            classify_paths([".github/workflows/ci.yml"]),
            {"runtime": True, "automation": True, "dependencies": True},
        )

    def test_required_action_and_policy_script_are_runtime(self):
        self.assertTrue(classify_paths([".github/actions/build-web-client/action.yml"])["runtime"])
        self.assertTrue(classify_paths([".github/scripts/ci_trust_policy.py"])["runtime"])

    def test_documentation_only_keeps_runtime_suite_optional(self):
        self.assertEqual(
            classify_paths(["README.md", "docs/operations.md"]),
            {"runtime": False, "automation": False, "dependencies": False},
        )


class RequiredContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = CI.read_text(encoding="utf-8")

    def test_current_workflow_has_complete_required_contract(self):
        validate_ci_workflow(self.workflow)

    def assert_contract_rejected(self, old: str, new: str):
        with self.assertRaises(TrustPolicyError):
            validate_ci_workflow(old.replace(new, "", 1))

    def test_quality_removal_is_not_a_skip(self):
        self.assert_contract_rejected(
            self.workflow,
            'require_success "Python and Django quality" "$QUALITY_RESULT"',
        )

    def test_container_if_false_is_rejected(self):
        changed = self.workflow.replace(
            "if: needs.classify.outputs.runtime == 'true'\n    needs: [classify, metadata, web_client, quality]",
            "if: false\n    needs: [classify, metadata, web_client, quality]",
            1,
        )
        with self.assertRaises(TrustPolicyError):
            validate_ci_workflow(changed)

    def test_missing_required_dependency_is_rejected(self):
        changed = self.workflow.replace("      - container\n      - performance_smoke", "      - performance_smoke", 1)
        with self.assertRaises(TrustPolicyError):
            validate_ci_workflow(changed)

    def test_quality_needs_classifier_and_web_client(self):
        changed = self.workflow.replace("needs: [classify, web_client]", "needs: [web_client]", 1)
        with self.assertRaises(TrustPolicyError):
            validate_ci_workflow(changed)

    def test_failure_cannot_be_treated_as_skipped(self):
        changed = self.workflow.replace('if [[ "$result" != "success" ]]', 'if [[ "$result" == "failure" ]]', 1)
        with self.assertRaises(TrustPolicyError):
            validate_ci_workflow(changed)

    def test_expanded_permissions_are_rejected(self):
        with self.assertRaises(TrustPolicyError):
            validate_workflow_safety(
                pathlib.PurePosixPath(".github/workflows/ci.yml"), self.workflow + "\n  permissions: write-all\n"
            )

    def test_reserved_required_name_cannot_be_forged(self):
        with self.assertRaises(TrustPolicyError):
            validate_workflow_safety(
                pathlib.PurePosixPath(".github/workflows/evil.yml"),
                "name: CI Trust / Required\non:\n  pull_request:\n",
            )


class CandidateBoundaryTests(unittest.TestCase):
    def test_trust_workflow_is_base_immutable(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary) / "base"
            candidate = pathlib.Path(temporary) / "candidate"
            for root in (base, candidate):
                (root / ".github/workflows").mkdir(parents=True)
                (root / ".github/scripts").mkdir(parents=True)
                (root / "scripts").mkdir()
            base_ci = CI.read_bytes()
            trust = TRUST.read_bytes()
            (base / ".github/workflows/ci.yml").write_bytes(base_ci)
            (base / ".github/workflows/ci-trust.yml").write_bytes(trust)
            (candidate / ".github/workflows/ci.yml").write_bytes(base_ci)
            (candidate / ".github/workflows/ci-trust.yml").write_bytes(trust + b"\n# candidate rewrite\n")
            with self.assertRaises(TrustPolicyError):
                verify_candidate(base, candidate, [".github/workflows/ci-trust.yml"])

    def test_classifier_rewrite_is_base_immutable_after_bootstrap(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary) / "base"
            candidate = pathlib.Path(temporary) / "candidate"
            for root in (base, candidate):
                (root / ".github/workflows").mkdir(parents=True)
                (root / ".github/scripts").mkdir(parents=True)
            (base / ".github/workflows/ci.yml").write_bytes(CI.read_bytes())
            (base / ".github/workflows/ci-trust.yml").write_bytes(TRUST.read_bytes())
            (candidate / ".github/workflows/ci.yml").write_bytes(CI.read_bytes())
            (candidate / ".github/workflows/ci-trust.yml").write_bytes(TRUST.read_bytes())
            base_classifier = base / ".github/scripts/classify-changes.sh"
            candidate_classifier = candidate / ".github/scripts/classify-changes.sh"
            base_classifier.write_text("runtime=true\n", encoding="utf-8")
            candidate_classifier.write_text("runtime=false\n", encoding="utf-8")
            with self.assertRaises(TrustPolicyError):
                verify_candidate(base, candidate, [".github/scripts/ci_classifier.sh"])

    def test_classify_and_required_jobs_are_base_immutable(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary) / "base"
            candidate = pathlib.Path(temporary) / "candidate"
            for root in (base, candidate):
                (root / ".github/workflows").mkdir(parents=True)
                (root / ".github/scripts").mkdir(parents=True)
            base_ci = CI.read_text(encoding="utf-8")
            (base / ".github/workflows/ci.yml").write_text(base_ci, encoding="utf-8")
            (base / ".github/workflows/ci-trust.yml").write_bytes(TRUST.read_bytes())
            (candidate / ".github/workflows/ci-trust.yml").write_bytes(TRUST.read_bytes())
            candidate_ci = base_ci.replace(
                "bash .github/scripts/classify-changes.sh\n",
                "bash .github/scripts/classify-changes.sh\n          echo changed\n",
                1,
            )
            (candidate / ".github/workflows/ci.yml").write_text(candidate_ci, encoding="utf-8")
            with self.assertRaises(TrustPolicyError):
                verify_candidate(base, candidate, [".github/workflows/ci.yml"])


if __name__ == "__main__":
    unittest.main()
