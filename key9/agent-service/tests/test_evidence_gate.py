from __future__ import annotations

import unittest

from key9_core.evidence import EvidenceBundle, evaluate_evidence


class EvidenceGateTests(unittest.TestCase):
    def test_single_poc_is_not_patch_acceptance(self) -> None:
        decision = evaluate_evidence(
            EvidenceBundle(
                target_authorized=True,
                reachable=True,
                observed_effect=True,
                independent_triggers=1,
                patched_twin_clean=False,
                root_cause_supported=False,
                patch_blocks_all_triggers=False,
                semantic_regression_passed=False,
                artifacts=("original-poc",),
            )
        )

        self.assertEqual(decision.status, "needs_more_evidence")
        self.assertIn("multiple_independent_triggers", decision.blockers)
        self.assertIn("semantic_regression_validation", decision.blockers)
        self.assertFalse(decision.autonomous_release_allowed)

    def test_complete_bundle_advances_only_to_human_review(self) -> None:
        decision = evaluate_evidence(
            EvidenceBundle(
                target_authorized=True,
                reachable=True,
                observed_effect=True,
                independent_triggers=3,
                patched_twin_clean=True,
                root_cause_supported=True,
                patch_blocks_all_triggers=True,
                semantic_regression_passed=True,
                artifacts=("request-response", "stack-trace", "test-report"),
            )
        )

        self.assertEqual(decision.status, "ready_for_human_patch_review")
        self.assertEqual(decision.blockers, ())
        self.assertFalse(decision.autonomous_release_allowed)

    def test_unauthorized_target_is_blocked_before_evidence_scoring(self) -> None:
        decision = evaluate_evidence(
            EvidenceBundle(
                target_authorized=False,
                reachable=True,
                observed_effect=True,
                independent_triggers=3,
                patched_twin_clean=True,
                root_cause_supported=True,
                patch_blocks_all_triggers=True,
                semantic_regression_passed=True,
                artifacts=("a", "b", "c"),
            )
        )

        self.assertEqual(decision.status, "blocked_unauthorized_target")
        self.assertFalse(decision.autonomous_release_allowed)


if __name__ == "__main__":
    unittest.main()
