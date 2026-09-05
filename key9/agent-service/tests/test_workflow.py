from __future__ import annotations

import inspect
import unittest

from key9_core.workflow import (
    _brokered_action,
    approve_accounting_export,
    collect_job_receipts,
    prepare_accounting_export,
    read_watchdawg_job,
)


class BrokeredWorkflowTests(unittest.TestCase):
    def test_read_actions_cross_broker_and_consume_lease(self) -> None:
        job = read_watchdawg_job()
        receipts = collect_job_receipts()

        self.assertEqual(job["status"], "success")
        self.assertEqual(receipts["status"], "success")
        self.assertEqual(job["lease_state"], "consumed_before_connector")
        self.assertEqual(receipts["lease_state"], "consumed_before_connector")
        self.assertEqual(job["secret_values_visible_to_model"], 0)
        self.assertNotIn("sandbox-watchdawg-token", str(job))
        self.assertNotIn("sandbox-drive-token", str(receipts))

    def test_accounting_write_is_held_without_owner_approval(self) -> None:
        result = prepare_accounting_export()

        self.assertEqual(result["status"], "approval_required")
        self.assertEqual(result["reason"], "owner_approval_required")
        self.assertFalse(result["external_write_performed"])

    def test_model_facing_tool_has_no_approval_parameter(self) -> None:
        parameters = inspect.signature(prepare_accounting_export).parameters
        self.assertNotIn("owner_approved", parameters)

    def test_server_approved_accounting_write_crosses_single_use_broker(self) -> None:
        result = approve_accounting_export()

        self.assertEqual(result["status"], "simulated")
        self.assertTrue(result["sandbox_action_simulated"])
        self.assertFalse(result["external_write_performed"])
        self.assertEqual(result["lease_state"], "consumed_before_connector")
        self.assertEqual(result["secret_values_visible_to_model"], 0)
        self.assertNotIn("sandbox-accounting-token", str(result))

    def test_receipts_are_dynamic_and_truthfully_labeled(self) -> None:
        first = read_watchdawg_job()
        second = read_watchdawg_job()

        first_receipt = first["audit_receipt"]
        second_receipt = second["audit_receipt"]
        self.assertEqual(first_receipt["schema"], "key9.audit.v1")
        self.assertEqual(first_receipt["evidence_claim"], "sandbox_fixture_only")
        self.assertEqual(first_receipt["event_type"], "credential_connector_action")
        self.assertEqual(first_receipt["actor"], "key9.connector")
        self.assertTrue(first_receipt["sandbox"])
        self.assertFalse(first_receipt["external_write_performed"])
        self.assertNotEqual(first_receipt["event_id"], second_receipt["event_id"])
        self.assertEqual(len(first_receipt["result_sha256"]), 64)

        held = prepare_accounting_export()["audit_receipt"]
        self.assertEqual(held["event_type"], "authorization_decision")
        self.assertEqual(held["actor"], "key9.policy_engine")
        self.assertEqual(held["evidence_claim"], "policy_blocked_or_held")

    def test_failed_write_never_claims_that_no_external_effect_occurred(self) -> None:
        def fail_after_boundary() -> dict[str, object]:
            raise RuntimeError("synthetic_ambiguous_connector_failure")

        result = _brokered_action(
            alias="accounting.export",
            target="https://sandbox-accounting.watch-dawg.ai",
            scopes=["exports:create"],
            owner_approved=True,
            action=fail_after_boundary,
        )

        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(result["external_write_performed"])
        self.assertEqual(
            result["effect_state"], "unknown_after_connector_boundary_failure"
        )
        self.assertEqual(
            result["audit_receipt"]["evidence_claim"], "connector_effect_unknown"
        )


if __name__ == "__main__":
    unittest.main()
