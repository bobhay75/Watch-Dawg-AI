from __future__ import annotations

import unittest

from key9_core.workflow import (
    collect_job_receipts,
    prepare_accounting_export,
    read_watchdawg_job,
)


class BrokeredWorkflowTests(unittest.TestCase):
    def test_read_actions_cross_broker_and_revoke_lease(self) -> None:
        job = read_watchdawg_job()
        receipts = collect_job_receipts()

        self.assertEqual(job["status"], "success")
        self.assertEqual(receipts["status"], "success")
        self.assertEqual(job["lease_state"], "revoked_after_use")
        self.assertEqual(receipts["lease_state"], "revoked_after_use")
        self.assertEqual(job["secret_values_visible_to_model"], 0)
        self.assertNotIn("sandbox-watchdawg-token", str(job))
        self.assertNotIn("sandbox-drive-token", str(receipts))

    def test_accounting_write_is_held_without_owner_approval(self) -> None:
        result = prepare_accounting_export(owner_approved=False)

        self.assertEqual(result["status"], "approval_required")
        self.assertEqual(result["reason"], "owner_approval_required")
        self.assertFalse(result["external_write_performed"])

    def test_approved_accounting_write_crosses_single_use_broker(self) -> None:
        result = prepare_accounting_export(owner_approved=True)

        self.assertEqual(result["status"], "success")
        self.assertTrue(result["external_write_performed"])
        self.assertEqual(result["lease_state"], "revoked_after_use")
        self.assertEqual(result["secret_values_visible_to_model"], 0)
        self.assertNotIn("sandbox-accounting-token", str(result))


if __name__ == "__main__":
    unittest.main()
