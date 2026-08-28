from __future__ import annotations

import time
import unittest

from key9_core.policy import LeaseStore, PolicyEngine


class PolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = PolicyEngine()

    def test_unknown_alias_fails_closed(self) -> None:
        decision = self.policy.evaluate(
            alias="model.supplied.secret",
            target="https://api.watch-dawg.ai",
            scopes=["jobs:read"],
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "unknown_secret_alias")

    def test_target_must_be_https_and_exact(self) -> None:
        insecure = self.policy.evaluate(
            alias="watchdawg.production",
            target="http://api.watch-dawg.ai",
            scopes=["jobs:read"],
        )
        lookalike = self.policy.evaluate(
            alias="watchdawg.production",
            target="https://api.watch-dawg.ai.attacker.example",
            scopes=["jobs:read"],
        )
        self.assertFalse(insecure.allowed)
        self.assertFalse(lookalike.allowed)

    def test_secret_disclosure_scope_is_never_allowed(self) -> None:
        decision = self.policy.evaluate(
            alias="watchdawg.production",
            target="https://api.watch-dawg.ai",
            scopes=["secret:reveal"],
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "secret_disclosure_forbidden")

    def test_unlisted_scope_is_denied(self) -> None:
        decision = self.policy.evaluate(
            alias="drive.receipts",
            target="https://www.googleapis.com",
            scopes=["drive:write"],
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "scope_not_allowlisted")

    def test_write_requires_owner_approval(self) -> None:
        held = self.policy.evaluate(
            alias="accounting.export",
            target="https://sandbox-accounting.watch-dawg.ai",
            scopes=["exports:create"],
        )
        allowed = self.policy.evaluate(
            alias="accounting.export",
            target="https://sandbox-accounting.watch-dawg.ai",
            scopes=["exports:create"],
            owner_approved=True,
        )
        self.assertFalse(held.allowed)
        self.assertTrue(held.requires_approval)
        self.assertTrue(allowed.allowed)

    def test_ttl_is_capped_by_policy(self) -> None:
        decision = self.policy.evaluate(
            alias="watchdawg.production",
            target="https://api.watch-dawg.ai",
            scopes=["jobs:read"],
            requested_ttl_seconds=86_400,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.ttl_seconds, 60)

    def test_lease_is_opaque_and_revocable(self) -> None:
        decision = self.policy.evaluate(
            alias="drive.receipts",
            target="https://www.googleapis.com",
            scopes=["receipts:read"],
            requested_ttl_seconds=5,
        )
        leases = LeaseStore()
        lease = leases.issue(
            alias="drive.receipts",
            target="https://www.googleapis.com",
            scopes=["receipts:read"],
            decision=decision,
            owner_approved=False,
        )
        self.assertTrue(lease.lease_id.startswith("k9l_"))
        self.assertGreater(lease.expires_at, time.time())
        self.assertEqual(leases.validate(lease.lease_id), lease)
        self.assertTrue(leases.revoke(lease.lease_id))
        with self.assertRaisesRegex(PermissionError, "lease_not_found"):
            leases.validate(lease.lease_id)


if __name__ == "__main__":
    unittest.main()
