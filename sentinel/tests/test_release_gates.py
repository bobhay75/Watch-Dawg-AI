from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from sentinel.cli import exit_code_for_result
from sentinel.core import Finding, Observation, SentinelEngine, StateStore


class StatefulPack:
    kind = "stateful"
    allowed_authorization_modes = {"owner"}

    def __init__(self, states: list[str]) -> None:
        self.states = iter(states)

    def observe(self, target: dict[str, Any]) -> Observation:
        state = next(self.states)
        if state == "error":
            raise RuntimeError("observation failed")
        return Observation(
            target_id=str(target["id"]),
            kind=self.kind,
            ok=True,
            facts={"broken": state == "broken"},
        )

    def evaluate(
        self,
        target: dict[str, Any],
        current: Observation,
        previous: Observation | None,
    ) -> list[Finding]:
        if not current.facts["broken"]:
            return []
        return [Finding(
            target_id=current.target_id,
            code="BROKEN",
            severity="high",
            title="Broken",
            detail="The fixture is broken.",
        )]


class ReleaseGateTests(unittest.TestCase):
    def test_fail_on_alert_preserves_event_behavior(self) -> None:
        result = {"healthy": True, "notify": True}
        self.assertEqual(exit_code_for_result(result, True), 2)
        self.assertEqual(exit_code_for_result(result, False), 0)

    def test_repeated_authorization_failure_remains_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine = SentinelEngine(
                StateStore(Path(directory) / "state.json"),
                [StatefulPack([])],
            )
            target = {"id": "fixture", "kind": "stateful"}
            first = engine.run([target])
            second = engine.run([target])

        self.assertFalse(first["healthy"])
        self.assertFalse(second["healthy"])
        self.assertFalse(second["notify"])
        self.assertEqual(exit_code_for_result(second, True), 2)

    def test_failed_observation_never_resolves_prior_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine = SentinelEngine(
                StateStore(Path(directory) / "state.json"),
                [StatefulPack(["broken", "error", "ok"])],
            )
            target = {
                "id": "fixture",
                "kind": "stateful",
                "authorization": {"mode": "owner"},
            }
            first = engine.run([target])
            failed = engine.run([target])
            recovered = engine.run([target])

        self.assertEqual(first["new_alert_count"], 1)
        self.assertFalse(failed["complete"])
        self.assertEqual(failed["resolved_count"], 0)
        self.assertEqual(exit_code_for_result(failed, True), 2)
        self.assertGreaterEqual(recovered["resolved_count"], 1)
        self.assertTrue(recovered["complete"])
        self.assertTrue(recovered["healthy"])


if __name__ == "__main__":
    unittest.main()
