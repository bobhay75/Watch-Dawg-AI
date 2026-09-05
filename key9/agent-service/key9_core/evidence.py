"""Evidence gates for isolated vulnerability-finding and patch evaluation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceBundle:
    """Evidence collected from an explicitly authorized laboratory target."""

    target_authorized: bool
    reachable: bool
    observed_effect: bool
    independent_triggers: int
    patched_twin_clean: bool
    root_cause_supported: bool
    patch_blocks_all_triggers: bool
    semantic_regression_passed: bool
    artifacts: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceDecision:
    status: str
    blockers: tuple[str, ...]
    autonomous_release_allowed: bool = False


def evaluate_evidence(bundle: EvidenceBundle) -> EvidenceDecision:
    """Require multi-layer evidence and always leave release to a human.

    This function performs no scanning, networking, exploitation, patching, or
    deployment. It evaluates evidence already produced in an isolated lab.
    """
    if not bundle.target_authorized:
        return EvidenceDecision("blocked_unauthorized_target", ("target_authorization",))

    checks = (
        (bundle.reachable, "reachability"),
        (bundle.observed_effect, "observed_effect"),
        (bundle.independent_triggers >= 2, "multiple_independent_triggers"),
        (bundle.patched_twin_clean, "patched_twin_counterevidence"),
        (bundle.root_cause_supported, "root_cause_support"),
        (bundle.patch_blocks_all_triggers, "patch_security_validation"),
        (bundle.semantic_regression_passed, "semantic_regression_validation"),
        (len(bundle.artifacts) >= 3, "reproduction_artifacts"),
    )
    blockers = tuple(name for passed, name in checks if not passed)
    if blockers:
        return EvidenceDecision("needs_more_evidence", blockers)
    return EvidenceDecision("ready_for_human_patch_review", ())
