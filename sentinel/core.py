from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import stat
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .discernment import build_discernment, explain_finding


SEVERITY_WEIGHTS = {
    "critical": 35,
    "high": 22,
    "medium": 12,
    "low": 5,
    "info": 0,
}
TRUTH_LABELS = {"VERIFIED", "INFERENCE"}
EVIDENCE_GRADES = {"A", "B", "C", "D"}
AUTHORIZATION_MODES = {"public", "owner", "contract"}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Finding:
    target_id: str
    code: str
    severity: str
    title: str
    detail: str
    truth: str = "VERIFIED"
    confidence: int = 100
    evidence_grade: str = "A"
    evidence: dict[str, Any] = field(default_factory=dict)
    stateful: bool = True

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHTS:
            raise ValueError(f"unsupported severity: {self.severity}")
        if self.truth not in TRUTH_LABELS:
            raise ValueError(f"unsupported truth label: {self.truth}")
        if not 0 <= self.confidence <= 100:
            raise ValueError("confidence must be between 0 and 100")
        if self.evidence_grade not in EVIDENCE_GRADES:
            raise ValueError(f"unsupported evidence grade: {self.evidence_grade}")

    @property
    def fingerprint(self) -> str:
        return stable_hash(f"{self.target_id}\0{self.code}")[:24]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["fingerprint"] = self.fingerprint
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Finding":
        clean = dict(value)
        clean.pop("fingerprint", None)
        return cls(**clean)


@dataclass(frozen=True)
class Observation:
    target_id: str
    kind: str
    ok: bool
    facts: dict[str, Any]
    observed_at: str = field(default_factory=utc_now_iso)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Observation":
        return cls(**value)


class WatchPack(Protocol):
    kind: str
    allowed_authorization_modes: set[str]

    def observe(self, target: dict[str, Any]) -> Observation: ...

    def evaluate(
        self,
        target: dict[str, Any],
        current: Observation,
        previous: Observation | None,
    ) -> list[Finding]: ...


class StateStore:
    """Small atomic JSON state store for baselines and active findings."""

    VERSION = 1
    MAX_STATE_BYTES = 16 * 1024 * 1024

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        state_fd = -1
        try:
            path_stat = os.lstat(self.path)
        except FileNotFoundError:
            return {"version": self.VERSION, "targets": {}}
        if stat.S_ISLNK(path_stat.st_mode):
            raise ValueError("Sentinel state must not be a symbolic link")
        try:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            state_fd = os.open(self.path, flags)
        except FileNotFoundError:
            return {"version": self.VERSION, "targets": {}}
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError("Sentinel state must not be a symbolic link") from exc
            raise

        try:
            state_stat = os.fstat(state_fd)
            if (state_stat.st_dev, state_stat.st_ino) != (
                path_stat.st_dev,
                path_stat.st_ino,
            ):
                raise ValueError("Sentinel state changed while it was being opened")
            if not stat.S_ISREG(state_stat.st_mode):
                raise ValueError("Sentinel state is not a regular file")
            self._secure_loaded_file(state_fd, state_stat)
            if state_stat.st_size > self.MAX_STATE_BYTES:
                raise ValueError("Sentinel state exceeds the size limit")
            raw_chunks: list[bytes] = []
            bytes_remaining = self.MAX_STATE_BYTES + 1
            while bytes_remaining:
                chunk = os.read(state_fd, bytes_remaining)
                if not chunk:
                    break
                raw_chunks.append(chunk)
                bytes_remaining -= len(chunk)
            raw = b"".join(raw_chunks)
        finally:
            os.close(state_fd)

        if len(raw) > self.MAX_STATE_BYTES:
            raise ValueError("Sentinel state exceeds the size limit")
        try:
            payload = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=self._unique_object,
                parse_constant=self._reject_nonfinite,
            )
        except UnicodeDecodeError as exc:
            raise ValueError("Sentinel state is not valid UTF-8 JSON") from exc
        self._validate_payload(payload)
        return payload

    @staticmethod
    def _secure_loaded_file(state_fd: int, state_stat: os.stat_result) -> None:
        effective_uid_fn = getattr(os, "geteuid", None)
        fchmod_fn = getattr(os, "fchmod", None)
        if effective_uid_fn is None or fchmod_fn is None:
            return
        if stat.S_IMODE(state_stat.st_mode) == 0o600:
            return
        if state_stat.st_uid != effective_uid_fn():
            raise PermissionError("Sentinel state permissions cannot be secured")
        fchmod_fn(state_fd, 0o600)
        if stat.S_IMODE(os.fstat(state_fd).st_mode) != 0o600:
            raise PermissionError("Sentinel state permissions cannot be secured")
        os.fsync(state_fd)

    def save(self, payload: dict[str, Any]) -> None:
        self._validate_payload(payload)
        try:
            encoded = (
                json.dumps(
                    payload,
                    allow_nan=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("Sentinel state is not JSON-serializable") from exc
        if len(encoded) > self.MAX_STATE_BYTES:
            raise ValueError("Sentinel state exceeds the size limit")

        self._prepare_parent()
        temporary_path: Path | None = None
        temporary_fd = -1
        try:
            temporary_fd, temporary_name = tempfile.mkstemp(
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
            )
            temporary_path = Path(temporary_name)
            os.fchmod(temporary_fd, 0o600)
            with os.fdopen(temporary_fd, "wb") as temporary_file:
                temporary_fd = -1
                temporary_file.write(encoded)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())

            os.replace(temporary_path, self.path)
            temporary_path = None
            self._fsync_parent()
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass

    @staticmethod
    def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Sentinel state contains a duplicate object key")
            result[key] = value
        return result

    @staticmethod
    def _reject_nonfinite(value: str) -> Any:
        raise ValueError("Sentinel state contains a non-finite number")

    @classmethod
    def _validate_payload(cls, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise ValueError("invalid Sentinel state")
        if type(payload.get("version")) is not int or payload["version"] != cls.VERSION:
            raise ValueError("unsupported Sentinel state version")
        if not isinstance(payload.get("targets"), dict):
            raise ValueError("invalid Sentinel state")
        for target_id, target_state in payload["targets"].items():
            if not isinstance(target_id, str) or not target_id:
                raise ValueError("invalid Sentinel target state")
            if not isinstance(target_state, dict):
                raise ValueError("invalid Sentinel target state")
            observation = target_state.get("observation")
            if observation is not None and not isinstance(observation, dict):
                raise ValueError("invalid Sentinel observation state")
            last_successful_observation = target_state.get(
                "last_successful_observation"
            )
            if (
                last_successful_observation is not None
                and not isinstance(last_successful_observation, dict)
            ):
                raise ValueError("invalid Sentinel observation state")
            active_findings = target_state.get("active_findings")
            if active_findings is not None:
                if not isinstance(active_findings, dict):
                    raise ValueError("invalid Sentinel finding state")
                for fingerprint, finding in active_findings.items():
                    if not isinstance(fingerprint, str) or not fingerprint:
                        raise ValueError("invalid Sentinel finding state")
                    if not isinstance(finding, dict):
                        raise ValueError("invalid Sentinel finding state")
        cls._validate_json_value(payload)

    @classmethod
    def _validate_json_value(cls, value: Any) -> None:
        if value is None or isinstance(value, (str, bool)):
            return
        if type(value) is int:
            return
        if type(value) is float:
            if not math.isfinite(value):
                raise ValueError("Sentinel state contains a non-finite number")
            return
        if isinstance(value, dict):
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise ValueError("Sentinel state contains a non-string object key")
                cls._validate_json_value(nested)
            return
        if isinstance(value, list):
            for nested in value:
                cls._validate_json_value(nested)
            return
        raise ValueError("Sentinel state contains a non-JSON value")

    def _prepare_parent(self) -> None:
        parent = self.path.parent
        created = False
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=False)
            created = True
        except FileExistsError:
            pass
        parent_stat = parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise ValueError("Sentinel state parent is not a directory")
        if created:
            os.chmod(parent, 0o700)

    def _fsync_parent(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        parent_fd = os.open(self.path.parent, flags)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


class SentinelEngine:
    """Runs watch packs, diffs state, and emits only new or resolved findings."""

    def __init__(self, state_store: StateStore, packs: list[WatchPack]):
        self.state_store = state_store
        self.packs = {pack.kind: pack for pack in packs}

    def run(self, targets: list[dict[str, Any]]) -> dict[str, Any]:
        state = self.state_store.load()
        results = [self._run_target(target, state) for target in targets]
        self.state_store.save(state)
        output = {
            "generated_at": utc_now_iso(),
            "notify": any(result["new_alerts"] or result["resolved"] for result in results),
            "targets_checked": len(results),
            "new_alert_count": sum(len(result["new_alerts"]) for result in results),
            "resolved_count": sum(len(result["resolved"]) for result in results),
            "results": results,
        }
        output["discernment"] = build_discernment(results)
        return output

    def _run_target(
        self,
        target: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        target_id = str(target.get("id", "")).strip()
        kind = str(target.get("kind", "")).strip()
        if not target_id or not kind:
            raise ValueError("each target requires non-empty id and kind")
        pack = self.packs.get(kind)
        if pack is None:
            raise ValueError(f"no watch pack registered for kind: {kind}")

        target_state = state["targets"].get(target_id, {})
        latest_data = target_state.get("observation")
        last_successful_data = target_state.get("last_successful_observation")
        # A failed/denied run remains the latest audit observation, but packs
        # compare against the last observation that completed successfully.
        # This keeps event watermarks stable across transient failures.
        previous_data = last_successful_data or latest_data
        previous = Observation.from_dict(previous_data) if previous_data else None
        prior_active = {
            key: Finding.from_dict(value)
            for key, value in target_state.get("active_findings", {}).items()
        }

        denial = self._authorization_denial(target, pack)
        preserve_prior_active = False
        evaluation_succeeded = False
        if denial:
            current = Observation(
                target_id=target_id,
                kind=kind,
                ok=False,
                facts={"blocked": True, "reason": denial.detail},
            )
            findings = [denial]
            preserve_prior_active = True
        else:
            try:
                current = pack.observe(target)
                findings = pack.evaluate(target, current, previous)
                evaluation_succeeded = True
                preserve_prior_active = (
                    current.facts.get("preserve_prior_active_findings") is True
                )
            except Exception as exc:  # A pack failure becomes review evidence.
                current = Observation(
                    target_id=target_id,
                    kind=kind,
                    ok=False,
                    facts={
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:300],
                    },
                )
                findings = [
                    Finding(
                        target_id=target_id,
                        code="PACK_EXECUTION_FAILED",
                        severity="high",
                        title="Watch pack could not complete",
                        detail="The target was not fully observed; human review is required.",
                        evidence=current.facts,
                    )
                ]
                preserve_prior_active = True

        if preserve_prior_active:
            current_fingerprints = {
                finding.fingerprint
                for finding in findings
                if finding.stateful
            }
            findings.extend(
                finding
                for fingerprint, finding in prior_active.items()
                if fingerprint not in current_fingerprints
            )

        active = {
            finding.fingerprint: finding
            for finding in findings
            if finding.stateful
        }
        events = [finding for finding in findings if not finding.stateful]
        new_alerts = [
            finding.to_dict()
            for fingerprint, finding in active.items()
            if fingerprint not in prior_active
        ] + [finding.to_dict() for finding in events]
        resolved = [
            {
                **finding.to_dict(),
                "resolved_at": current.observed_at,
            }
            for fingerprint, finding in prior_active.items()
            if fingerprint not in active
        ]
        score = max(
            0,
            100 - sum(SEVERITY_WEIGHTS[item.severity] for item in findings),
        )
        verdict = self._verdict(findings)

        next_target_state = {
            "observation": current.to_dict(),
            "active_findings": {
                fingerprint: finding.to_dict()
                for fingerprint, finding in active.items()
            },
        }
        if not (
            evaluation_succeeded
            and current.ok
            and not preserve_prior_active
        ):
            baseline_data = last_successful_data
            if baseline_data is None and latest_data is not None:
                latest = Observation.from_dict(latest_data)
                if (
                    latest.ok
                    and latest.facts.get("preserve_prior_active_findings")
                    is not True
                ):
                    baseline_data = latest_data
            if baseline_data is not None:
                next_target_state["last_successful_observation"] = baseline_data
        state["targets"][target_id] = next_target_state
        return {
            "target_id": target_id,
            "kind": kind,
            "observed_at": current.observed_at,
            "verdict": verdict,
            "dawg_score": score,
            "evidence_sources": list(current.evidence),
            "current_findings": [explain_finding(item.to_dict()) for item in findings],
            "new_alerts": [explain_finding(item) for item in new_alerts],
            "resolved": [explain_finding(item) for item in resolved],
        }

    @staticmethod
    def _authorization_denial(
        target: dict[str, Any],
        pack: WatchPack,
    ) -> Finding | None:
        authorization = target.get("authorization")
        mode = authorization.get("mode") if isinstance(authorization, dict) else None
        target_id = str(target.get("id", "unknown"))
        if mode not in AUTHORIZATION_MODES:
            return Finding(
                target_id=target_id,
                code="AUTHORIZATION_REQUIRED",
                severity="critical",
                title="Target blocked: authorization missing or unsupported",
                detail="Declare a supported public, owner, or contract authority before observation.",
            )
        if mode not in pack.allowed_authorization_modes:
            return Finding(
                target_id=target_id,
                code="AUTHORIZATION_SCOPE_DENIED",
                severity="critical",
                title="Target blocked: authority is insufficient",
                detail=f"The {pack.kind} pack does not permit authorization mode {mode}.",
            )
        return None

    @staticmethod
    def _verdict(findings: Any) -> str:
        severities = {finding.severity for finding in findings}
        if severities & {"critical", "high", "medium"}:
            return "REVIEW"
        if severities:
            return "WATCH"
        return "VERIFIED"
