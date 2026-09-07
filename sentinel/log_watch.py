from __future__ import annotations

import re
from collections import Counter, deque
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .core import Finding, Observation, stable_hash


ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" (?P<status>\d{3}) (?P<size>\S+)'
)
SUSPICIOUS_PATH_MARKERS = (
    "/.env",
    "/.git",
    "wp-login.php",
    "xmlrpc.php",
    "phpmyadmin",
    "../",
)


class AccessLogWatchPack:
    kind = "access_log"
    allowed_authorization_modes = {"owner", "contract"}

    def __init__(self, log_root: str | Path):
        self.log_root = Path(log_root).resolve()

    def observe(self, target: dict[str, Any]) -> Observation:
        target_id = str(target["id"])
        candidate = (self.log_root / str(target["path"])).resolve()
        if candidate != self.log_root and self.log_root not in candidate.parents:
            raise ValueError("access-log path escapes the configured log root")
        max_lines = min(max(int(target.get("max_lines", 10_000)), 100), 50_000)
        lines: deque[str] = deque(maxlen=max_lines)
        with candidate.open("r", encoding="utf-8", errors="replace") as handle:
            lines.extend(handle)

        statuses: Counter[str] = Counter()
        suspicious_paths: Counter[str] = Counter()
        clients: Counter[str] = Counter()
        parsed = 0
        auth_failures = 0
        server_errors = 0
        for line in lines:
            match = ACCESS_LOG_PATTERN.match(line)
            if not match:
                continue
            parsed += 1
            status = match.group("status")
            path = unquote(match.group("path")).casefold()
            statuses[status] += 1
            clients[stable_hash(match.group("ip"))[:12]] += 1
            if status in {"401", "403"}:
                auth_failures += 1
            if status.startswith("5"):
                server_errors += 1
            if any(marker in path for marker in SUSPICIOUS_PATH_MARKERS):
                suspicious_paths[path[:160]] += 1

        facts = {
            "lines_read": len(lines),
            "requests_parsed": parsed,
            "parse_failures": len(lines) - parsed,
            "status_counts": dict(statuses),
            "server_error_rate": (server_errors / parsed) if parsed else 0.0,
            "auth_failures": auth_failures,
            "suspicious_hits": sum(suspicious_paths.values()),
            "suspicious_paths": dict(suspicious_paths.most_common(10)),
            "top_client_hashes": dict(clients.most_common(10)),
        }
        return Observation(
            target_id=target_id,
            kind=self.kind,
            ok=True,
            facts=facts,
            evidence=[str(candidate)],
        )

    def evaluate(
        self,
        target: dict[str, Any],
        current: Observation,
        previous: Observation | None,
    ) -> list[Finding]:
        checks = target.get("checks", {})
        facts = current.facts
        findings: list[Finding] = []
        max_error_rate = float(checks.get("max_5xx_rate", 0.05))
        if facts["server_error_rate"] > max_error_rate:
            findings.append(self._finding(current, "SERVER_ERROR_RATE_HIGH", "high", "Server error rate crossed the limit", "The observed 5xx rate is above the configured threshold.", {"observed_rate": facts["server_error_rate"], "limit": max_error_rate}))

        suspicious_limit = int(checks.get("max_suspicious_hits", 0))
        if facts["suspicious_hits"] > suspicious_limit:
            findings.append(self._finding(current, "SUSPICIOUS_PATH_ACTIVITY", "medium", "Common probe paths appeared in traffic", "Requests matched common automated probing paths. This is an inference about intent, not proof of compromise.", {"hits": facts["suspicious_hits"], "paths": facts["suspicious_paths"]}, truth="INFERENCE"))

        auth_limit = int(checks.get("max_auth_failures", 20))
        if facts["auth_failures"] > auth_limit:
            findings.append(self._finding(current, "AUTH_FAILURES_HIGH", "medium", "Authentication failures crossed the limit", "The observed 401/403 count is above the configured threshold.", {"observed": facts["auth_failures"], "limit": auth_limit}))

        if facts["lines_read"] and facts["parse_failures"] / facts["lines_read"] > 0.20:
            findings.append(self._finding(current, "LOG_PARSE_COVERAGE_LOW", "low", "Access-log coverage is incomplete", "More than 20% of sampled lines did not match the supported Apache/Nginx combined format.", {"lines": facts["lines_read"], "parse_failures": facts["parse_failures"]}))

        if previous and previous.ok:
            multiplier = float(checks.get("traffic_spike_multiplier", 3.0))
            prior = int(previous.facts.get("requests_parsed", 0))
            current_count = int(facts["requests_parsed"])
            if prior >= 10 and current_count >= prior * multiplier:
                findings.append(self._finding(current, "TRAFFIC_SPIKE", "medium", "Traffic volume spiked", "The sampled request count crossed the configured multiplier versus the prior observation.", {"before": prior, "after": current_count, "multiplier": multiplier}, stateful=False))
        return findings

    @staticmethod
    def _finding(current: Observation, code: str, severity: str, title: str, detail: str, evidence: dict[str, Any], truth: str = "VERIFIED", stateful: bool = True) -> Finding:
        return Finding(
            target_id=current.target_id,
            code=code,
            severity=severity,
            title=title,
            detail=detail,
            truth=truth,
            evidence=evidence,
            stateful=stateful,
        )
