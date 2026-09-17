from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .ai_system_watch import AiSystemRiskWatchPack
from .core import SentinelEngine, StateStore
from .domain_watch import DnsTlsWatchPack
from .http_watch import HttpWatchPack
from .log_watch import AccessLogWatchPack
from .secret_watch import SecretExposureWatchPack
from .service_watch import ServiceExposureWatchPack
from .sitemap_watch import SitemapWatchPack


def load_config(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload.get("targets"), list):
        raise ValueError("config requires a targets list")
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Watch-Dawg Sentinel once")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--state", type=Path, default=Path(".sentinel/state.json"))
    parser.add_argument("--fail-on-alert", action="store_true")
    return parser


def exit_code_for_result(result: dict[str, Any], fail_on_alert: bool) -> int:
    """Fail on current unhealthy state, not only newly emitted events."""
    has_alert = bool(result.get("notify")) or not result.get("healthy", False)
    return 2 if fail_on_alert and has_alert else 0


def main() -> int:
    args = build_parser().parse_args()
    config = load_config(args.config)
    log_root = Path(config.get("log_root", "."))
    secret_root = Path(config.get("secret_root", "."))
    ai_manifest_root = Path(config.get("ai_manifest_root", "."))
    engine = SentinelEngine(
        StateStore(args.state),
        [
            HttpWatchPack(),
            DnsTlsWatchPack(),
            SitemapWatchPack(),
            AccessLogWatchPack(log_root),
            ServiceExposureWatchPack(),
            SecretExposureWatchPack(secret_root),
            AiSystemRiskWatchPack(ai_manifest_root),
        ],
    )
    result = engine.run(config["targets"])
    print(json.dumps(result, indent=2, sort_keys=True))
    return exit_code_for_result(result, args.fail_on_alert)


if __name__ == "__main__":
    raise SystemExit(main())
