from __future__ import annotations

import argparse
import json
import os
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
from .swarm_proof import load_proof_hmac_key
from .swarm_watch import SwarmDefenseWatchPack


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


def main() -> int:
    args = build_parser().parse_args()
    config = load_config(args.config)
    log_root = Path(config.get("log_root", "."))
    secret_root = Path(config.get("secret_root", "."))
    ai_manifest_root = Path(config.get("ai_manifest_root", "."))
    swarm_snapshot_root = Path(config.get("swarm_snapshot_root", "."))
    proof_hmac_key = load_proof_hmac_key(
        os.environ.get("SENTINEL_SWARM_PROOF_HMAC_KEY_BASE64"),
        required=False,
    )
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
            SwarmDefenseWatchPack(
                swarm_snapshot_root,
                proof_hmac_key=proof_hmac_key,
            ),
        ],
    )
    result = engine.run(config["targets"])
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if args.fail_on_alert and result["notify"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
