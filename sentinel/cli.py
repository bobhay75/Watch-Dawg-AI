from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .core import SentinelEngine, StateStore
from .http_watch import HttpWatchPack
from .log_watch import AccessLogWatchPack


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
    engine = SentinelEngine(
        StateStore(args.state),
        [HttpWatchPack(), AccessLogWatchPack(log_root)],
    )
    result = engine.run(config["targets"])
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if args.fail_on_alert and result["notify"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

