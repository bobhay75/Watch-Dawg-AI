#!/usr/bin/env python3
"""Bootstrap a private policy without printing or overwriting tokens."""

import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.security import Policy, SCOPES  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument(
        "--scope", action="append", choices=sorted(SCOPES), required=True
    )
    parser.add_argument("--host", action="append", required=True)
    parser.add_argument("--network", action="append", required=True)
    parser.add_argument("--origin", action="append", default=[])
    parser.add_argument(
        "--transport", choices=["https", "proxy", "loopback"], default="https"
    )
    parser.add_argument("--proxy-network", action="append", default=[])
    parser.add_argument("--days", type=int, default=7)
    args = parser.parse_args()
    try:
        if not 1 <= args.days <= 90:
            raise ValueError("Invalid expiry")
        token = "wd_" + secrets.token_urlsafe(32)
        doc = {
            "rate_hmac_key": secrets.token_hex(32),
            "allowed_hosts": args.host,
            "allowed_networks": args.network,
            "allowed_origins": args.origin,
            "transport": args.transport,
            "trusted_proxy_networks": args.proxy_network,
            "principals": [
                {
                    "id": args.principal,
                    "scopes": args.scope,
                    "token_sha256": [
                        hashlib.sha256(token.encode()).hexdigest()
                    ],
                    "expires_at": (
                        datetime.now(timezone.utc) + timedelta(days=args.days)
                    ).isoformat(),
                }
            ],
        }
        Policy.parse(doc)
        root = Path(args.output_dir)
        root.mkdir(mode=0o700, parents=False, exist_ok=True)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (
                info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise ValueError("Private directory required")
            for name, data in [
                ("token", token + "\n"),
                ("security.json", json.dumps(doc, indent=2) + "\n"),
            ]:
                out = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=fd,
                )
                with os.fdopen(out, "w", encoding="utf-8") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
        finally:
            os.close(fd)
    except (OSError, ValueError):
        parser.exit(
            1,
            "Creation refused. Use an owned private directory "
            "and valid policy; "
            "existing files were not overwritten.\n",
        )
    print("Created private token and policy files. No credential was printed.")


if __name__ == "__main__":
    main()
