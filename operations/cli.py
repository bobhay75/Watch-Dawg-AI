"""Explicit local operations. Never deploys, uploads or publishes
intelligence.
"""

import argparse
import json
from pathlib import Path
import secrets
import sys
import tempfile

from .backups import backup, restore
from .files import canonical, digest, read_private, write_new
from .tokens import prepare_rotation, stage_revocation, install
from .review_records import append


def synthetic_drill(workspace):
    workspace = Path(workspace)
    with tempfile.TemporaryDirectory(
        prefix="synthetic-drill-", dir=workspace
    ) as temp:
        root = Path(temp)
        source = root / "synthetic"
        source.mkdir(mode=0o700)
        write_new(
            source / "fixture.json",
            canonical({"synthetic": True, "public_release_approved": False}),
        )
        key = root / "key"
        write_new(key, secrets.token_bytes(32))
        encrypted = root / "backup.wdb"
        receipt = backup(source, key, encrypted)
        recovered = root / "restored"
        restore(encrypted, key, recovered, str(encrypted) + ".receipt.json")
        if (source / "fixture.json").read_bytes() != (
            recovered / "fixture.json"
        ).read_bytes():
            raise ValueError("Synthetic restore mismatch")
        return {
            "synthetic_drill": "passed",
            "ciphertext_sha256": receipt["ciphertext_sha256"],
            "public_release_approved": False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("backup", "restore"):
        p = sub.add_parser(command)
        p.add_argument("--key-file", required=True)
        p.add_argument("--destination", required=True)
        p.add_argument("--source", required=True)
        if command == "restore":
            p.add_argument("--receipt", required=True)
    p = sub.add_parser("keygen")
    p.add_argument("--output", required=True)
    p = sub.add_parser("drill")
    p.add_argument("--workspace", required=True)
    p = sub.add_parser("rotate")
    p.add_argument("--policy", required=True)
    p.add_argument("--principal", required=True)
    p.add_argument("--output-directory", required=True)
    p = sub.add_parser("revoke")
    p.add_argument("--policy", required=True)
    p.add_argument("--principal", required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("install-policy")
    p.add_argument("--staged", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--expected-sha256", required=True)
    p = sub.add_parser("review")
    p.add_argument("--journal", required=True)
    p.add_argument("--reviewer", required=True)
    p.add_argument("--key-file", required=True)
    p.add_argument("--registry", required=True)
    p.add_argument("--evidence-sha256", required=True)
    p.add_argument("--note-file", required=True)
    p.add_argument(
        "--decision",
        required=True,
        choices=["reviewed_private", "needs_more_evidence", "rejected"],
    )
    args = parser.parse_args()
    try:
        result = {"public_release_approved": False}
        if args.command == "backup":
            result = backup(args.source, args.key_file, args.destination)
        elif args.command == "restore":
            result = restore(
                args.source, args.key_file, args.destination, args.receipt
            )
        elif args.command == "keygen":
            write_new(args.output, secrets.token_bytes(32))
        elif args.command == "drill":
            result = synthetic_drill(args.workspace)
        elif args.command == "rotate":
            result = prepare_rotation(
                args.policy, args.principal, args.output_directory
            )
        elif args.command == "revoke":
            stage_revocation(args.policy, args.principal, args.output)
        elif args.command == "install-policy":
            if (
                not sys.stdin.isatty()
                or input("Type INSTALL " + args.expected_sha256 + ": ")
                != "INSTALL " + args.expected_sha256
            ):
                raise ValueError("Interactive approval required")
            install(args.staged, args.target, args.expected_sha256)
        elif args.command == "review":
            confirmation = "REVIEW " + args.evidence_sha256
            if (
                not sys.stdin.isatty()
                or input("Type " + confirmation + ": ") != confirmation
            ):
                raise ValueError("Interactive human review required")
            registry = {
                k: bytes.fromhex(v)
                for k, v in json.loads(read_private(args.registry)).items()
            }
            row = append(
                args.journal,
                args.reviewer,
                read_private(args.key_file, 32),
                registry,
                args.evidence_sha256,
                digest(read_private(args.note_file)),
                args.decision,
                confirmation,
            )
            result["review_record_sha256"] = digest(canonical(row))
        print(json.dumps(result, sort_keys=True))
    except Exception:
        parser.exit(
            1,
            "Operation refused or failed; inspect private local state. "
            "No upload or publication occurred.\n",
        )


if __name__ == "__main__":
    main()
