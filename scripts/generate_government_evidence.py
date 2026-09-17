from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from verify_supply_chain import inspect_root


ROOT = Path(__file__).resolve().parents[1]
INCLUDED_SUFFIXES = {".js", ".json", ".md", ".mjs", ".py", ".sh", ".ts", ".tsx", ".yml", ".yaml"}
EXCLUDED_PARTS = {".git", ".sentinel", "build", "node_modules", "test_reports"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.suffix.lower() in INCLUDED_SUFFIXES
        and not EXCLUDED_PARTS.intersection(path.relative_to(ROOT).parts)
    )


def revision() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def workspace_dirty() -> bool:
    completed = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode != 0 or bool(completed.stdout.strip())


def packages() -> list[dict[str, Any]]:
    discovered: dict[tuple[str, str], dict[str, Any]] = {}
    for requirements in ROOT.rglob("requirements.txt"):
        if EXCLUDED_PARTS.intersection(requirements.relative_to(ROOT).parts):
            continue
        for line in requirements.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            name, separator, version = value.partition("==")
            key = (name.strip(), version.strip() if separator else "NOASSERTION")
            discovered[key] = {
                "SPDXID": f"SPDXRef-Package-pypi-{hashlib.sha256(str(key).encode()).hexdigest()[:12]}",
                "name": key[0],
                "versionInfo": key[1],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "supplier": "NOASSERTION",
            }
    for lock_path in ROOT.rglob("package-lock.json"):
        if EXCLUDED_PARTS.intersection(lock_path.relative_to(ROOT).parts):
            continue
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        for location, metadata in lock.get("packages", {}).items():
            if not location.startswith("node_modules/") or not isinstance(metadata, dict):
                continue
            name = location.removeprefix("node_modules/")
            version = str(metadata.get("version", "NOASSERTION"))
            key = (name, version)
            discovered[key] = {
                "SPDXID": f"SPDXRef-Package-npm-{hashlib.sha256(str(key).encode()).hexdigest()[:12]}",
                "name": name,
                "versionInfo": version,
                "downloadLocation": str(metadata.get("resolved", "NOASSERTION")),
                "filesAnalyzed": False,
                "supplier": "NOASSERTION",
            }
    return [discovered[key] for key in sorted(discovered)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a reviewable Watch-Dawg evidence bundle")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat()
    current_revision = revision()

    inventory = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
        for path in source_files()
    ]
    (output / "source-sha256.json").write_text(
        json.dumps({"files": inventory}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "watch-dawg-ai",
        "documentNamespace": f"https://bobsome1.com/watch-dawg/sbom/{current_revision}",
        "creationInfo": {
            "created": generated_at,
            "creators": ["Tool: Watch-Dawg-government-evidence/1"],
        },
        "packages": packages(),
    }
    (output / "sbom.spdx.json").write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    matrix = ROOT / "docs/government-control-matrix.json"
    (output / "government-control-matrix.json").write_bytes(matrix.read_bytes())
    supply_chain = inspect_root(ROOT)
    (output / "supply-chain-report.json").write_text(
        json.dumps(supply_chain, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest = {
        "schema_version": 1,
        "generated_at": generated_at,
        "revision": current_revision,
        "workspace_dirty": workspace_dirty(),
        "claim": "Evidence bundle only; not a certification or authorization.",
        "artifacts": {
            "source_hashes": "source-sha256.json",
            "sbom": "sbom.spdx.json",
            "control_crosswalk": "government-control-matrix.json",
            "supply_chain_report": "supply-chain-report.json",
        },
        "verification_commands": [
            "npm test",
            "python -m compileall -q sentinel scripts",
            "python -m unittest discover -s sentinel/tests -v",
            "bash -n sentinel/scripts/*.sh",
            "python scripts/verify_supply_chain.py",
            "docker build --tag watch-dawg-sentinel-api:test -f sentinel/Dockerfile .",
        ],
    }
    (output / "evidence-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
