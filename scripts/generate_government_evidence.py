from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from verify_supply_chain import inspect_root


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = {
    "source_hashes": "source-sha256.json",
    "sbom": "sbom.spdx.json",
    "control_crosswalk": "government-control-matrix.json",
    "supply_chain_report": "supply-chain-report.json",
}
MANIFEST_NAME = "evidence-manifest.json"
REGULAR_GIT_MODES = frozenset({"100644", "100755"})
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(RuntimeError):
    """Raised when an evidence bundle cannot be produced safely."""


def _run_git(root: Path, arguments: list[str]) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceError(f"git {' '.join(arguments)} failed: {detail or 'unknown error'}")
    return completed.stdout


def revision(root: Path = ROOT) -> str:
    value = _run_git(root, ["rev-parse", "--verify", "HEAD"]).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise EvidenceError("git rev-parse did not return a full commit SHA")
    return value


def workspace_dirty(root: Path = ROOT) -> bool:
    status = _run_git(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    return bool(status)


def _tracked_entries(root: Path) -> list[tuple[Path, str]]:
    raw_entries = _run_git(root, ["ls-files", "--cached", "--stage", "-z"])
    entries: list[tuple[Path, str]] = []
    seen: set[str] = set()
    for raw_entry in raw_entries.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, _object_id, stage = metadata.decode("ascii").split()
        except (UnicodeDecodeError, ValueError) as error:
            raise EvidenceError("git ls-files returned an invalid index entry") from error
        relative_text = os.fsdecode(raw_path)
        relative = Path(relative_text)
        if (
            not relative_text
            or relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise EvidenceError(f"unsafe tracked path: {relative_text!r}")
        normalized = relative.as_posix()
        if normalized in seen:
            raise EvidenceError(f"duplicate or unmerged tracked path: {normalized}")
        seen.add(normalized)
        if stage != "0":
            raise EvidenceError(f"unmerged tracked path is not evidence-ready: {normalized}")
        if mode not in REGULAR_GIT_MODES:
            kind = "symlink" if mode == "120000" else f"special index mode {mode}"
            raise EvidenceError(f"tracked {kind} is not allowed in evidence: {normalized}")
        entries.append((relative, mode))
    return sorted(entries, key=lambda entry: entry[0].as_posix())


def _read_regular_file(root: Path, relative: Path) -> bytes:
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise EvidenceError(f"cannot inspect tracked path component: {relative.as_posix()}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError(f"tracked path crosses a symlink: {relative.as_posix()}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceError(f"tracked path parent is not a directory: {relative.as_posix()}")

    path = root / relative
    try:
        before = os.lstat(path)
    except OSError as error:
        raise EvidenceError(f"tracked file is missing: {relative.as_posix()}") from error
    if stat.S_ISLNK(before.st_mode):
        raise EvidenceError(f"tracked symlink is not allowed in evidence: {relative.as_posix()}")
    if not stat.S_ISREG(before.st_mode):
        raise EvidenceError(f"tracked special file is not allowed in evidence: {relative.as_posix()}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError(f"cannot safely open tracked file: {relative.as_posix()}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise EvidenceError(f"tracked special file is not allowed in evidence: {relative.as_posix()}")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise EvidenceError(f"tracked file changed while being opened: {relative.as_posix()}")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 128 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def tracked_snapshot(root: Path = ROOT) -> dict[Path, bytes]:
    root = root.absolute()
    return {
        relative: _read_regular_file(root, relative)
        for relative, _mode in _tracked_entries(root)
    }


def source_files(root: Path = ROOT) -> list[Path]:
    """Return every tracked regular file, including extensionless deployment assets."""
    root = root.absolute()
    return [root / relative for relative, _mode in _tracked_entries(root)]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _decode_text(relative: Path, payload: bytes) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"expected UTF-8 text in {relative.as_posix()}") from error


def packages(snapshot: dict[Path, bytes]) -> list[dict[str, Any]]:
    discovered: dict[tuple[str, str], dict[str, Any]] = {}
    for requirements in sorted(path for path in snapshot if path.name == "requirements.txt"):
        for line in _decode_text(requirements, snapshot[requirements]).splitlines():
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
    for lock_path in sorted(path for path in snapshot if path.name == "package-lock.json"):
        try:
            lock = json.loads(_decode_text(lock_path, snapshot[lock_path]))
        except json.JSONDecodeError as error:
            raise EvidenceError(f"invalid package lock: {lock_path.as_posix()}") from error
        if not isinstance(lock, dict):
            raise EvidenceError(f"package lock must contain an object: {lock_path.as_posix()}")
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


def _generated_at() -> str:
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_date_epoch is not None:
        try:
            moment = datetime.fromtimestamp(int(source_date_epoch), timezone.utc)
        except (OverflowError, ValueError) as error:
            raise EvidenceError("SOURCE_DATE_EPOCH must be an integer Unix timestamp") from error
    else:
        moment = datetime.now(timezone.utc)
    return moment.isoformat()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _assert_directory_path_safe(path: Path, *, create: bool) -> Path:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            if not create:
                raise EvidenceError(f"directory does not exist: {absolute}")
            current.mkdir()
            metadata = os.lstat(current)
        except OSError as error:
            raise EvidenceError(f"cannot inspect directory: {absolute}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError(f"directory path crosses a symlink: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceError(f"path component is not a directory: {current}")
    return absolute


def _write_artifact(path: Path, payload: bytes) -> None:
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        raise EvidenceError(f"refusing to replace non-regular artifact: {path.name}")

    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _artifact_record(output: Path, filename: str) -> dict[str, Any]:
    payload = _read_regular_file(output, Path(filename))
    return {"path": filename, "bytes": len(payload), "sha256": _sha256(payload)}


def build_bundle(
    root: Path,
    output: Path,
    *,
    allow_dirty: bool = False,
) -> dict[str, Any]:
    root = _assert_directory_path_safe(root, create=False)
    dirty_at_start = workspace_dirty(root)
    if dirty_at_start and not allow_dirty:
        raise EvidenceError("working tree is dirty; commit/stash changes or pass --allow-dirty for local use")

    current_revision = revision(root)
    snapshot = tracked_snapshot(root)
    output = _assert_directory_path_safe(output, create=True)
    allowed_output_names = {*ARTIFACTS.values(), MANIFEST_NAME}
    unexpected = sorted(path.name for path in output.iterdir() if path.name not in allowed_output_names)
    if unexpected:
        raise EvidenceError(f"output directory contains unmanifested entries: {', '.join(unexpected)}")

    inventory = [
        {
            "path": relative.as_posix(),
            "sha256": _sha256(payload),
            "bytes": len(payload),
        }
        for relative, payload in snapshot.items()
    ]
    source_hashes = _json_bytes({"files": inventory})
    generated_at = _generated_at()
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
        "packages": packages(snapshot),
    }
    matrix_path = Path("docs/government-control-matrix.json")
    if matrix_path not in snapshot:
        raise EvidenceError("tracked control matrix is required: docs/government-control-matrix.json")

    artifact_payloads = {
        "source_hashes": source_hashes,
        "sbom": _json_bytes(sbom),
        "control_crosswalk": snapshot[matrix_path],
        "supply_chain_report": _json_bytes(inspect_root(root)),
    }
    for role, filename in ARTIFACTS.items():
        _write_artifact(output / filename, artifact_payloads[role])

    dirty_at_end = workspace_dirty(root)
    if dirty_at_end and not allow_dirty:
        raise EvidenceError("working tree changed while evidence was being generated")
    manifest = {
        "schema_version": 2,
        "generated_at": generated_at,
        "revision": current_revision,
        "workspace_dirty": dirty_at_start or dirty_at_end,
        "claim": (
            "Evidence bundle only; it is not a certification, authorization, "
            "attestation, or cryptographic signature."
        ),
        "artifacts": {
            role: _artifact_record(output, filename)
            for role, filename in sorted(ARTIFACTS.items())
        },
        "verification_commands": [
            "npm test",
            "python -m compileall -q sentinel scripts",
            "python -m unittest discover -s sentinel/tests -v",
            "bash -n sentinel/scripts/*.sh",
            "python scripts/verify_supply_chain.py",
            f"python scripts/generate_government_evidence.py --verify {output}",
            "docker build --tag watch-dawg-sentinel-api:test -f sentinel/Dockerfile .",
        ],
    }
    _write_artifact(output / MANIFEST_NAME, _json_bytes(manifest))
    verification = verify_bundle(output)
    if not verification["valid"]:
        raise EvidenceError("generated bundle failed self-verification: " + "; ".join(verification["errors"]))
    return manifest


def _safe_manifest_path(value: Any) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    pure = PurePosixPath(value)
    if pure.is_absolute() or len(pure.parts) != 1 or pure.as_posix() != value:
        return None
    if pure.parts[0] in {".", "..", MANIFEST_NAME}:
        return None
    return Path(value)


def verify_bundle(bundle: Path) -> dict[str, Any]:
    errors: list[str] = []
    checked = 0
    try:
        bundle = _assert_directory_path_safe(bundle, create=False)
        manifest_payload = _read_regular_file(bundle, Path(MANIFEST_NAME))
        manifest = json.loads(manifest_payload.decode("utf-8"))
    except (EvidenceError, OSError, UnicodeError, json.JSONDecodeError) as error:
        return {"valid": False, "artifacts_checked": 0, "errors": [str(error)]}

    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
    if not isinstance(artifacts, dict) or not artifacts:
        return {
            "valid": False,
            "artifacts_checked": 0,
            "errors": ["manifest artifacts must be a non-empty object"],
        }

    expected_names = {MANIFEST_NAME}
    for role, record in sorted(artifacts.items()):
        if not isinstance(role, str) or not isinstance(record, dict):
            errors.append("manifest contains an invalid artifact record")
            continue
        relative = _safe_manifest_path(record.get("path"))
        expected_bytes = record.get("bytes")
        expected_sha256 = record.get("sha256")
        if relative is None:
            errors.append(f"artifact {role!r} has an unsafe path")
            continue
        if relative.name in expected_names:
            errors.append(f"artifact path is duplicated: {relative.name}")
            continue
        expected_names.add(relative.name)
        if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool) or expected_bytes < 0:
            errors.append(f"artifact {relative.name} has an invalid byte count")
            continue
        if not isinstance(expected_sha256, str) or SHA256.fullmatch(expected_sha256) is None:
            errors.append(f"artifact {relative.name} has an invalid SHA-256")
            continue
        try:
            payload = _read_regular_file(bundle, relative)
        except EvidenceError as error:
            errors.append(str(error))
            continue
        checked += 1
        if len(payload) != expected_bytes:
            errors.append(
                f"artifact byte count mismatch: {relative.name} "
                f"(expected {expected_bytes}, found {len(payload)})"
            )
        actual_sha256 = _sha256(payload)
        if actual_sha256 != expected_sha256:
            errors.append(f"artifact SHA-256 mismatch: {relative.name}")

    try:
        actual_names: set[str] = set()
        for path in bundle.iterdir():
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode):
                errors.append(f"bundle contains a non-regular entry: {path.name}")
            actual_names.add(path.name)
        for unexpected in sorted(actual_names - expected_names):
            errors.append(f"bundle contains an unmanifested artifact: {unexpected}")
        for missing in sorted(expected_names - actual_names):
            errors.append(f"bundle artifact is missing: {missing}")
    except OSError as error:
        errors.append(f"cannot enumerate bundle artifacts: {error}")

    return {"valid": not errors, "artifacts_checked": checked, "errors": errors}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build or verify a reviewable Watch-Dawg evidence bundle")
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--output", type=Path, help="directory in which to build the bundle")
    operation.add_argument("--verify", type=Path, metavar="BUNDLE", help="verify an existing bundle")
    parser.add_argument("--root", type=Path, default=ROOT, help="Git work tree to snapshot")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="allow a dirty local work tree and mark the bundle accordingly",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.verify is not None:
            if args.allow_dirty:
                raise EvidenceError("--allow-dirty only applies when building a bundle")
            report = verify_bundle(args.verify)
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if report["valid"] else 1
        build_bundle(args.root, args.output, allow_dirty=args.allow_dirty)
        return 0
    except EvidenceError as error:
        print(f"evidence error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
