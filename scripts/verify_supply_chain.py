from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


ACTION_PATTERN = re.compile(r"\buses:\s*([^\s#]+)")
FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _issue(level: str, code: str, path: Path, detail: str) -> dict[str, str]:
    return {"level": level, "code": code, "path": path.as_posix(), "detail": detail}


def inspect_root(root: Path) -> dict[str, Any]:
    root = root.resolve()
    issues: list[dict[str, str]] = []
    actions_checked = 0
    dependencies_checked = 0
    containers_checked = 0

    for workflow in sorted((root / ".github/workflows").glob("*.y*ml")):
        relative = workflow.relative_to(root)
        for action in ACTION_PATTERN.findall(workflow.read_text(encoding="utf-8")):
            if action.startswith("./"):
                continue
            actions_checked += 1
            name, separator, reference = action.rpartition("@")
            if not separator or not name or not FULL_COMMIT.fullmatch(reference):
                issues.append(_issue(
                    "error",
                    "ACTION_NOT_COMMIT_PINNED",
                    relative,
                    f"{action} must use a full 40-character commit SHA",
                ))

    for requirements in sorted(root.rglob("requirements.txt")):
        if any(part in {".git", "build", "node_modules"} for part in requirements.relative_to(root).parts):
            continue
        relative = requirements.relative_to(root)
        for line_number, line in enumerate(requirements.read_text(encoding="utf-8").splitlines(), start=1):
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            dependencies_checked += 1
            pinned = "==" in value or (" @ https://" in value and "#sha256=" in value)
            if not pinned:
                issues.append(_issue(
                    "error",
                    "PYTHON_DEPENDENCY_NOT_PINNED",
                    relative,
                    f"line {line_number} is not exact-version or hash pinned",
                ))

    for package_json in sorted(root.rglob("package.json")):
        relative = package_json.relative_to(root)
        if any(part in {".git", "build", "node_modules"} for part in relative.parts):
            continue
        payload = json.loads(package_json.read_text(encoding="utf-8"))
        dependency_count = sum(
            len(payload.get(key, {}))
            for key in ("dependencies", "devDependencies", "optionalDependencies")
        )
        dependencies_checked += dependency_count
        if dependency_count and not (package_json.parent / "package-lock.json").is_file():
            issues.append(_issue(
                "error",
                "NODE_LOCKFILE_MISSING",
                relative,
                "package dependencies require a committed package-lock.json",
            ))

    for dockerfile in sorted(root.rglob("Dockerfile")):
        relative = dockerfile.relative_to(root)
        if any(part in {".git", "build", "node_modules"} for part in relative.parts):
            continue
        for line_number, line in enumerate(dockerfile.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if not stripped.upper().startswith("FROM "):
                continue
            containers_checked += 1
            image = stripped.split()[1]
            if image.endswith(":latest") or (":" not in image and "@sha256:" not in image):
                issues.append(_issue(
                    "error",
                    "CONTAINER_BASE_FLOATS_ON_LATEST",
                    relative,
                    f"line {line_number} uses an unversioned base image",
                ))
            elif "@sha256:" not in image:
                issues.append(_issue(
                    "warning",
                    "CONTAINER_BASE_NOT_DIGEST_PINNED",
                    relative,
                    f"line {line_number} is version-tagged but not digest-pinned: {image}",
                ))

    errors = [item for item in issues if item["level"] == "error"]
    warnings = [item for item in issues if item["level"] == "warning"]
    return {
        "schema_version": 1,
        "status": "FAIL" if errors else "PASS_WITH_WARNINGS" if warnings else "PASS",
        "summary": {
            "actions_checked": actions_checked,
            "dependencies_checked": dependencies_checked,
            "container_bases_checked": containers_checked,
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "issues": issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify reproducible dependency boundaries")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = inspect_root(args.root)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 1 if report["summary"]["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
