from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit


EXTERNAL_ACTION = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$"
)
CONTAINER_DIGEST = re.compile(r"^[^@$\s]+@sha256:[0-9a-f]{64}$")
REQUIREMENT_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9._-]+(?:\s*,\s*[A-Za-z0-9._-]+)*\])?"
EXACT_REQUIREMENT = re.compile(
    rf"^(?P<name>{REQUIREMENT_NAME})\s*==\s*"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)"
    r"(?:\s*;\s*(?P<marker>.+))?$"
)
DIRECT_REQUIREMENT = re.compile(
    rf"^(?P<name>{REQUIREMENT_NAME})\s*@\s*"
    r"(?P<url>https://\S+?)"
    r"(?:\s+;\s*(?P<marker>.+))?$"
)
SHA256_FRAGMENT = re.compile(r"^sha256=[0-9a-f]{64}$")
NPM_INTEGRITY = re.compile(r"^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$")
YAML_USES_KEY = re.compile(r'''^\s*(?:-\s*)?(?:uses|"uses"|'uses')\s*:\s*(?P<value>.*)$''')
YAML_MAPPING_KEY = re.compile(
    r'''^\s*(?:-\s*)?(?P<key>[A-Za-z0-9_.-]+|"(?:[^"\\]|\\.)*"|'[^']*')'''
    r'''\s*:\s*(?P<value>.*)$'''
)
YAML_BLOCK_SCALAR_VALUE = re.compile(r"^[>|](?:[1-9][+-]?|[+-][1-9]?)?(?:\s+#.*)?$")
YAML_BLOCK_SCALAR = re.compile(
    r'''^\s*(?:-\s*)?(?:[^:#"']+|"(?:[^"\\]|\\.)*"|'[^']*')\s*:\s*'''
    r'''[>|](?:[1-9][+-]?|[+-][1-9]?)?\s*(?:#.*)?$'''
)
MARKER_TOKEN = re.compile(
    r"\s*(?:"
    r"(?P<lparen>\()|(?P<rparen>\))|"
    r"(?P<string>'[^']*'|\"[^\"]*\")|"
    r"(?P<operator>not\s+in\b|===|~=|==|!=|<=|>=|<|>|in\b)|"
    r"(?P<boolean>and\b|or\b)|"
    r"(?P<variable>python_version\b|python_full_version\b|os_name\b|sys_platform\b|"
    r"platform_release\b|platform_system\b|platform_version\b|platform_machine\b|"
    r"platform_python_implementation\b|implementation_name\b|implementation_version\b|"
    r"extra\b|extras\b|dependency_groups\b)"
    r")"
)
SKIPPED_DIRECTORIES = frozenset({
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "bower_components",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
})


def _issue(level: str, code: str, path: Path, detail: str) -> dict[str, str]:
    return {"level": level, "code": code, "path": path.as_posix(), "detail": detail}


def _repository_entries(root: Path) -> tuple[list[Path], list[Path]]:
    """Return regular files and unsupported symlinks without following either."""
    files: list[Path] = []
    symlinks: list[Path] = []
    for directory, child_directories, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        kept_directories: list[str] = []
        for name in sorted(child_directories):
            if name in SKIPPED_DIRECTORIES:
                continue
            candidate = directory_path / name
            if candidate.is_symlink():
                symlinks.append(candidate)
            else:
                kept_directories.append(name)
        child_directories[:] = kept_directories
        for filename in sorted(filenames):
            candidate = directory_path / filename
            if candidate.is_symlink():
                symlinks.append(candidate)
            elif candidate.is_file():
                files.append(candidate)
    return files, symlinks


def _strip_requirement_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quote and character == "\\":
            escaped = True
            continue
        if character in {'"', "'"}:
            quote = None if quote == character else character if quote is None else quote
            continue
        if character == "#" and quote is None and index > 0 and line[index - 1].isspace():
            return line[:index].rstrip()
    return line.strip()


def _tokenize_marker(marker: str) -> list[str] | None:
    tokens: list[str] = []
    position = 0
    while position < len(marker):
        match = MARKER_TOKEN.match(marker, position)
        if not match:
            return None
        tokens.append(match.lastgroup or "")
        position = match.end()
    return tokens


def _valid_marker(marker: str) -> bool:
    tokens = _tokenize_marker(marker)
    if not tokens:
        return False
    position = 0

    def parse_operand() -> bool:
        nonlocal position
        if position < len(tokens) and tokens[position] in {"string", "variable"}:
            position += 1
            return True
        return False

    def parse_term() -> bool:
        nonlocal position
        if position < len(tokens) and tokens[position] == "lparen":
            position += 1
            if not parse_or_expression():
                return False
            if position >= len(tokens) or tokens[position] != "rparen":
                return False
            position += 1
            return True
        if not parse_operand():
            return False
        if position >= len(tokens) or tokens[position] != "operator":
            return False
        position += 1
        return parse_operand()

    def parse_and_expression() -> bool:
        nonlocal position
        if not parse_term():
            return False
        while position < len(tokens) and tokens[position] == "boolean":
            position += 1
            if not parse_term():
                return False
        return True

    def parse_or_expression() -> bool:
        return parse_and_expression()

    return parse_or_expression() and position == len(tokens)


def _valid_requirement(value: str) -> bool:
    exact = EXACT_REQUIREMENT.fullmatch(value)
    if exact:
        version = exact.group("version")
        marker = exact.group("marker")
        return "*" not in version and (marker is None or _valid_marker(marker))

    direct = DIRECT_REQUIREMENT.fullmatch(value)
    if not direct:
        return False
    try:
        parsed_url = urlsplit(direct.group("url"))
        hostname = parsed_url.hostname
        parsed_url.port
    except ValueError:
        return False
    marker = direct.group("marker")
    return (
        parsed_url.scheme == "https"
        and bool(hostname)
        and parsed_url.username is None
        and parsed_url.password is None
        and bool(parsed_url.path)
        and SHA256_FRAGMENT.fullmatch(parsed_url.fragment) is not None
        and (marker is None or _valid_marker(marker))
    )


def _yaml_scalar(value: str) -> str | None:
    value = value.strip()
    if not value or YAML_BLOCK_SCALAR_VALUE.fullmatch(value):
        return None
    if value[0] in {'"', "'"}:
        quote = value[0]
        escaped = False
        for index in range(1, len(value)):
            character = value[index]
            if quote == '"' and character == "\\" and not escaped:
                escaped = True
                continue
            if character == quote and not escaped:
                remainder = value[index + 1:].strip()
                if remainder and not remainder.startswith("#"):
                    return None
                return value[1:index]
            escaped = False
        return None

    comment = re.search(r"\s+#", value)
    if comment:
        value = value[:comment.start()].rstrip()
    return value if value and not any(character.isspace() for character in value) else None


def _quoted_scalar_end(value: str, start: int) -> int | None:
    quote = value[start]
    index = start + 1
    while index < len(value):
        if quote == '"' and value[index] == "\\":
            index += 2
            continue
        if value[index] == quote:
            if quote == "'" and index + 1 < len(value) and value[index + 1] == quote:
                index += 2
                continue
            return index + 1
        index += 1
    return None


def _flow_uses_values(line: str) -> Iterator[str | None]:
    """Extract uses scalars from YAML flow mappings without scanning quoted text."""
    index = 0
    mapping_depth = 0
    entry_start = False
    while index < len(line):
        character = line[index]
        if mapping_depth and entry_start:
            while index < len(line) and line[index].isspace():
                index += 1
            if index >= len(line):
                return
            if line[index] in {'"', "'"}:
                key_end = _quoted_scalar_end(line, index)
                if key_end is None:
                    return
                key = line[index + 1:key_end - 1]
                index = key_end
            else:
                key_match = re.match(r"[A-Za-z0-9_-]+", line[index:])
                if not key_match:
                    entry_start = False
                    continue
                key = key_match.group(0)
                index += len(key)
            while index < len(line) and line[index].isspace():
                index += 1
            if index >= len(line) or line[index] != ":":
                entry_start = False
                continue
            index += 1
            entry_start = False
            if key != "uses":
                continue
            while index < len(line) and line[index].isspace():
                index += 1
            if index >= len(line):
                yield None
                return
            if line[index] in {'"', "'"}:
                value_end = _quoted_scalar_end(line, index)
                if value_end is None:
                    yield None
                    return
                yield _yaml_scalar(line[index:value_end])
                index = value_end
                continue
            value_end = index
            while value_end < len(line) and line[value_end] not in ",}":
                value_end += 1
            yield _yaml_scalar(line[index:value_end])
            index = value_end
            continue

        if character in {'"', "'"}:
            end = _quoted_scalar_end(line, index)
            index = len(line) if end is None else end
        elif character == "#" and (index == 0 or line[index - 1].isspace()):
            return
        elif character == "{":
            mapping_depth += 1
            entry_start = True
            index += 1
        elif character == "}":
            mapping_depth = max(0, mapping_depth - 1)
            entry_start = False
            index += 1
        elif character == "," and mapping_depth:
            entry_start = True
            index += 1
        else:
            index += 1


def _unquote_yaml_key(key: str) -> str:
    return key[1:-1] if len(key) >= 2 and key[0] in {'"', "'"} else key


def _valid_uses_context(context: list[str]) -> bool:
    return (
        len(context) == 3 and context[0] == "jobs" and context[2] == "steps"
    ) or context == ["runs", "steps"] or (
        len(context) == 2 and context[0] == "jobs"
    )


def _uses_values(path: Path) -> Iterator[tuple[int, str | None]]:
    block_scalar_indent: int | None = None
    context: list[tuple[int, str]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        indentation = len(line) - len(line.lstrip(" "))
        if block_scalar_indent is not None:
            if not line.strip() or indentation > block_scalar_indent:
                continue
            block_scalar_indent = None
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        while context and context[-1][0] >= indentation:
            context.pop()
        ancestors = [key for _, key in context]
        mapping = YAML_MAPPING_KEY.match(line)
        key = _unquote_yaml_key(mapping.group("key")) if mapping else None
        value = mapping.group("value") if mapping else ""

        if key == "uses" and _valid_uses_context(ancestors):
            if YAML_BLOCK_SCALAR_VALUE.fullmatch(value.strip()):
                block_scalar_indent = indentation
            yield line_number, _yaml_scalar(value)
        elif YAML_BLOCK_SCALAR.match(line):
            block_scalar_indent = indentation
        elif _valid_uses_context(ancestors) or ancestors == ["jobs"]:
            for action in _flow_uses_values(line):
                yield line_number, action

        if mapping and (not value.strip() or re.fullmatch(r"&[A-Za-z0-9_.-]+", value.strip())):
            context.append((indentation, key or ""))


def _valid_local_action(root: Path, action: str) -> bool:
    if "\\" in action or not action.startswith("./") or action == "./":
        return False
    relative = Path(action[2:])
    if ".." in relative.parts:
        return False
    try:
        (root / relative).resolve().relative_to(root)
    except ValueError:
        return False
    return True


def _docker_instructions(path: Path) -> Iterator[tuple[int, str]]:
    start_line = 0
    parts: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not parts and (not stripped or stripped.startswith("#")):
            continue
        if not parts:
            start_line = line_number
        if stripped.endswith("\\"):
            parts.append(stripped[:-1].rstrip())
            continue
        parts.append(stripped)
        yield start_line, " ".join(parts)
        parts = []
    if parts:
        yield start_line, " ".join(parts)


def _from_image(instruction: str) -> str | None:
    tokens = instruction.split()
    if not tokens or tokens[0].upper() != "FROM":
        return None
    index = 1
    while index < len(tokens) and tokens[index].startswith("--"):
        index += 1
    return tokens[index] if index < len(tokens) else ""


def _node_lock_error(lockfile: Path) -> str | None:
    try:
        lock = json.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return f"package-lock.json could not be parsed: {error}"
    if not isinstance(lock, dict) or lock.get("lockfileVersion") not in {2, 3}:
        return "package-lock.json must use lockfileVersion 2 or 3"
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        return "package-lock.json must contain a root packages entry"
    for location, metadata in packages.items():
        if not isinstance(location, str) or not isinstance(metadata, dict):
            return "package-lock.json contains a malformed package entry"
        if not location or metadata.get("link") is True:
            continue
        version = metadata.get("version")
        integrity = metadata.get("integrity")
        if not isinstance(version, str) or not version:
            return f"package-lock entry {location!r} lacks an exact version"
        if not isinstance(integrity, str) or NPM_INTEGRITY.fullmatch(integrity) is None:
            return f"package-lock entry {location!r} lacks a valid integrity digest"
    return None


def inspect_root(root: Path) -> dict[str, Any]:
    root = root.resolve()
    issues: list[dict[str, str]] = []
    actions_checked = 0
    dependencies_checked = 0
    containers_checked = 0
    if root.is_dir():
        repository_files, repository_symlinks = _repository_entries(root)
    else:
        repository_files, repository_symlinks = [], []
        issues.append(_issue(
            "error",
            "ROOT_NOT_DIRECTORY",
            Path("."),
            "verification root must be an existing directory",
        ))

    for symlink in repository_symlinks:
        issues.append(_issue(
            "error",
            "REPOSITORY_SYMLINK_UNSUPPORTED",
            symlink.relative_to(root),
            "repository symlinks are not followed and must be replaced with committed files",
        ))

    workflow_root = root / ".github" / "workflows"
    action_sources = {
        path
        for path in repository_files
        if (
            path.parent == workflow_root and path.suffix in {".yml", ".yaml"}
        ) or path.name in {"action.yml", "action.yaml"}
    }
    for source in sorted(action_sources):
        relative = source.relative_to(root)
        for line_number, action in _uses_values(source):
            actions_checked += 1
            if action is None:
                issues.append(_issue(
                    "error",
                    "ACTION_REFERENCE_INVALID",
                    relative,
                    f"line {line_number} has an invalid uses value",
                ))
                continue
            if action.startswith("./"):
                if not _valid_local_action(root, action):
                    issues.append(_issue(
                        "error",
                        "LOCAL_ACTION_PATH_INVALID",
                        relative,
                        f"line {line_number}: local action path must remain inside the repository",
                    ))
                continue
            if not EXTERNAL_ACTION.fullmatch(action):
                issues.append(_issue(
                    "error",
                    "ACTION_NOT_COMMIT_PINNED",
                    relative,
                    f"line {line_number}: {action} must use an exact lowercase 40-character commit SHA",
                ))

    for requirements in sorted(path for path in repository_files if path.name == "requirements.txt"):
        relative = requirements.relative_to(root)
        for line_number, line in enumerate(requirements.read_text(encoding="utf-8").splitlines(), start=1):
            value = _strip_requirement_comment(line).strip()
            if not value or value.startswith("#"):
                continue
            dependencies_checked += 1
            if not _valid_requirement(value):
                issues.append(_issue(
                    "error",
                    "PYTHON_DEPENDENCY_NOT_PINNED",
                    relative,
                    f"line {line_number} is not an exact non-wildcard == pin or SHA-256-pinned HTTPS URL",
                ))

    for package_json in sorted(path for path in repository_files if path.name == "package.json"):
        relative = package_json.relative_to(root)
        try:
            payload = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            issues.append(_issue(
                "error",
                "NODE_MANIFEST_INVALID",
                relative,
                f"package.json could not be parsed: {error}",
            ))
            continue
        if not isinstance(payload, dict):
            issues.append(_issue(
                "error",
                "NODE_MANIFEST_INVALID",
                relative,
                "package.json must contain a JSON object",
            ))
            continue
        dependency_count = sum(
            len(payload.get(key, {}))
            for key in ("dependencies", "devDependencies", "optionalDependencies")
            if isinstance(payload.get(key, {}), dict)
        )
        dependencies_checked += dependency_count
        lockfile = package_json.parent / "package-lock.json"
        if dependency_count and (not lockfile.is_file() or lockfile.is_symlink()):
            issues.append(_issue(
                "error",
                "NODE_LOCKFILE_MISSING",
                relative,
                "package dependencies require a committed package-lock.json",
            ))
        elif dependency_count:
            lock_error = _node_lock_error(lockfile)
            if lock_error:
                issues.append(_issue(
                    "error",
                    "NODE_LOCKFILE_INVALID",
                    lockfile.relative_to(root),
                    lock_error,
                ))

    for dockerfile in sorted(path for path in repository_files if path.name.startswith("Dockerfile")):
        relative = dockerfile.relative_to(root)
        for line_number, instruction in _docker_instructions(dockerfile):
            image = _from_image(instruction)
            if image is None:
                continue
            containers_checked += 1
            if not image or not CONTAINER_DIGEST.fullmatch(image):
                issues.append(_issue(
                    "error",
                    "CONTAINER_BASE_NOT_DIGEST_PINNED",
                    relative,
                    f"line {line_number} must use image@sha256 followed by exactly 64 lowercase hex characters",
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
