"""Validate complete image-bound Trivy reports for development review."""

import argparse
from collections import Counter
import json
from pathlib import Path
import re

SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def evaluate(report, expected_image, expected_id, require_python=False):
    if not isinstance(report, dict):
        raise ValueError("Invalid scanner report")
    metadata = report.get("Metadata", {})
    results = report.get("Results")
    if not isinstance(metadata, dict):
        raise ValueError("Invalid scanner metadata")
    os_info = metadata.get("OS", {})
    if not isinstance(os_info, dict):
        raise ValueError("Invalid OS information")
    if (
        report.get("SchemaVersion") != 2
        or report.get("ArtifactType") != "container_image"
        or report.get("ArtifactName") != expected_image
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_id)
        or metadata.get("ImageID") != expected_id
        or os_info.get("Family") not in {"alpine", "debian", "ubuntu"}
        or not os_info.get("Name")
        or not isinstance(results, list)
        or not all(isinstance(row, dict) for row in results)
        or not any(row.get("Class") == "os-pkgs" for row in results)
        or (
            require_python
            and not any(
                row.get("Class") == "lang-pkgs"
                and row.get("Type") == "python-pkg"
                for row in results
            )
        )
    ):
        raise ValueError("Missing, incomplete or wrong-image scan")
    rows = []
    for result in results:
        if result.get("Class") not in {"os-pkgs", "lang-pkgs"}:
            raise ValueError("Unexpected scanner result")
        findings = result.get("Vulnerabilities", [])
        if findings is None:
            findings = []
        if not isinstance(findings, list):
            raise ValueError("Invalid vulnerability list")
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("Invalid vulnerability record")
            if (
                finding.get("Severity") not in SEVERITIES
                or any(
                    not isinstance(finding.get(key), str) or not finding[key]
                    for key in (
                        "VulnerabilityID",
                        "PkgName",
                        "InstalledVersion",
                    )
                )
                or not isinstance(finding.get("FixedVersion", ""), str)
            ):
                raise ValueError("Incomplete vulnerability record")
            rows.append(finding)
    blocked = [
        {
            "id": row["VulnerabilityID"],
            "package": row["PkgName"],
            "installed": row["InstalledVersion"],
            "fixed": row.get("FixedVersion", ""),
            "severity": row["Severity"],
        }
        for row in rows
        if row["Severity"] == "CRITICAL"
        or (row["Severity"] == "HIGH" and row.get("FixedVersion"))
    ]
    end_of_life = metadata["OS"].get("EOSL", False)
    if type(end_of_life) is not bool:
        raise ValueError("Invalid OS lifecycle information")
    return {
        "image": expected_image,
        "image_id": expected_id,
        "status": (
            "FAIL"
            if blocked or end_of_life
            else "PASS_WITH_FINDINGS" if rows else "PASS"
        ),
        "severity_rows": dict(Counter(row["Severity"] for row in rows)),
        "unfixed_high_rows": sum(
            row["Severity"] == "HIGH" and not row.get("FixedVersion")
            for row in rows
        ),
        "end_of_life": end_of_life,
        "development_blockers": blocked,
        "production_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    parser.add_argument("--expected-image", required=True)
    parser.add_argument("--expected-id", required=True)
    parser.add_argument("--require-python", action="store_true")
    args = parser.parse_args()
    try:
        path = Path(args.report)
        if path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("Oversized scanner report")
        result = evaluate(
            json.loads(path.read_bytes()),
            args.expected_image,
            args.expected_id,
            require_python=args.require_python,
        )
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        parser.exit(2, "Image scan missing, incomplete or unsafe\n")
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
