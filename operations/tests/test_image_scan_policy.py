"""Synthetic scanner-policy tests; no registry, Docker or real data access."""

from copy import deepcopy
import pytest
from scripts.check_image_vulnerabilities import evaluate

IMAGE = "synthetic:test"
IMAGE_ID = "sha256:" + "a" * 64


def report(findings=()):
    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "ArtifactName": IMAGE,
        "Metadata": {
            "ImageID": IMAGE_ID,
            "OS": {
                "Family": "debian",
                "Name": "13",
                "EOSL": False,
            },
        },
        "Results": [
            {"Class": "os-pkgs", "Vulnerabilities": list(findings)},
            {"Class": "lang-pkgs", "Type": "python-pkg"},
        ],
    }


def finding(severity, fixed=""):
    return {
        "Severity": severity,
        "VulnerabilityID": "SYNTHETIC-TEST",
        "PkgName": "synthetic",
        "InstalledVersion": "1",
        "FixedVersion": fixed,
    }


@pytest.mark.parametrize(
    "severity,fixed,expected",
    [
        ("CRITICAL", "", "FAIL"),
        ("CRITICAL", "2", "FAIL"),
        ("HIGH", "2", "FAIL"),
        ("HIGH", "", "PASS_WITH_FINDINGS"),
        ("MEDIUM", "2", "PASS_WITH_FINDINGS"),
    ],
)
def test_development_gate_keeps_unfixed_findings_visible(
    severity, fixed, expected
):
    result = evaluate(report([finding(severity, fixed)]), IMAGE, IMAGE_ID)
    assert result["status"] == expected
    assert result["severity_rows"] == {severity: 1}
    assert result["production_approved"] is False
    assert result["unfixed_high_rows"] == (severity == "HIGH" and not fixed)


def test_empty_complete_report_and_eol_gate():
    value = report()
    assert evaluate(value, IMAGE, IMAGE_ID)["status"] == "PASS"
    value["Metadata"]["OS"]["EOSL"] = True
    assert evaluate(value, IMAGE, IMAGE_ID)["status"] == "FAIL"


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(ArtifactName="other:test"),
        lambda r: r["Metadata"].update(ImageID="sha256:" + "b" * 64),
        lambda r: r.update(Results=[]),
        lambda r: r["Metadata"].pop("OS"),
        lambda r: r["Results"][0].update(Vulnerabilities={}),
        lambda r: r["Results"][0].update(Vulnerabilities=[{}]),
        lambda r: r["Results"][0].update(
            Vulnerabilities=[finding("unrecognized", "2")]
        ),
    ],
)
def test_missing_malformed_or_wrong_image_reports_fail_closed(change):
    value = deepcopy(report())
    change(value)
    with pytest.raises(ValueError):
        evaluate(value, IMAGE, IMAGE_ID)


def test_expected_python_analysis_cannot_silently_disappear():
    value = report()
    value["Results"].pop()
    with pytest.raises(ValueError):
        evaluate(value, IMAGE, IMAGE_ID, require_python=True)
