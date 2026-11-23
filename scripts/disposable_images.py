"""Build the pinned disposable database separately from runtime probes."""

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MONGO_IMAGE = "watchdawg-mongo:operations"
# Cold pulls plus signed distribution updates can exceed the 120-second
# runtime-command budget. Keep setup bounded without relaxing readiness,
# recovery assertions, image scans, or the workflow's overall deadline.
IMAGE_BUILD_TIMEOUT_SECONDS = 600


def build_mongo_image():
    """Build only the repository's pinned, non-root synthetic MongoDB image.

    Stream build output so registry/package failures remain diagnosable.
    Timeouts and nonzero exits propagate; neither is retried or suppressed.
    No container, database volume, or production setting is used here.
    """
    print(
        "Building disposable MongoDB image "
        f"({IMAGE_BUILD_TIMEOUT_SECONDS}-second setup limit)",
        flush=True,
    )
    subprocess.run(
        [
            "docker", "build", "--progress=plain",
            "-f", str(ROOT / "deployment/secure/Mongo.Dockerfile"),
            "-t", MONGO_IMAGE, str(ROOT),
        ],
        check=True,
        timeout=IMAGE_BUILD_TIMEOUT_SECONDS,
    )
