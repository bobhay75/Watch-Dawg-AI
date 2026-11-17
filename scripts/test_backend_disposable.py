#!/usr/bin/env python3
"""Run deterministic backend tests against disposable, loopback-only MongoDB.

Only containers/networks created here are stopped/removed.
No production settings,
volumes, .env files, credentials or external endpoints are used.
"""

import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
MONGO_IMAGE = (
    "mongo@sha256:"
    "bdc216e9d5a6ec2cfdac789b5832fdab64cd32055f59885cae918a92de63c361"
)


def docker(*args):
    return subprocess.check_output(
        ["docker", *args], text=True, timeout=120
    ).strip()


def port(container, internal):
    return docker("port", container, internal).rsplit(":", 1)[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backend-image",
        help="Test an already built backend image instead of host Uvicorn",
    )
    parser.add_argument("--all-python", action="store_true")
    args = parser.parse_args()
    suffix = uuid.uuid4().hex[:12]
    network = "watchdawg-test-" + suffix
    mongo = network + "-mongo"
    api = network + "-api"
    created = []
    process = None
    result = 1
    network_created = False
    try:
        docker("network", "create", network)
        network_created = True
        docker(
            "run",
            "-d",
            "--rm",
            "--name",
            mongo,
            "--network",
            network,
            "--network-alias",
            "mongo",
            "-p",
            "127.0.0.1::27017",
            "--tmpfs",
            "/data/db:rw,size=1g",
            "--memory",
            "1g",
            "--cpus",
            "2",
            MONGO_IMAGE,
            "mongod",
            "--bind_ip_all",
            "--quiet",
        )
        created.append(mongo)
        db_port = port(mongo, "27017/tcp")
        db_name = "watchdawg_test_" + suffix
        env = {
            key: value
            for key, value in os.environ.items()
            if key
            not in {
                "MONGO_URL",
                "DB_NAME",
                "REACT_APP_BACKEND_URL",
                "LLM_PROVIDER",
                "LLM_BASE_URL",
                "LLM_API_KEY",
                "LLM_MODEL",
                "EMERGENT_LLM_KEY",
                "WATCHDAWG_TEST_MODE",
            }
        }
        env.update(
            MONGO_URL="mongodb://127.0.0.1:" + db_port,
            DB_NAME=db_name,
            LLM_PROVIDER="synthetic",
            WATCHDAWG_TEST_MODE="true",
            WATCHDAWG_REQUIRE_INTEGRATION="true",
            WATCHDAWG_DISPOSABLE_RUN=suffix,
        )
        # Wait for the synthetic database before launching either API runtime.
        from pymongo import MongoClient

        deadline = time.monotonic() + 40
        while True:
            try:
                with MongoClient(
                    env["MONGO_URL"], serverSelectionTimeoutMS=500
                ) as client:
                    client.admin.command("ping")
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "Disposable MongoDB did not become ready"
                    ) from None
                time.sleep(0.2)
        with tempfile.TemporaryFile() as log:
            if args.backend_image:
                docker(
                    "run",
                    "-d",
                    "--name",
                    api,
                    "--network",
                    network,
                    "-p",
                    "127.0.0.1::8001",
                    "-e",
                    "MONGO_URL=mongodb://mongo:27017",
                    "-e",
                    "DB_NAME=" + db_name,
                    "-e",
                    "LLM_PROVIDER=synthetic",
                    "-e",
                    "WATCHDAWG_TEST_MODE=true",
                    args.backend_image,
                )
                created.append(api)
                api_port = port(api, "8001/tcp")
            else:
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    api_port = str(sock.getsockname()[1])
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "backend.server:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        api_port,
                    ],
                    cwd=ROOT,
                    env=env,
                    stdout=log,
                    stderr=log,
                )
            env["REACT_APP_BACKEND_URL"] = "http://127.0.0.1:" + api_port
            deadline = time.monotonic() + 40
            # Disable ambient proxies for loopback readiness requests.
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({})
            )
            while True:
                try:
                    with opener.open(
                        env["REACT_APP_BACKEND_URL"] + "/api/health", timeout=1
                    ) as response:
                        if response.status == 200:
                            break
                except OSError:
                    pass
                if (
                    process and process.poll() is not None
                ) or time.monotonic() >= deadline:
                    if args.backend_image:
                        subprocess.run(
                            ["docker", "logs", "--tail", "20", api],
                            check=False,
                        )
                    raise RuntimeError(
                        "Disposable API did not become ready; "
                        "no production endpoint used"
                    )
                time.sleep(0.2)
            paths = ["backend/tests"]
            if args.all_python:
                paths += [
                    "tests",
                    "sentinel/tests",
                    "key9/agent-service/tests",
                ]
                env["PYTHONPATH"] = os.pathsep.join(
                    [
                        str(ROOT),
                        str(ROOT / "key9/agent-service"),
                    ]
                )
            result = subprocess.call(
                [sys.executable, "-m", "pytest", *paths, "-q"],
                cwd=ROOT,
                env=env,
            )
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for name in reversed(created):
            subprocess.run(
                ["docker", "rm", "--force", name],
                check=False,
                stdout=subprocess.DEVNULL,
                timeout=30,
            )
        if network_created:
            subprocess.run(
                ["docker", "network", "rm", network],
                check=False,
                stdout=subprocess.DEVNULL,
                timeout=30,
            )
    return result


if __name__ == "__main__":
    raise SystemExit(main())
