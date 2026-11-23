#!/usr/bin/env python3
"""Run deterministic backend tests against disposable, loopback-only MongoDB.

Only containers/networks created here are stopped/removed.
No production settings,
volumes, .env files, credentials or external endpoints are used.
"""

import argparse
import hashlib
import json
import secrets
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
MONGO_IMAGE = "watchdawg-mongo:operations"


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
    # Build only the pinned, non-root disposable variant; never pull a URI.
    docker(
        "build",
        "-f",
        str(ROOT / "deployment/secure/Mongo.Dockerfile"),
        "-t",
        MONGO_IMAGE,
        str(ROOT),
    )
    suffix = uuid.uuid4().hex[:12]
    network = "watchdawg-test-" + suffix
    mongo = network + "-mongo"
    api = network + "-api"
    created = []
    process = None
    result = 1
    network_created = False
    secret_dir = tempfile.TemporaryDirectory(prefix="watchdawg-test-security-")
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
            "/data/db:rw,size=1g,uid=999,gid=999,mode=0700",
            "--tmpfs",
            "/data/configdb:rw,size=16m,uid=999,gid=999,mode=0700",
            "--tmpfs",
            "/tmp:rw,size=16m,uid=999,gid=999,mode=0700",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
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
        token = secrets.token_urlsafe(32)
        subnet = docker(
            "network",
            "inspect",
            network,
            "--format",
            "{{(index .IPAM.Config 0).Subnet}}",
        )
        policy = {
            "rate_hmac_key": secrets.token_hex(32),
            "allowed_hosts": ["127.0.0.1", "localhost", "testserver"],
            "allowed_networks": ["127.0.0.1/32", subnet],
            "allowed_origins": [],
            "transport": "test",
            "principals": [
                {
                    "id": "synthetic-runner",
                    "scopes": ["health:read", "audit:run"],
                    "token_sha256": [
                        hashlib.sha256(token.encode()).hexdigest()
                    ],
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            ],
            "rates": {
                "global_limit": 1000,
                "network_limit": 500,
                "principal_limit": 200,
                "global_streams": 8,
                "principal_streams": 8,
            },
        }
        policy_bytes = json.dumps(policy).encode()
        policy_file = str(Path(secret_dir.name) / "security.json")
        fd = os.open(policy_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(policy_bytes)
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
                "MONGO_URL_FILE",
                "LLM_API_KEY_FILE",
                "BACKEND_SECURITY_FILE",
                "BACKEND_AUDIT_DIR",
                "BACKEND_AUDIT_SEGMENT_BYTES",
                "BACKEND_AUDIT_MAX_SEGMENTS",
                "BACKEND_AUDIT_RETENTION_DAYS",
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "AZURE_OPENAI_API_KEY",
            }
        }
        env.update(
            MONGO_URL="mongodb://127.0.0.1:" + db_port,
            DB_NAME=db_name,
            LLM_PROVIDER="synthetic",
            WATCHDAWG_TEST_MODE="true",
            WATCHDAWG_REQUIRE_INTEGRATION="true",
            WATCHDAWG_DISPOSABLE_RUN=suffix,
            WATCHDAWG_TEST_TOKEN=token,
            BACKEND_SECURITY_FILE=policy_file,
            HTTP_PROXY="",
            HTTPS_PROXY="",
            ALL_PROXY="",
            NO_PROXY="127.0.0.1,localhost",
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
                    "-e",
                    "BACKEND_SECURITY_FILE=/run/secrets/security.json",
                    "--tmpfs",
                    "/run/secrets:rw,size=64k,mode=0700,uid=10001,gid=10001",
                    "--entrypoint",
                    "sh",
                    args.backend_image,
                    "-c",
                    "until test -f /run/secrets/security.json; "
                    "do sleep 0.1; done; "
                    "exec python -m uvicorn backend.server:app --host 0.0.0.0 "
                    "--port 8001 --no-proxy-headers --no-access-log",
                )
                created.append(api)
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        "-i",
                        api,
                        "python",
                        "-c",
                        'import os,sys; p="/run/secrets/security.tmp"; '
                        "flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL; "
                        "fd=os.open(p,flags,0o600); "
                        "os.write(fd,sys.stdin.buffer.read()); os.close(fd); "
                        'os.replace(p,"/run/secrets/security.json")',
                    ],
                    input=policy_bytes,
                    check=True,
                    timeout=15,
                )
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
                        "--no-proxy-headers",
                        "--no-access-log",
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
                        urllib.request.Request(
                            env["REACT_APP_BACKEND_URL"] + "/api/health",
                            headers={"Authorization": "Bearer " + token},
                        ),
                        timeout=1,
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
        secret_dir.cleanup()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
