#!/usr/bin/env python3
"""Synthetic-only TLS, least-privilege, failover, encrypted restore drill.

No production URI, volume, credential or .env is read.
All resources
are uniquely named and only resources created here are cleaned up.
"""

import argparse
import base64
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from operations.tls import authority, issue  # noqa: E402
from operations.files import write_new, canonical  # noqa: E402
from operations.backups import backup, restore  # noqa: E402
from operations.tokens import (  # noqa: E402
    prepare_rotation,
    install,
    stage_revocation,
)  # noqa: E402
from operations.mongo_roles import roles  # noqa: E402
from backend.audit import validate  # noqa: E402

MONGO = (
    "mongo@sha256:bdc216e9d5a6ec2cfdac789b5832fdab64cd32055f59885cae918"
    "a92de63c361"
)


def command(*args, data=None):
    result = subprocess.run(
        list(args),
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if result.returncode:
        # Only synthetic containers/commands are executed; never dump input.
        raise RuntimeError(
            "Disposable command failed: "
            + result.stderr.decode(errors="replace")[-1800:]
        )
    return result.stdout.decode().strip()


def docker(*args, data=None):
    return command("docker", *args, data=data)


def wait(function, seconds=60):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            value = function()
            if value:
                return value
        except Exception as exc:
            last = exc
        time.sleep(0.5)
    raise RuntimeError("Synthetic readiness timeout") from last


def inject(container, user, files, ready=False):
    for name, data in files.items():
        docker(
            "exec",
            "-i",
            "--user",
            user,
            container,
            "sh",
            "-c",
            "umask 077; cat > /run/secrets/" + name,
            data=data,
        )
    if ready:
        docker(
            "exec",
            "--user",
            user,
            container,
            "sh",
            "-c",
            "touch /run/secrets/ready",
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-image", required=True)
    parser.add_argument("--proxy-image", required=True)
    args = parser.parse_args()
    suffix = uuid.uuid4().hex[:12]
    prefix = "wdops-" + suffix
    data_net, api_net = prefix + "-data", prefix + "-api"
    ingress_net = prefix + "-ingress"
    nodes = [prefix + "-m" + str(i) for i in range(1, 4)]
    aliases = ["ops-m" + str(i) for i in range(1, 4)]
    backend, proxy = prefix + "-backend", prefix + "-proxy"
    containers, volumes, networks = [], [], []
    ca_key, ca = authority()
    from cryptography.hazmat.primitives import serialization

    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    _, client_pem = issue(
        ca_key, ca, ["synthetic-client", "localhost", "127.0.0.1"]
    )
    certificates = [
        issue(ca_key, ca, [alias, "localhost", "127.0.0.1"])[1]
        for alias in aliases
    ]
    cert, server_pem = issue(
        ca_key, ca, ["watchdawg.internal", "localhost", "127.0.0.1"]
    )
    backend_cert, backend_pem = issue(
        ca_key, ca, ["watchdawg-backend.internal", "watchdawg_backend"]
    )
    _, proxy_client_pem = issue(ca_key, ca, ["synthetic-proxy-client"])
    # Nginx accepts the combined cert+key file as its key file.
    credentials = {
        name: secrets.token_hex(32)
        for name in ["admin", "app", "backup", "restore"]
    }
    repl_key = base64.b64encode(secrets.token_bytes(96))
    db_name = "watchdawg_test_ops_" + suffix
    restore_db = "watchdawg_restore_" + suffix
    paths = (
        "tls=true&tlsCAFile=/run/secrets/ca.crt&tlsCertificateKeyFile=/"
        "run/secrets/client.pem"
    )
    local_uri = "mongodb://localhost:27017/?directConnection=true&" + paths
    cluster_uri = (
        "mongodb://"
        + ",".join(a + ":27017" for a in aliases)
        + "/?replicaSet=wdops&"
        + paths
    )
    common = (
        "const fs=require('fs'); const c=JSON.parse(fs.readFileSync('/r"
        "un/secrets/credentials.json')); "
    )

    def js(index, script, cluster=False, admin=False):
        uri = cluster_uri if cluster else local_uri
        pre = common + "const conn=new Mongo(" + json.dumps(uri) + "); "
        if admin:
            pre += (
                "const admin=conn.getDB('admin'); if(!admin.auth('synth"
                "etic_admin',c.admin)) throw Error('auth'); "
            )
        return docker(
            "exec",
            "-i",
            nodes[index],
            "mongosh",
            "--quiet",
            "--nodb",
            "--file",
            "/dev/stdin",
            data=(pre + script).encode(),
        )

    def node_files(index):
        return {
            "ca.crt": ca_pem,
            "node.pem": certificates[index],
            "client.pem": client_pem,
            "repl.key": repl_key,
            "credentials.json": canonical(credentials),
        }

    with tempfile.TemporaryDirectory(
        prefix="watchdawg-ops-synthetic-"
    ) as temporary:
        root = Path(temporary)
        try:
            docker("network", "create", "--internal", data_net)
            networks.append(data_net)
            docker("network", "create", "--internal", api_net)
            networks.append(api_net)
            docker("network", "create", ingress_net)
            networks.append(ingress_net)
            for i, node in enumerate(nodes):
                volume = node + "-data"
                docker("volume", "create", volume)
                volumes.append(volume)
                docker(
                    "run",
                    "-d",
                    "--name",
                    node,
                    "--network",
                    data_net,
                    "--network-alias",
                    aliases[i],
                    "--user",
                    "999:999",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--memory",
                    "768m",
                    "--cpus",
                    "1",
                    "--mount",
                    "type=volume,source=" + volume + ",target=/data/db",
                    "--tmpfs",
                    "/tmp:rw,size=32m,uid=999",
                    "--tmpfs",
                    "/run/secrets:rw,size=1m,uid=999,gid=999,mode=0700",
                    "--entrypoint",
                    "sh",
                    MONGO,
                    "-c",
                    "until test -f /run/secrets/ready; do sleep 0.1; done; "
                    "exec docker-entrypoint.sh mongod --replSet wdops --auth "
                    "--keyFile /run/secrets/repl.key --bind_ip_all --quiet "
                    "--wiredTigerCacheSizeGB 0.25 --tlsMode requireTLS "
                    "--tlsCertificateKeyFile /run/secrets/node.pem --tl"
                    "sCAFile /run/secrets/ca.crt",
                )
                containers.append(node)
                inject(node, "999", node_files(i), True)
            wait(
                lambda: js(
                    0, "print(conn.getDB('admin').runCommand({ping:1}).ok)"
                )
                == "1"
            )
            members = [
                {"_id": i, "host": alias + ":27017"}
                for i, alias in enumerate(aliases)
            ]
            js(
                0,
                "const r=conn.getDB('admin').runCommand({replSetInitiate:"
                + json.dumps({"_id": "wdops", "members": members})
                + "}); if(!r.ok) throw Error('init');",
            )
            primary = int(
                wait(
                    lambda: next(
                        (
                            str(i)
                            for i in range(3)
                            if js(
                                i,
                                "print(conn.getDB('admin').runCommand({"
                                "hello:1}).isWritablePrimary)",
                            )
                            == "true"
                        ),
                        None,
                    )
                )
            )
            js(
                primary,
                "conn.getDB('admin').createUser({user:'synthetic_admin'"
                ",pwd:c.admin,roles:['root']});",
            )
            definition = roles(db_name)
            js(
                primary,
                "const d=conn.getDB(" + json.dumps(db_name) + "); "
                "for(const n of ['ai_audit_messages','security_windows'"
                ",'security_leases']) d.createCollection(n); "
                "for(const r of "
                + json.dumps(definition)
                + ") d.createRole(r); "
                "d.createUser({user:'watchdawg_app',pwd:c.app,roles:['w"
                "atchdawg_app']}); "
                "d.createUser({user:'watchdawg_backup',pwd:c.backup,rol"
                "es:['watchdawg_backup']});",
                admin=True,
            )
            # Assert allowed writes and denied reads/escalation against real
            # auth.
            js(
                primary,
                "const d=conn.getDB("
                + json.dumps(db_name)
                + "); d.auth('watchdawg_app',c.app); "
                "d.ai_audit_messages.insertOne({session_id:'synthetic-b"
                "efore-failover',role:'synthetic-marker',content:'synth"
                "etic only'}); "
                "for(const cmd of [{find:'ai_audit_messages'},{update:'"
                "ai_audit_messages',updates:[{q:{},u:{$set:{bad:true}}}"
                "]},{find:'archaeological_coordinates'},{drop:'ai_audit"
                "_messages'},{createUser:'forbidden',pwd:'never-used',r"
                "oles:[]}]) {try { const r=d.runCommand(cmd); if(r.ok) "
                "throw Error('privilege escalation'); } catch(e) { if(e"
                ".code!==13) throw e; }}",
            )
            # Start private TLS ingress, then backend with no host port.
            docker(
                "run",
                "-d",
                "--name",
                proxy,
                "--network",
                ingress_net,
                "--user",
                "101:101",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "-p",
                "127.0.0.1::8443",
                "--tmpfs",
                "/tmp:rw,size=32m,uid=101",
                "--tmpfs",
                "/run/secrets:rw,size=1m,uid=101,gid=101,mode=0700",
                "--entrypoint",
                "sh",
                args.proxy_image,
                "-c",
                "until test -f /run/secrets/ready; do sleep 0.1; done; "
                'exec nginx -g "daemon off;"',
            )
            containers.append(proxy)
            docker("network", "connect", api_net, proxy)
            proxy_ip = docker(
                "inspect",
                proxy,
                "--format",
                '{{(index .NetworkSettings.Networks "'
                + api_net
                + '").IPAddress}}',
            )
            token, monitor = secrets.token_urlsafe(32), secrets.token_urlsafe(
                32
            )
            import hashlib

            policy = {
                "rate_hmac_key": secrets.token_hex(32),
                "allowed_hosts": ["watchdawg.internal"],
                "allowed_networks": [proxy_ip + "/32"],
                "trusted_proxy_networks": [proxy_ip + "/32"],
                "allowed_origins": [],
                "transport": "proxy",
                "principals": [
                    {
                        "id": "synthetic-ops",
                        "scopes": ["health:read", "audit:run"],
                        "token_sha256": [
                            hashlib.sha256(token.encode()).hexdigest()
                        ],
                        "expires_at": "2099-01-01T00:00:00Z",
                    },
                    {
                        "id": "synthetic-monitor",
                        "scopes": ["health:read"],
                        "token_sha256": [
                            hashlib.sha256(monitor.encode()).hexdigest()
                        ],
                        "expires_at": "2099-01-01T00:00:00Z",
                    },
                ],
                "rates": {
                    "global_limit": 1000,
                    "network_limit": 1000,
                    "principal_limit": 500,
                },
            }
            policy_file = root / "security.json"
            write_new(policy_file, canonical(policy))
            mongo_uri = (
                "mongodb://watchdawg_app:"
                + credentials["app"]
                + "@"
                + ",".join(a + ":27017" for a in aliases)
                + "/"
                + db_name
                + "?authSource="
                + db_name
                + "&replicaSet=wdops&"
                + paths
            )
            audit_volume = prefix + "-audit"
            docker("volume", "create", audit_volume)
            volumes.append(audit_volume)
            docker(
                "create",
                "--name",
                backend,
                "--network",
                data_net,
                "--user",
                "10001:10001",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--mount",
                "type=volume,source="
                + audit_volume
                + ",target=/var/lib/watchdawg/audit",
                "--tmpfs",
                "/tmp:rw,size=16m,uid=10001",
                "--tmpfs",
                "/run/secrets:rw,size=1m,uid=10001,gid=10001,mode=0700",
                "-e",
                "MONGO_URL_FILE=/run/secrets/mongo-uri",
                "-e",
                "DB_NAME=" + db_name,
                "-e",
                "BACKEND_SECURITY_FILE=/run/secrets/security.json",
                "-e",
                "BACKEND_AUDIT_DIR=/var/lib/watchdawg/audit",
                "-e",
                "LLM_PROVIDER=synthetic",
                "-e",
                "WATCHDAWG_TEST_MODE=true",
                "--entrypoint",
                "sh",
                args.backend_image,
                "-c",
                "until test -f /run/secrets/ready; do sleep 0.1; done; "
                "exec python -m uvicorn backend.server:app --host 0.0.0"
                ".0 --port 8001 --no-proxy-headers --no-access-log --ss"
                "l-certfile /run/secrets/backend.crt --ssl-keyfile /run"
                "/secrets/backend.pem --ssl-ca-certs /run/secrets/backe"
                "nd-ca.crt --ssl-cert-reqs 2",
            )
            containers.append(backend)
            docker(
                "network",
                "connect",
                "--alias",
                "watchdawg_backend",
                api_net,
                backend,
            )
            docker("start", backend)
            inject(
                backend,
                "10001",
                {
                    "ca.crt": ca_pem,
                    "client.pem": client_pem,
                    "mongo-uri": mongo_uri.encode(),
                    "backend.crt": backend_cert,
                    "backend.pem": backend_pem,
                    "backend-ca.crt": ca_pem,
                    "security.json": canonical(policy),
                },
                True,
            )
            inject(
                proxy,
                "101",
                {
                    "server.crt": cert,
                    "server.key": server_pem,
                    "proxy-client.pem": proxy_client_pem,
                    "backend-ca.crt": ca_pem,
                },
                True,
            )
            for name, expected in [
                (backend, {api_net, data_net}),
                (proxy, {api_net, ingress_net}),
                *[(node, {data_net}) for node in nodes],
            ]:
                state = json.loads(docker("inspect", name))[0]
                assert set(state["NetworkSettings"]["Networks"]) == expected
                if name != proxy:
                    assert not any(state["NetworkSettings"]["Ports"].values())
            port = docker("port", proxy, "8443/tcp").rsplit(":", 1)[1]
            url = "https://127.0.0.1:" + port
            ctx = ssl.create_default_context(cadata=ca_pem.decode())
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ctx),
            )

            def request(
                path="/api/health",
                credential=None,
                host="watchdawg.internal",
                body=None,
                extra=None,
            ):
                headers = {
                    "Host": host,
                    "Authorization": "Bearer "
                    + (token if credential is None else credential),
                }
                headers.update(extra or {})
                if body is not None:
                    headers["Content-Type"] = "application/json"
                req = urllib.request.Request(
                    url + path, data=body, headers=headers
                )
                try:
                    with opener.open(req, timeout=15) as response:
                        return response.status, response.read()
                except urllib.error.HTTPError as exc:
                    return exc.code, exc.read()

            wait(lambda: request()[0] == 200)
            import socket

            with socket.create_connection(
                ("127.0.0.1", int(port)), timeout=5
            ) as tcp:
                with ctx.wrap_socket(
                    tcp, server_hostname="watchdawg.internal"
                ) as tls:
                    assert tls.version() in {"TLSv1.2", "TLSv1.3"}
            wait(lambda: request()[0] == 200)
            assert request(credential="invalid")[0] == 401
            assert request(host="evil.invalid")[0] == 421
            assert (
                request(
                    extra={
                        "X-Forwarded-Proto": "http",
                        "X-Forwarded-For": "203.0.113.9",
                    }
                )[0]
                == 200
            )
            assert (
                request(
                    "/api/ai/audit",
                    monitor,
                    body=canonical(
                        {
                            "payload": {},
                            "deterministic_result": {},
                            "report": "synthetic",
                        }
                    ),
                )[0]
                == 403
            )
            assert (
                request(
                    "/api/ai/audit",
                    body=canonical(
                        {
                            "payload": {"synthetic": True},
                            "deterministic_result": {"status": "REVIEW"},
                            "report": "synthetic-private-data",
                        }
                    ),
                )[0]
                == 200
            )
            try:
                urllib.request.build_opener(
                    urllib.request.ProxyHandler({})
                ).open(
                    urllib.request.Request(
                        url, headers={"Host": "watchdawg.internal"}
                    ),
                    timeout=5,
                )
                raise AssertionError("Untrusted CA accepted")
            except (urllib.error.URLError, ssl.SSLError):
                pass
            # A valid credential and spoofed proto cannot bypass the direct-
            # peer restriction.
            probe = """
import json,sys,urllib.request,urllib.error,ssl,tempfile,http.client
from pathlib import Path
c=json.load(sys.stdin)
ctx=ssl.create_default_context(cadata=c['ca'])
probe_url='https://watchdawg_backend:8001/api/health'
no_certificate=urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ctx))
try:
    no_certificate.open(probe_url,timeout=5)
    raise AssertionError('missing client certificate accepted')
except urllib.error.HTTPError:
    raise AssertionError('HTTP reached without a client certificate')
except (ssl.SSLError,http.client.RemoteDisconnected,ConnectionResetError):
    pass
except urllib.error.URLError as exc:
    assert isinstance(exc.reason,ssl.SSLError)
with tempfile.TemporaryDirectory() as temp:
    key=Path(temp)/'client.pem'
    key.write_text(c['client']);key.chmod(0o600)
    ctx.load_cert_chain(key)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
    r=urllib.request.Request(
        'https://watchdawg_backend:8001/api/health', headers={
            'Host':'watchdawg.internal',
            'Authorization':'Bearer '+c['token'],
            'X-Forwarded-Proto':'https'})
    try:
        opener.open(r);raise RuntimeError('network bypass')
    except urllib.error.HTTPError as exc:
        assert exc.code==403
"""
            docker(
                "run",
                "--rm",
                "-i",
                "--network",
                api_net,
                "--entrypoint",
                "python",
                args.backend_image,
                "-c",
                probe,
                data=canonical(
                    {
                        "token": token,
                        "ca": ca_pem.decode(),
                        "client": proxy_client_pem.decode(),
                    }
                ),
            )
            # Rotate, then revoke without restarting a worker or resetting
            # limits.
            receipt = prepare_rotation(
                policy_file, "synthetic-ops", root / "rotation"
            )
            new_token = (root / "rotation/token").read_text().strip()

            def push_policy(path):
                docker(
                    "exec",
                    "-i",
                    backend,
                    "python",
                    "-c",
                    'import os,sys; p="/run/secrets/policy.tmp"; fd=os.'
                    "open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os"
                    ".write(fd,sys.stdin.buffer.read()); os.close(fd); "
                    'os.replace(p,"/run/secrets/security.json")',
                    data=Path(path).read_bytes(),
                )

            install(
                root / "rotation/overlap.json",
                policy_file,
                receipt["previous_sha256"],
            )
            push_policy(policy_file)
            assert (
                request(credential=token)[0]
                == request(credential=new_token)[0]
                == 200
            )
            install(
                root / "rotation/final.json",
                policy_file,
                receipt["overlap_sha256"],
            )
            push_policy(policy_file)
            assert (
                request(credential=token)[0] == 401
                and request(credential=new_token)[0] == 200
            )
            stage_revocation(policy_file, "synthetic-ops", root / "revoked")
            install(root / "revoked", policy_file, receipt["final_sha256"])
            push_policy(policy_file)
            assert request(credential=new_token)[0] == 401
            policy_file.write_bytes(b"{corrupt")
            push_policy(policy_file)
            assert request(credential=monitor)[0] == 503
            # Restore the revoked policy: never resurrect revoked credentials.
            policy_file.write_bytes((root / "revoked").read_bytes())
            push_policy(policy_file)
            token = monitor
            # Fail over the primary, retain majority-committed records and
            # resume API budgets.
            old_primary = primary
            docker("stop", "--time", "3", nodes[old_primary])
            survivor = next(i for i in range(3) if i != old_primary)

            def elected_primary():
                value = js(
                    survivor,
                    "print(conn.getDB('admin').runCommand({hello:1}).pr"
                    "imary || '')",
                )
                return (
                    value
                    if value
                    in {
                        a + ":27017"
                        for a in aliases
                        if a != aliases[old_primary]
                    }
                    else None
                )

            new_primary = wait(elected_primary)
            assert new_primary in {
                a + ":27017" for a in aliases if a != aliases[old_primary]
            }
            wait(lambda: request()[0] == 200)
            js(
                survivor,
                "const d=conn.getDB("
                + json.dumps(db_name)
                + "); d.auth('watchdawg_app',c.app); d.ai_audit_messages."
                "insertOne({session_id:'synthetic-after-failover',role:"
                "'synthetic-marker',content:'synthetic only'},{writeCon"
                "cern:{w:'majority'}});",
                cluster=True,
            )
            # Export with a read-only backup principal, encrypt, verify and
            # restore into a new DB.
            snapshot = js(
                survivor,
                "const d=conn.getDB("
                + json.dumps(db_name)
                + "); d.auth('watchdawg_backup',c.backup); print(EJSON.st"
                "ringify(d.ai_audit_messages.find({}).sort({_id:1}).toA"
                "rray()));",
                cluster=True,
            )
            records = json.loads(snapshot)
            assert {r["session_id"] for r in records} >= {
                "synthetic-before-failover",
                "synthetic-after-failover",
            }
            source = root / "snapshot"
            source.mkdir(mode=0o700)
            write_new(source / "mongo.json", snapshot.encode())
            key = root / "backup.key"
            write_new(key, secrets.token_bytes(32))
            encrypted = root / "backup.wdb"
            backup(source, key, encrypted)
            restore(
                encrypted,
                key,
                root / "verified",
                str(encrypted) + ".receipt.json",
            )
            assert (
                root / "verified/mongo.json"
            ).read_bytes() == snapshot.encode()
            inject(nodes[survivor], "999", {"restore.json": snapshot.encode()})
            js(
                survivor,
                "const d=conn.getDB("
                + json.dumps(restore_db)
                + "); d.createCollection('ai_audit_messages'); d.createRo"
                "le({role:'restore_insert',privileges:[{resource:{db:d."
                "getName(),collection:'ai_audit_messages'},actions:['in"
                "sert']}],roles:[]}); d.createUser({user:'watchdawg_res"
                "tore',pwd:c.restore,roles:['restore_insert']});",
                cluster=True,
                admin=True,
            )
            js(
                survivor,
                "const d=conn.getDB("
                + json.dumps(restore_db)
                + "); d.auth('watchdawg_restore',c.restore); d.ai_audit_m"
                "essages.insertMany(EJSON.parse(fs.readFileSync('/run/s"
                "ecrets/restore.json','utf8')));",
                cluster=True,
            )
            assert js(
                survivor,
                "print(conn.getDB("
                + json.dumps(restore_db)
                + ").ai_audit_messages.countDocuments({}))",
                cluster=True,
                admin=True,
            ) == str(len(records))
            docker("start", nodes[old_primary])
            inject(nodes[old_primary], "999", node_files(old_primary), True)
            wait(
                lambda: js(
                    old_primary,
                    "print(conn.getDB('admin').runCommand({hello:1}).se"
                    "condary)",
                )
                == "true"
            )
            # Lose majority: fail closed, then restore quorum and recover.
            stopped = [i for i in range(3) if i != old_primary]
            for i in stopped:
                docker("stop", "--time", "3", nodes[i])
            assert request()[0] == 503
            for i in stopped:
                docker("start", nodes[i])
                inject(nodes[i], "999", node_files(i), True)
            wait(lambda: request()[0] == 200)
            raw_logs = docker(
                "exec",
                backend,
                "python",
                "-c",
                'from pathlib import Path; print("".join(p.read_text() '
                'for p in sorted(Path("/var/lib/watchdawg/audit").glob('
                '"audit-*.jsonl"))),end="")',
            )
            events = [json.loads(line) for line in raw_logs.splitlines()]
            for event in events:
                validate(event)
            assert any(e["event"] == "backend_admission" for e in events)
            for sensitive in [
                token,
                monitor,
                credentials["admin"],
                credentials["app"],
                "synthetic-private-data",
            ]:
                assert sensitive not in raw_logs
            # Persistence survives process restart; no secret directory is
            # shared with proxy.
            before = len(events)
            docker("restart", backend)
            inject(
                backend,
                "10001",
                {
                    "ca.crt": ca_pem,
                    "client.pem": client_pem,
                    "mongo-uri": mongo_uri.encode(),
                    "backend.crt": backend_cert,
                    "backend.pem": backend_pem,
                    "backend-ca.crt": ca_pem,
                    "security.json": policy_file.read_bytes(),
                },
                True,
            )
            wait(lambda: request()[0] == 200)
            raw_after = docker(
                "exec",
                backend,
                "python",
                "-c",
                "from pathlib import Path; print(sum(len(p.read_text()."
                'splitlines()) for p in Path("/var/lib/watchdawg/audit"'
                ').glob("audit-*.jsonl")))',
            )
            assert int(raw_after) > before
            print(
                json.dumps(
                    {
                        "synthetic_operations": "passed",
                        "tls_verified": True,
                        "least_privilege": "passed",
                        "failover": "passed",
                        "majority_outage": "failed_closed_and_recovered",
                        "encrypted_restore": "passed",
                        "audit_restart": "passed",
                        "public_release_approved": False,
                    }
                )
            )
        finally:
            for name in reversed(containers):
                subprocess.run(
                    ["docker", "rm", "--force", name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
            for volume in volumes:
                subprocess.run(
                    ["docker", "volume", "rm", volume],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
            for network in reversed(networks):
                subprocess.run(
                    ["docker", "network", "rm", network],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )


if __name__ == "__main__":
    main()
