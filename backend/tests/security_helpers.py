"""Synthetic credentials and atomic in-memory unit-test storage only."""

import hashlib
import secrets
import threading

from backend.security import Policy, Limited

TOKEN = "synthetic_" + "a" * 43
READ_TOKEN = "synthetic_" + "b" * 43
ROTATED_TOKEN = "synthetic_" + "c" * 43


def policy_document(token=TOKEN, network="127.0.0.1/32"):
    return {
        "rate_hmac_key": secrets.token_hex(32),
        "allowed_hosts": ["testserver", "127.0.0.1", "localhost"],
        "allowed_networks": [network, "127.0.0.1/32"],
        "allowed_origins": ["https://synthetic.invalid"],
        "transport": "test",
        "principals": [
            {
                "id": "synthetic-analysis",
                "scopes": ["health:read", "audit:run"],
                "token_sha256": [
                    hashlib.sha256(t.encode()).hexdigest()
                    for t in (token, ROTATED_TOKEN)
                ],
                "expires_at": "2099-01-01T00:00:00Z",
            },
            {
                "id": "synthetic-monitor",
                "scopes": ["health:read"],
                "token_sha256": [
                    hashlib.sha256(READ_TOKEN.encode()).hexdigest()
                ],
                "expires_at": "2099-01-01T00:00:00Z",
            },
        ],
        "rates": {
            "global_limit": 1000,
            "network_limit": 500,
            "principal_limit": 200,
            "global_streams": 8,
            "principal_streams": 8,
        },
    }


def unit_policy(**changes):
    doc = policy_document()
    doc.update(changes)
    return Policy.parse(doc)


class MemorySecurityStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts = {}
        self.leases = {}

    async def take(self, key, limit, expires):
        with self.lock:
            if self.counts.get(key, 0) >= limit:
                raise Limited
            self.counts[key] = self.counts.get(key, 0) + 1

    async def acquire(self, key, limit, seconds):
        with self.lock:
            for slot in range(limit):
                handle = (key, slot)
                if handle not in self.leases:
                    self.leases[handle] = True
                    return handle
            raise Limited

    async def release(self, handle):
        with self.lock:
            self.leases.pop(handle, None)
