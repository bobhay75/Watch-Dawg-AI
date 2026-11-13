# Prosper AI Gateway integration (optional developer preview)

This branch proposes a **real execution-point authorization check** at the Watch-Dawg
Sentinel API's `POST /v1/run` endpoint. The existing bearer authentication, approved
profile allowlist, cooldown and rate limits remain in place.

## Local setup

Run Prosper AI Gateway v0.7 on `127.0.0.1:8080`. Register agent `watch-dawg`
and grant exactly `sentinel.run`; securely copy its agent key. In the Sentinel
service process, set:

```bash
export PROSPER_GATEWAY_URL=http://127.0.0.1:8080
export PROSPER_AGENT_KEY='YOUR_AGENT_KEY'
```

Configure the existing `SENTINEL_API_TOKEN`, `SENTINEL_PROFILES_JSON`, etc.
as usual and start the Sentinel API. Never commit keys or config secrets.

When configured, every run must be permitted by Prosper first:
- allow: continue to approved profile execution
- deny / revoked key: HTTP 403, no run
- unavailable / broken gateway: HTTP 503, no run
- invalid config: startup fails

When not configured, existing Sentinel behavior is unchanged. This is an opt-in
**prototype** and not multi-tenant production security. The gateway is loopback-only;
cross-host use requires a separate authenticated TLS design. Authorization and
execution are not atomic; code calling `SentinelEngine` directly is not covered.

## Test

```bash
python3 -m unittest -v sentinel.tests.test_prosper_guard sentinel.tests.test_api
```

No production secrets or operational profiles are used in these tests.
