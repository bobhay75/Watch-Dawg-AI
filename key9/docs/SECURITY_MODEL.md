# KEY-9 security model

## Assets

- Human passwords and passkeys
- API keys, OAuth tokens, session credentials, and service identities
- Watch-Dawg job, payroll, receipt, and accounting records
- Authorization policies and audit receipts

## Trust assumptions

- Google Cloud IAM and Secret Manager enforce the configured service identity.
- The operator controls the allowlist and the mapping from alias to secret
  resource.
- Connectors use TLS and reject unexpected hosts.
- The public contest demo contains no real credentials or customer data.

## Threats and controls

| Threat | Control | Regression evidence |
|---|---|---|
| Prompt asks the model to reveal a password | Model has no secret retrieval tool; disclosure scopes are always denied | `test_secret_disclosure_scope_is_never_allowed` |
| Lookalike or suffix domain exfiltration | Normalized HTTPS host must equal the allowlisted host | `test_target_must_be_https_and_exact` |
| Agent invents a secret name | Only fixed aliases configured outside model control resolve | `test_unknown_alias_fails_closed` |
| Excess privilege | Requested scopes must be a subset of per-alias scopes | `test_unlisted_scope_is_denied` |
| Silent accounting write | Write scopes require explicit owner approval | `test_write_requires_owner_approval` |
| Long-lived credential exposure | Lease TTL is capped and invocation is single-use | `test_ttl_is_capped_by_policy`, `test_lease_is_opaque_and_revocable` |
| Credential appears in a connector response | Known values and common secret shapes are redacted | `test_secret_is_injected_then_removed_from_result` |
| Backend becomes unavailable | Server bridge uses a disclosed safe sandbox and performs no external write | `/api/agent` fail-closed branch |
| User pastes a secret into the goal | Secret-like assignments are rejected before the agent call | `/api/agent` input boundary |

## What KEY-9 does not claim

KEY-9 has not undergone an independent cryptographic or penetration-test audit.
It does not replace Android Credential Manager, a browser password manager, or a
network VPN in this prototype. It must not store real personal passwords in the
public contest environment.

The intended production direction is to reuse audited storage and platform
credential APIs while KEY-9 supplies the policy, orchestration, connector, and
proof-of-action layer.
