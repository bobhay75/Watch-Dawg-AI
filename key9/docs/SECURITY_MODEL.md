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
| Long-lived credential exposure | Lease TTL is capped and invocation is single-use | `test_ttl_is_capped_by_policy`, `test_lease_is_opaque_and_consumable` |
| Concurrent replay or retry after provider failure | Lease is atomically consumed before target check, provider access, or connector execution | `test_concurrent_replay_executes_exactly_once`, `test_provider_failure_cannot_restore_consumed_lease` |
| Target is swapped between authorization and invocation | Invocation host must equal the canonical host bound into the consumed lease | `test_invocation_target_mismatch_consumes_lease_without_secret_access` |
| Credential appears in nested or escaped connector output | Structured payloads are recursively redacted before serialization | `test_nested_and_json_escaped_secrets_are_redacted` |
| Backend becomes unavailable | Server bridge uses a disclosed safe sandbox and performs no external write | `/api/agent` fail-closed branch |
| User pastes a secret into the goal | Secret-like assignments are rejected before the agent call | `/api/agent` input boundary |
| Public UI relays a privileged approval | Public approval returns a truthful local simulation and never calls `/v1/approve-export` | `test_public_route_cannot_relay_owner_approval` |
| Static headers are mistaken for production owner authentication | Approval endpoint is disabled outside sandbox until owner authentication exists | `test_production_approval_fails_closed_until_owner_auth_exists` |
| Low-trust repository or tool content gains authority | Repository policy declares context origin, trust, role, scope, mutability, and prohibited implicit sources | `test_context_sources_are_explicit_and_implicit_sources_are_denied` |
| Lifecycle metadata executes with ambient authority | Application hooks are default-deny and package lifecycle scripts are checked | `test_application_package_defines_no_lifecycle_hooks` |
| In-memory mission state is used in production | Non-sandbox startup rejects `memory://` | `test_production_rejects_process_local_sessions` |
| One PoC or passing regression test is treated as a valid repair | Evidence gate requires reachability, multiple triggers, patched-twin counterevidence, root cause, and semantic regression evidence | `test_single_poc_is_not_patch_acceptance`, `test_complete_bundle_advances_only_to_human_review` |
| Public sandbox is deployed as if production-ready | Deploy script requires explicit sandbox opt-in and always sets sandbox mode | `test_public_cloud_run_deploy_requires_explicit_sandbox_opt_in` |

## What KEY-9 does not claim

KEY-9 has not undergone an independent cryptographic or penetration-test audit.
It does not replace Android Credential Manager, a browser password manager, or a
network VPN in this prototype. It must not store real personal passwords in the
public contest environment.

The supplied Cloud Run configuration is publicly reachable and protected by an
application bridge token; it is suitable only for synthetic sandbox data. A
production design still needs private Cloud Run IAM, workload identity between
the web bridge and agent service, and authenticated owner approval. Audit
receipts are dynamic but are not yet signed or stored in a durable append-only
system. The context manifest and Agent Control Standard fields are local policy
and preview-shaped telemetry, not a runtime context-taint engine or proof of
standards conformance. The evidence gate evaluates supplied lab artifacts; it
does not perform scanning, exploitation, patching, or release approval. A UI
stop prevents stale local state transitions but does not prove that an in-flight
remote ADK run was cancelled.

The intended production direction is to reuse audited storage and platform
credential APIs while KEY-9 supplies the policy, orchestration, connector, and
proof-of-action layer.
