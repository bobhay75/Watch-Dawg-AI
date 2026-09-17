# Watch-Dawg AI capability statement — draft

**Provider:** Bobsome1 / Watch-Dawg AI  
**Website:** https://bobsome1.com/  
**Offering:** Authorized cyber observation, operational audit, and human-gated
correction evidence for public-sector pilots

> Complete the legal entity name, physical address, point of contact, UEI,
> CAGE code, socioeconomic status, approved NAICS/PSC codes, and contract
> vehicles before submitting this document to a contracting officer.

## Core capabilities

- Passive public-website, DNS, TLS, sitemap, content, latency, and response-
  header monitoring.
- Authorized, explicit-port TCP reachability checks for owned public systems,
  with exact method, asset, port, and expiration scope.
- Owned Apache/Nginx traffic-log review with client IP hashing, service-error
  thresholds, authentication-failure counts, traffic-change detection, and
  clearly labeled probe-pattern inference.
- Authorized source-file credential-exposure review with redacted evidence;
  suspected values are fingerprinted and never included in output.
- Authorized AI-system control-manifest review covering immutable model
  identity, supplier remote code, high-impact tool approval, zero-trust egress
  and tool defaults, prompt/output safeguards, brokered secrets, recovery
  objectives, and cryptographic migration ownership.
- Repository supply-chain evidence covering commit-pinned workflow actions,
  exact Python dependencies, Node lockfiles, container-base digests, source
  hashes, and a machine-readable SPDX SBOM.
- Deterministic transaction-allocation review and SHA-256-bound correction
  proposals that require explicit review and create no external financial
  write.
- Repeat-noise suppression, new/resolved finding tracking, evidence grading,
  prioritized preventive action, and retained verification instructions.

## Differentiators

- Authorization is a runtime prerequisite, not merely contract language.
- Active checks are deliberately bounded: no port ranges, banner collection,
  exploitation, credential guessing, evasion, persistence, or lateral movement.
- Findings separate direct observation (`VERIFIED`) from interpretation
  (`INFERENCE`).
- Secret values and traffic client identifiers are excluded or transformed
  before entering findings.
- The evidence build produces source hashes, a machine-readable SPDX SBOM,
  verification commands, revision identity, and a candid control-gap matrix.
- Human decision authority remains outside the automated observation engine.
- AI assessment is deterministic and manifest-only: no model invocation,
  autonomous exploitation, credential guessing, or automatic external action.

## Fixed-scope pilot

**Authorized Observation and Evidence Pilot — 30 days**

Customer supplies:

- one accountable system owner;
- written authority, exact assets, permitted methods, and expiration;
- an approved customer-managed execution environment;
- the expected service and content baselines;
- a secure contact for urgent findings.

Watch-Dawg supplies:

1. reviewed target profile and authorization manifest references;
2. installation and operator runbook;
3. initial baseline and prioritized findings report;
4. scheduled comparison runs using the customer-approved cadence;
5. new/resolved finding evidence and a closeout verification report;
6. source/SBOM/control-crosswalk evidence bundle for technical review.
7. AI-control and software-supply-chain gap report when those scopes are
   included in the authorization record.

Acceptance criteria:

- no operation occurs outside the approved target and method scope;
- every finding identifies its evidence and truth label;
- credential values do not appear in output;
- repeated unchanged findings do not generate repeated alerts;
- all proposed financial changes remain non-executing unless a separately
  reviewed integration and authenticated approval boundary are contracted.

## Current deployment boundary

The safest current offer is customer-managed software or a private,
single-instance evaluation service. It is not represented as FedRAMP
Authorized, FISMA compliant, FIPS validated, approved for CUI, CMMC certified,
Section 508 conformant, or agency authorized. Production cloud authorization,
durable centralized audit storage, agency identity federation, incident
response operations, accessibility conformance, and independent assessment are
separate work packages.

## Procurement completion checklist

- [ ] Register and maintain the legal entity in SAM.gov; record UEI and CAGE.
- [ ] Select NAICS and PSC codes with an acquisition professional or the target
      solicitation rather than claiming codes from this draft.
- [ ] Publish a verified security-reporting contact and response SLA.
- [ ] Choose customer-managed, contractor-operated, or federal-cloud delivery.
- [ ] Define data types and confirm whether CUI, PII, financial, tax, health, or
      law-enforcement data is excluded or requires additional controls.
- [ ] Complete a production threat model, accessibility review, incident plan,
      retention schedule, continuity plan, and independent security test.
- [ ] Validate declared AI safeguards through adversarial testing, runtime
      telemetry, supplier review, and incident exercises; a manifest alone is
      not operating-effectiveness evidence.
- [ ] Establish a documented dependency-update and vulnerability-response SLA;
      review and deliberately update pinned container digests on that cadence.
- [ ] Tailor the control matrix and SSP/OSCAL artifacts to the actual agency
      system boundary.

Technical readiness and claim restrictions are maintained in
[`GOVERNMENT-READINESS.md`](GOVERNMENT-READINESS.md).
