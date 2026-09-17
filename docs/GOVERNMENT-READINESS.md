# Watch-Dawg government-readiness boundary

Watch-Dawg is being engineered so a public-sector evaluator can inspect what it
does, what it cannot do, who authorized each operation, and what evidence each
run produced. This document is a readiness statement, not a certification.

## Current sellable scope

The current defensible offer is a **customer-managed, authorized assessment
pilot** for public websites, owned traffic logs, reviewed source files, and
explicitly named TCP services and AI-system control manifests. The customer
supplies the written scope and runs Watch-Dawg in an environment it controls.
Watch-Dawg produces findings and redacted evidence; a human decides whether any
corrective action occurs.

The World Economic Forum's [*Global Cybersecurity Outlook
2026*](https://www.weforum.org/publications/global-cybersecurity-outlook-2026/)
reports that 87% of its survey respondents identified AI-related vulnerabilities
as the fastest-growing cyber risk during 2025. Watch-Dawg addresses the control
problem that statistic highlights through deterministic evidence checks—not by
claiming that a static manifest can prove an AI system secure.

The service-exposure pack:

- accepts only `owner` or `contract` authority;
- requires an authorization record ID, exact hostname and exact port list;
- requires an expiration time and the approved `tcp-connect` method;
- limits a run to 16 explicit ports on a public address;
- performs TCP connection checks only—no ranges, banners, exploits, payloads,
  credential attempts, evasion, persistence, or lateral movement.

The secret-exposure pack:

- accepts only explicitly listed local files under a configured root;
- requires an authorization record, exact path scope, expiration, and the
  `read-local-files` method;
- limits file count and size;
- reports the rule, file, line, and a truncated SHA-256 fingerprint;
- never returns the matched credential value.

The financial correction path creates a deterministic proposal tied to a
SHA-256 digest of the source ledger. Application requires an exact plan digest,
an explicit `APPROVE` decision, and a named approver. It returns a corrected
copy and audit receipt; it does not write to a bank, accounting system, or
external record.

The AI-system pack reads only an exact authorized local manifest. It checks
immutable model identity, supplier remote-code trust, high-impact tool approval,
deny-by-default tool and egress policy, prompt-injection defenses, output
validation, brokered secrets, redacted logging, kill switch, model-change
approval, vendor and data-provenance records, incident recovery targets and
tests, and cryptographic migration ownership. It does not invoke a model,
execute a tool, probe an endpoint, or establish that the declared controls are
operating effectively.

The repository supply-chain verifier requires GitHub Actions to use full commit
SHAs, Python dependencies to use exact versions, and Node projects with
dependencies to retain a lockfile. Versioned-but-not-digest-pinned container
bases remain an explicit warning and procurement gap.

## Control crosswalk

`government-control-matrix.json` is a candidate crosswalk to relevant NIST SP
800-53 control families. It is evidence-navigation help, not an assertion that
an assessor has found the controls effective. The evidence bundle generator
produces a source inventory, SHA-256 file manifest, test commands, revision
identifier, and SPDX 2.3 software bill of materials.

Primary references:

- [NIST Secure Software Development Framework (SP 800-218)](https://csrc.nist.gov/pubs/sp/800/218/final)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [NIST OSCAL](https://pages.nist.gov/OSCAL/)
- [CISA Software Bill of Materials](https://www.cisa.gov/sbom)
- [CISA Secure by Design](https://www.cisa.gov/securebydesign)
- [FedRAMP authorization](https://www.fedramp.gov/authorization/)

## Claims that are not permitted yet

Do not describe Watch-Dawg as FedRAMP Authorized, FISMA compliant, FIPS
validated, CMMC certified, NIST compliant, approved for CUI, Section 508
conformant, or authorized by any agency. Those outcomes require a defined
system boundary, production environment, organizational policies, independent
assessment where applicable, and customer/agency decisions beyond this source
repository.

## Remaining gates before a federal production offer

1. Choose the delivery model and information types: customer-managed software,
   contractor-operated service, or federal cloud service.
2. Define the authorization boundary, data flows, roles, retention, incident
   response, contingency recovery, vulnerability handling, and support SLA.
3. Move state and audit records to durable, access-controlled storage with
   retention, integrity protection, backup, and cross-instance locking.
4. Add agency identity federation, role-based access, separation of duties, and
   centralized rate limiting.
5. Establish an approved cryptographic boundary and document validated modules
   where a contract requires FIPS validation; maintain an algorithm inventory
   and migration triggers for post-quantum transition. The present inventory
   check is not cryptographic agility, post-quantum protection, or FIPS
   validation by itself.
6. Complete accessibility testing and create an accurate Accessibility
   Conformance Report when the user interface is offered to an agency.
7. Threat-model and independently test the exact production deployment.
8. Create the required SSP/OSCAL package and pursue the procurement or
   authorization route selected by the customer.

## Build an evaluator evidence bundle

```bash
python scripts/generate_government_evidence.py \
  --output build/government-evidence
```

Then run the verification printed in `evidence-manifest.json`. CI builds the
same bundle as a downloadable artifact for each relevant pull request and push
to `main`. The bundle now includes `supply-chain-report.json`; warnings must be
reviewed rather than interpreted as a clean bill of health.
