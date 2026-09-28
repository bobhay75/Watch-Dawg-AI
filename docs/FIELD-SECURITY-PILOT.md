# Watch-Dawg Field Security Pilot

## Positioning

Watch-Dawg Field Security turns the existing Watch-Dawg proof, audit, and human-review model toward a contractor-facing security problem: jobsite loss, undocumented incidents, tool/material exposure, change-order disputes, and weak field records.

The operating promise is:

> Protect the site. Document the truth. Reduce loss. Keep authority in human hands.

This is not a replacement for police, licensed alarm monitoring, legal advice, insurance underwriting, or a guaranteed security outcome. It is an evidence-first web application that helps owners and managers detect field risk, preserve proof, and decide what to do next.

## Buyer pain

Small contractors and field-service businesses can lose money when site reality moves faster than documentation. Common loss channels include:

- stolen tools, trailers, copper, fixtures, or job materials;
- customer-requested extras without an approved change order;
- damage claims with no before/after proof;
- crew labor or delivery activity without supporting records;
- unauthorized after-hours access to sensitive areas;
- mismatched purchases, receipts, and job-cost records;
- unclear responsibility when multiple trades touch one site.

One serious loss event can cost more than a pilot subscription. The financial case is prevention plus clean documentation.

## Core user

The first pilot should serve one owner/operator who manages one to five active jobsites or properties and needs fast proof without hiring a security department.

Primary users:

- owner/operator;
- site lead or foreman;
- office/admin reviewer;
- optional customer-facing read-only report recipient.

## MVP feature set

### 1. Site command dashboard

A single view for the owner or site lead:

- active sites/properties;
- current site status;
- open incidents;
- unresolved risk signals;
- missing daily documentation;
- most recent check-in;
- newest evidence receipt;
- next recommended human action.

The dashboard should not claim a whole site is safe. It should show what Watch-Dawg has evidence for and what remains unobserved.

### 2. Open boundary zones

Each site can define zones with different expectations instead of treating the whole property as locked down.

Examples:

- public approach;
- customer/visitor zone;
- crew work zone;
- material laydown zone;
- equipment/trailer zone;
- restricted after-hours zone;
- completed-work protection zone.

Each zone can carry:

- allowed time window;
- expected users or roles;
- evidence requirements;
- escalation level;
- report language;
- proof limitations.

### 3. Incident capture

A user can create an incident from mobile or desktop with:

- site;
- zone;
- category;
- severity;
- time observed;
- notes;
- photos;
- estimated financial exposure;
- people notified;
- action taken;
- follow-up required.

The app should preserve the original record and append later updates instead of silently overwriting history.

### 4. Evidence vault

Every uploaded or generated artifact should be stored with content-addressed references where practical:

- original photo or document reference;
- SHA-256 digest;
- uploader identity;
- timestamp;
- site/zone linkage;
- incident linkage;
- review status;
- limitations statement.

This aligns with the existing Watch-Dawg principle: prove what was observed and label interpretation separately.

### 5. AI risk summary

AI may summarize an incident only from captured evidence and declared context.

Allowed outputs:

- plain-English summary;
- likely business risk categories;
- missing evidence checklist;
- recommended next human action;
- report draft language;
- uncertainty and blind spots.

Disallowed outputs:

- accusations of criminal intent;
- guaranteed identification;
- automated police reports;
- autonomous remediation;
- legal conclusions;
- insurance coverage determinations;
- malware, exploitability, or intrusion claims without verified supporting evidence.

### 6. Human-reviewed report export

The pilot should export a clean report that separates:

- direct evidence;
- user statements;
- Watch-Dawg interpretation;
- unverified gaps;
- recommended next steps;
- attachments and digests.

Report types:

- incident report;
- theft/loss report;
- damage report;
- daily site log;
- change-order support packet;
- customer-facing condition summary;
- internal review packet.

### 7. Watch-Dawg peace / risk indicator

Use a simple operational indicator, not a false guarantee.

Suggested states:

- `CLEAR_OBSERVED`: No open findings within observed scope.
- `WATCH`: Low-confidence or missing-evidence concern.
- `REVIEW`: Human review needed before action.
- `URGENT_REVIEW`: High-priority human review recommended.
- `UNOBSERVED`: Watch-Dawg has insufficient evidence.

Avoid a single magical safety score in the pilot unless it clearly shows coverage limits.

## Data model sketch

```text
Organization
  id
  name
  owner_user_id
  subscription_status

User
  id
  organization_id
  role
  display_name
  contact_methods

Site
  id
  organization_id
  name
  address_or_label
  active
  default_timezone

Zone
  id
  site_id
  name
  zone_type
  allowed_window
  escalation_level
  evidence_requirements

Incident
  id
  site_id
  zone_id
  category
  severity
  observed_at
  created_by
  summary
  status
  estimated_exposure

EvidenceArtifact
  id
  incident_id
  artifact_type
  storage_ref
  sha256
  captured_at
  captured_by
  original_filename
  limitations

ReviewFinding
  id
  incident_id
  source
  direct_evidence_refs
  interpretation
  confidence
  status
  next_action

ReportExport
  id
  incident_id
  generated_by
  generated_at
  report_type
  package_sha256
  human_reviewed
```

## Pilot offer

### Watch-Dawg Field Security Starter Pilot

Recommended first offer: **$250 to $500 setup + 30-day pilot**.

Includes:

- one organization;
- one to three sites;
- zone setup;
- incident and evidence workflow;
- report templates;
- one owner/admin training session;
- weekly review summary;
- final risk and documentation-gap report.

Monthly subscription after pilot:

- single-site personal/business: $29-$49/month;
- contractor/jobsite: $79-$149/month;
- multi-site/operator: custom.

## Fastest build sequence

### Phase 1: Sellable clickable workflow

Build enough to demonstrate value without external integrations:

1. site dashboard;
2. zone setup;
3. incident creation;
4. photo/document attachment placeholder;
5. AI-style summary generated from local sample evidence;
6. evidence vault table;
7. report preview/export mock;
8. pilot signup/contact call-to-action.

### Phase 2: Real data persistence

Add authenticated organization accounts, durable storage, and append-only incident history.

### Phase 3: Evidence receipts

Add SHA-256 artifact digests, package manifests, and receipt verification using the same proof language already used by Watch-Dawg.

### Phase 4: Mobile-first field capture

Add PWA/offline-first capture for low-signal jobsites.

### Phase 5: Optional sensor/connectors

Only after the workflow sells, connect approved signals such as Android owner sensor exports, camera snapshots, storage logs, QuickBooks-style job costing, or website/asset audit evidence.

## Safety and authorization boundaries

The pilot must stay inside these limits:

- no unauthorized scanning;
- no credential guessing;
- no bypassing access controls;
- no covert tracking;
- no face recognition claim;
- no criminal identification claim;
- no automatic removal, disabling, or retaliation;
- no public emergency dispatch without human approval;
- no evidence modification without append-only history;
- no claim that Watch-Dawg proves legal truth, guilt, or intent.

## Success metrics

A pilot is working if it can show:

- number of sites configured;
- number of zones defined;
- number of incidents captured;
- number of reports generated;
- missing-documentation items found;
- estimated dollars at risk documented;
- owner actions taken;
- time saved in preparing a clean report;
- one clear before/after story from a real jobsite workflow.

## Product sentence

Watch-Dawg Field Security gives contractors and property owners a proof-first command center for jobsites: define open-boundary zones, capture incidents, preserve evidence, generate human-reviewed reports, and reduce financial loss without handing authority to an unchecked AI system.
