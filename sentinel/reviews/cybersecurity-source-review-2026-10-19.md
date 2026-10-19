# Cybersecurity sources — pending human review

Research date: 2026-10-19. State: **PENDING; NO REAL SOURCE APPROVED**.

This packet is research for a human curator, not a source registry, a claim
review, or an executable dossier. The normal `source-registry.json` remains
empty. No source credibility, editorial independence, live integration or
notification permission is granted by this document. No named human has reviewed
or approved these candidates in this packet.

Cybersecurity is the first proposed category because the existing synthetic
classifier example uses it. This is an implementation default, not a recorded
owner preference. The candidates below are a small starting set, not a complete
or ranked list of reliable publishers.

## Findings and unresolved decisions

| Candidate | Proposed exact content host; not approved | Evidence obtained | Human decisions still open |
| --- | --- | --- | --- |
| CISA | `www.cisa.gov` | The `cisagov` GitHub organization identifies itself as CISA. GitHub displays verified control of `cisa.gov` and `cisa.dhs.gov` [1]. | Verify the exact content host, current institutional control, relevant publishing desk, original reporting and claim-specific support. Root-domain verification is supporting evidence, not approval of every subdomain or document. |
| NIST National Vulnerability Database | `nvd.nist.gov` | NIST's own About page places NIST within the U.S. Department of Commerce and links to NVD [2]. An indexed official NVD FAQ describes enriching published CVEs using reference and publicly available information [3]. | Preserve and inspect the full NVD process documentation and each selected record. Distinguish original observations from descriptions, reference links and third-party metrics inherited from elsewhere. |
| CERT/CC Vulnerability Notes Database | `www.kb.cert.org` | Its own site identifies the CERT Division/SEI, says SEI is operated by Carnegie Mellon University, and lists CISA sponsorship [4]. | Verify editorial authority and the relevance of sponsorship to the particular report. Identify common authors, researchers, vendor disclosures and coordinated publication chains before claiming independence. |

All three candidates remain pending. No `ownerId` or `editorialGroupId` is
approved, and no reviewer, review time or expiry has been invented to make a
registry record appear complete.

## Dependence policy proposed for human review

These are conservative policy proposals and inferences, not findings of
editorial control:

- If the chosen owner policy groups the U.S. federal government as one ultimate
  controlling entity, CISA and NIST/NVD must share an owner group. Separate
  agencies or domains would not produce two independent counts under that policy.
- CERT/CC's university operation does not, on its own, establish independence
  from CISA for a given publication. Its stated sponsorship is a relationship
  requiring review, not proof that CISA directs its editorial decisions.
- NVD enrichment must not be treated as independent confirmation of every
  upstream assertion. A vendor advisory, a CVE description and an NVD entry
  repeating that description can share one reporting origin even on different
  domains. A shared CVE number identifies a vulnerability; it does not, by itself,
  prove either independent investigation or a common original investigation.
- A coordinated CERT/CC note and a vendor advisory can also describe one joint
  disclosure. Establish the actual reporting chain; do not manufacture a second
  `originId` from a second URL.
- Only a human-reviewed record that directly supports the exact claim and its
  impact ceiling can corroborate it. Merely identifying a publisher, a CVE or a
  severity score is insufficient. Do not convert a CVSS value automatically into
  Sentinel's 0–4 impact value.

## Shared hosting and aliases

Use CISA's GitHub profile as identity evidence only. **Do not approve all of
`github.com` or `raw.githubusercontent.com` as CISA**: those hostnames serve other
organizations as well. This classifier's registry has exact-host identity and
has no reviewed organization/path-scoped identity policy. Shared hosting needs a
separately designed and tested scope policy before any such approval.

Do not silently add `cisa.gov`, `cisa.dhs.gov`, `kb.cert.org`, alternate NIST
hosts, mirrors or redirect targets as approved aliases. Each must be explicitly
reviewed. A verified root domain, a redirect, branding or a similar hostname is
not an independent editorial source.

## Retrieval record and evidence limitations

This was a one-time manual research pass, not a live feed integration.

| Reference | Retrieval outcome on research date | What that permits |
| --- | --- | --- |
| [1] CISA GitHub organization | Readable organization page, including GitHub's domain-verification display | Supporting identity evidence; no blanket approval of GitHub content |
| [2] NIST About page | Readable institutional page and NVD navigation link | Supporting institutional association; no claim-specific verification |
| [3] NVD CVE FAQs | Official indexed text was available; direct opening redirected to a lowercase path but yielded no readable body | Research lead only; a full preserved source document remains required |
| [4] CERT/CC notes home | Readable page with operator and sponsorship information | Supporting relationship evidence; no determination of editorial control |
| [5] CISA About; [6] DHS cybersecurity page | Direct opening returned HTTP 403 | No usable document captured from these attempts; do not infer absence, unreliability or approval |

No original HTML/PDF bytes, document hashes or approved claim reviews were
created from these search renderings. They must not be inserted into an offline
dossier as if they were authenticated captures. Research access date is not the
publication date of any cyber event. These pages do not establish a current
incident, exposure, exploitation status or warning.

## Concrete human review record still needed

For each proposed source, a curator must resolve the exact host, institutional
control, editorial authority, relevant scope and documented relationships; then
record their own identity, reasoning, references, review date and expiry in a
protected registry snapshot. Keep unknown cases pending.

For the first real signal, preserve the actual documents locally; hash their
exact bytes with `sentinel:prepare`; establish the same event, original reporting
chains, publication/retrieval times and supported impact; and complete explicit
claim approvals. Keep revocation tombstones. Use `sentinel:review` to recheck
preserved bytes and policy. Hash agreement cannot establish factual truth.

No approvals are requested or assumed by this packet. A source approval does not
authorize feeds, notifications, autonomous decisions, merge or deployment.

## Primary references

1. [CISA organization on GitHub](https://github.com/cisagov).
2. [About NIST](https://www.nist.gov/about-nist).
3. [NVD CVE FAQs](https://nvd.nist.gov/general/faq-sections/cve-faqs).
4. [CERT/CC Vulnerability Notes Database](https://www.kb.cert.org/vuls/).
5. [CISA About — blocked during direct retrieval](https://www.cisa.gov/about).
6. [DHS cybersecurity — blocked during direct retrieval](https://www.dhs.gov/topics/cybersecurity).
