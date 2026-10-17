# Sentinel Scholarship Hunter — implementation specification

Purpose: help the owner discover, qualify for, prepare, submit with explicit approval, and track legitimate scholarships and education grants. Never guarantee awards.

## Profile (private, consent-based)
School, current confirmed degree/major, enrollment status, credits, GPA, graduation estimate, location eligibility, adult-learner status, work/trades experience, relevant career goals, and user-approved financial eligibility facts. Do not embed personal or sensitive profile data in the public repository. Verify current major and enrollment before filtering. Store documents privately, encrypted where appropriate.

## Discovery and verification
Official university scholarship portal, institutional financial aid, legitimate foundation and government sites, professional associations, trade/cybersecurity scholarships, Missouri resources. Preserve direct official application URL, eligibility text, amount, deadline/timezone, renewal rules, fees, source checked date, and evidence. Flag dubious fees, guaranteed-award claims, requests for bank credentials, or unrelated sensitive data. Avoid duplicate and expired listings.

## Workflow
Discovered -> eligibility review -> qualified / ineligible / uncertain -> documents needed -> draft ready -> owner review -> owner-authorized submission -> confirmation captured -> follow-up -> awarded / declined / expired. Preserve audit trail, confirmation receipts, deadline alerts, and no double submissions.

## Ranking
Prioritize verified eligibility, approaching deadline, realistic competitiveness, award value, effort, and reusable materials. Show reasons and missing information; never fabricate qualifications, references, essays, or documents.

## Permissions
No autonomous account creation, login bypass, payments, legal attestations, submissions, or outreach without explicit owner authorization. No production deployment without approval.

## MVP acceptance tests
Correctly reject expired and ineligible opportunities; distinguish unknown eligibility; deduplicate; sort by verified deadline and fit; preserve original source; never mark an application submitted without a confirmation record. Live discovery, integrations, and submissions are not yet implemented.
