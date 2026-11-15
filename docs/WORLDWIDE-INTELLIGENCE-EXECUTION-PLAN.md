# Worldwide Intelligence Brief — execution plan
Date: 2026-11-15
Status: proposed implementation, not live monitoring
Owner: Watch-Dawg AI; evidence review: Trust-Worthy AI

## Mission
Worldwide public-source intelligence with deeper U.S. coverage. Watch-Dawg ingests and flags observations; Trust-Worthy evaluates evidence and counterevidence. Free public beta first; commercial licensing only after validation. Continue other product development in parallel.

## Initial vertical slice
1. Ingest three documented public sources: NOAA weather observations, NASA Earth observation metadata, and a public aviation source with explicit commercial-use terms. Verify API availability and licenses before implementation.
2. Normalize records to UTC, latitude/longitude (rounded or withheld when sensitive), source ID, retrieval timestamp, original URL, observation window, data quality, and license.
3. Persist raw source responses and normalized events locally with hashes and deduplication; maintain backups and recovery tests.
4. Produce a deterministic weekly report: executive summary; SkyWatch aviation/atmosphere; God's Eye environmental change; infrastructure/security; global comparisons; evidence ledger; corrections.
5. Require human review for public conclusions and alerts. No automatic attribution of aircraft trails to intentional spraying. Compare humidity, altitude, weather, traffic and environmental measurements; distinguish contrails from documented cloud seeding.
6. Publish only approved summaries at bobsome1.com; never publish private paleo-site coordinates or protected originals.

## 30-day parallel delivery targets
- Days 1–7: source/license matrix, ingestion adapter contract, event schema, first reproducible sample ingest and tests.
- Days 8–14: local evidence store, provenance checks, first actual-data U.S. draft.
- Days 15–21: global baseline comparisons, alert rules, false-positive review.
- Days 22–30: public beta report after review, corrections ledger, operational and cost assessment.

## Release gates
- Source links, capture times, and license status on every public finding.
- Clear labels: observed / independently corroborated / unresolved / contradicted / corrected.
- No fabricated observations, scores, predictions, or confidence percentages.
- Tests for ingestion failure, stale data, duplicate events, privacy redaction, and offline restore.
- Record uptime, missing-data intervals, false alerts, review decisions, and user feedback.
- Public beta remains free. Paid API and data resale require license review.

## Next engineering action
Implement the normalized observation schema and a fixture-backed ingestion test in a separate PR. Keep existing contractor/security functions intact; do not rewrite the production app.
