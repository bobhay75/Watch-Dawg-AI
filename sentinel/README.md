# DAWG Sentinel v1 — evidence triage core

This module is a **review-only** early-warning classifier, not a live monitoring service or a disaster prediction model. It does not fetch feeds, send alerts, deploy, or perform external actions.

Inputs are explicitly supplied signal objects with an ID, category, headline, ISO observation time, indicators (impact 0–4), and source records (HTTPS URL, credible, independent). These source flags are assertions by the upstream curator, **not** independently validated by this module. Do not let an LLM assign trust without a reviewed source registry. Distinct hostnames alone do not prove editorial independence.

Output includes severity LOW/GUARDED/ELEVATED/HIGH/CRITICAL, confidence UNVERIFIED/SINGLE_SOURCE/CORROBORATED/STALE, alert eligibility, and mandatory human review. Alerts require freshness <=72h, >=2 asserted independent credible domains, and impact >=3. Never interpret these thresholds as calibrated probabilities.

Run: `node --test sentinel/sentinel.test.mjs`

Next integration: approved feed adapters (official weather alerts, CISA, central-bank releases, government emergency bulletins, trusted news), source registry with ownership/independence mapping, timestamp and duplicate-event validation, persistent history, cross-category cascade correlation, configurable geographic relevance, digest/notification delivery, rate limits, and audit log. Test all adapters with recorded fixtures before enabling network access. Never merge or deploy without owner approval.
