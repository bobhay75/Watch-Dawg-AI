# Sentinel Historical Pattern Intelligence — design contract

Guiding hypothesis: recurring human incentives and system dynamics may produce measurable precursor patterns. "History repeats" is a research hypothesis, not a guarantee of forecast accuracy.

## Historical case schema
Each case records: case ID, geography, start/end, outcome type, outcome onset date, observation cutoff date, measured indicators and their original as-of publication dates, verified primary/secondary sources, missing-data flags, confounders, and retrospective revisions. Include matched *non-event* control windows and recovered/averted crises. Avoid selecting only famous disasters.

## Matching and forecasts
- Compare economic, geopolitical, social, infrastructure, environmental and technological precursors using explicitly versioned, explainable feature definitions.
- Align timelines relative to observation cutoffs; prohibit future knowledge and revised historical values leaking into prior forecasts.
- Use historical analogues to generate hypotheses; require independently calibrated models to produce probabilities.
- Publish event definition, region, horizon (30/90/365 days), base rate, probability, uncertainty interval, and top positive/negative indicators. If data are insufficient, abstain.
- A similarity score is **not** an event probability.
- Evaluate with walk-forward time splits, untouched holdout eras, Brier score, calibration plots, precision/recall, false alarm rate and lead time. Compare against base-rate and simple-trend baselines.
- Audit data provenance, changes, drift, geographic bias and historical revision; preserve forecast snapshots for later scoring.
- Never claim exact disaster dates, inevitability, divine revelation or verified prediction accuracy without prospective evidence.

## Example question
Given currently available bank stress, lending, employment and liquidity indicators, which past periods are most comparable, how did both crisis and non-crisis analogues unfold, and does a validated model show risk above baseline for a defined 90-day horizon?

## Integration boundaries
No automatic external actions. Do not notify on historical similarity alone. Escalation requires credible contemporary corroboration and human-reviewed severity. No production deployment without owner approval.

## Next implementation slice
Build historical case ingestion/validation, a versioned local dataset with non-events, time-aware analogue ranking, walk-forward backtests, calibration reporting, and an explainable Sentinel dashboard. Keep original evidence and model outputs separately.
