// DAWG Sentinel: deterministic, offline, review-only triage.
import {readFileSync} from 'node:fs';
import {timestamp, verifyEvidence} from './evidence.mjs';
const DEFAULT_REGISTRY = JSON.parse(readFileSync(new URL('./source-registry.json', import.meta.url), 'utf8'));
export const CATEGORIES = Object.freeze(['geopolitical','economic','cybersecurity','ai','infrastructure','environmental','social']);
const LEVELS = ['LOW','GUARDED','ELEVATED','HIGH','CRITICAL'];
export function assessSignal(input, now = new Date(), {registry = DEFAULT_REGISTRY, evidenceReviews = []} = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Signal object required');
  const {id, category, headline, sources, observedAt, indicators = []} = input;
  if (typeof id !== 'string' || !id.trim() || !CATEGORIES.includes(category) ||
      typeof headline !== 'string' || !headline.trim() ||
      !Array.isArray(sources) || !Array.isArray(indicators)) throw new TypeError('Invalid signal');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new TypeError('Invalid evaluation clock');
  const observed = timestamp(observedAt);
  if (!Number.isFinite(observed)) throw new TypeError('Observation must be a valid UTC ISO timestamp');
  const ageHours = (now.getTime() - observed) / 3600000;
  const fresh = ageHours >= 0 && ageHours <= 72;
  const severity = indicators.reduce((max, i) => {
    if (!i || !Number.isInteger(i.impact) || i.impact < 0 || i.impact > 4) throw new TypeError('Impact must be 0..4');
    return Math.max(max, i.impact);
  }, 0);
  const evidence = verifyEvidence(input, now.getTime(), registry, evidenceReviews, severity);
  const corroborated = evidence.independentSourceCount >= 2;
  const confidence = !fresh ? 'STALE' : corroborated ? 'CORROBORATED' : evidence.sources.length ? 'SINGLE_SOURCE' : 'UNVERIFIED';
  const alert = fresh && corroborated && severity >= 3;
  return {id,category,headline,observedAt:new Date(observed).toISOString(),level:LEVELS[severity],confidence,alert,
    sourceCount:evidence.independentSourceCount,...evidence,reviewRequired:true,reviewOnly:true,
    reason:!fresh?'Stale or future-dated event':!corroborated?'Insufficient reviewed independent evidence':severity<3?'Below alert threshold':'Eligible for human review; no external action',
    indicators};
}
export function evaluateBatch(signals, now = new Date(), options = {}) {
  if (!Array.isArray(signals)) throw new TypeError('Signals array required');
  const unique = new Map();
  for (const signal of signals) {
    const result = assessSignal(signal,now,options);
    // Never silently overwrite an earlier claim with a conflicting duplicate ID.
    const serialized = JSON.stringify(signal);
    if (unique.has(result.id) && unique.get(result.id).serialized !== serialized) throw new TypeError('Conflicting duplicate signal ID');
    unique.set(result.id,{serialized,result});
  }
  return [...unique.values()].map(entry => entry.result).sort((a,b)=>Number(b.alert)-Number(a.alert) || LEVELS.indexOf(b.level)-LEVELS.indexOf(a.level));
}
