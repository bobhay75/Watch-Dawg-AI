// DAWG Sentinel v1: deterministic evidence triage; no autonomous claims.
export const CATEGORIES = Object.freeze(['geopolitical','economic','cybersecurity','ai','infrastructure','environmental','social']);
const LEVELS = ['LOW','GUARDED','ELEVATED','HIGH','CRITICAL'];
export function assessSignal(input, now = new Date()) {
  if (!input || typeof input !== 'object') throw new TypeError('Signal object required');
  const {id, category, headline, sources, observedAt, indicators = []} = input;
  if (typeof id !== 'string' || !id.trim() || !CATEGORIES.includes(category) ||
      typeof headline !== 'string' || !headline.trim() ||
      !Array.isArray(sources) || !Array.isArray(indicators)) throw new TypeError('Invalid signal');
  const observed = new Date(observedAt);
  if (!Number.isFinite(observed.getTime())) throw new TypeError('Invalid observation date');
  const ageHours = (now.getTime() - observed.getTime()) / 3600000;
  const fresh = ageHours >= 0 && ageHours <= 72;
  const verified = sources.filter(s => s && /^https:\/\//.test(s.url || '') && s.independent === true && s.credible === true);
  const domains = new Set(verified.map(s => new URL(s.url).hostname.replace(/^www\./,'')));
  const corroborated = domains.size >= 2;
  const severity = indicators.reduce((max, i) => {
    if (!i || !Number.isInteger(i.impact) || i.impact < 0 || i.impact > 4) throw new TypeError('Impact must be 0..4');
    return Math.max(max, i.impact);
  }, 0);
  const level = LEVELS[severity];
  const confidence = !fresh ? 'STALE' : corroborated ? 'CORROBORATED' : verified.length ? 'SINGLE_SOURCE' : 'UNVERIFIED';
  const alert = fresh && corroborated && severity >= 3;
  return {id,category,headline,observedAt:observed.toISOString(),level,confidence,alert,
    sourceCount:domains.size,reviewRequired:true,
    reason:!fresh?'Stale or future-dated evidence':!corroborated?'Insufficient independent corroboration':severity<3?'Below alert threshold':'High-impact corroborated signal',
    sources:verified.map(s=>({url:s.url})),indicators};
}
export function evaluateBatch(signals, now = new Date()) {
  if (!Array.isArray(signals)) throw new TypeError('Signals array required');
  const unique = new Map();
  for (const signal of signals) {
    const result = assessSignal(signal,now);
    unique.set(result.id,result);
  }
  return [...unique.values()].sort((a,b)=>Number(b.alert)-Number(a.alert) || LEVELS.indexOf(b.level)-LEVELS.indexOf(a.level));
}
