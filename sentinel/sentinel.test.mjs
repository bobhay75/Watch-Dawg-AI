import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessSignal,evaluateBatch} from './sentinel.mjs';
import {canonicalURL} from './evidence.mjs';
const fixture = JSON.parse(readFileSync(new URL('./fixtures/evidence-review.json',import.meta.url),'utf8'));
function setup(indices = [0,1]) {
  const f = structuredClone(fixture);
  f.signal.sources = indices.map(i => f.signal.sources[i]);
  f.now = new Date(f.now);
  return f;
}
function assess(f) { return assessSignal(f.signal,f.now,f); }
function blocked(f, reason) {
  const r = assess(f);
  assert.equal(r.alert,false);
  if (reason) assert.ok(r.rejectedEvidence.some(e => e.reason === reason), JSON.stringify(r));
  return r;
}
test('reviewed independent claim qualifies only for human review',()=>{
  const r=assess(setup()); assert.equal(r.alert,true); assert.equal(r.confidence,'CORROBORATED');
  assert.equal(r.sourceCount,2); assert.equal(r.reviewRequired,true); assert.equal(r.reviewOnly,true);
  assert.deepEqual(r.rejectedEvidence,[]);
});
test('empty shipped registry and omitted reviews fail closed despite asserted trust',()=>{
  const f=setup(); f.signal.sources.forEach(s=>Object.assign(s,{credible:true,independent:true,sourceId:'trusted'}));
  assert.equal(assessSignal(f.signal,f.now).confidence,'UNVERIFIED');
  assert.equal(assessSignal(f.signal,f.now,{registry:f.registry}).alert,false);
});
test('signal payload cannot inject a registry or claim reviews',()=>{
  const f=setup(); Object.assign(f.signal,{registry:f.registry,evidenceReviews:f.evidenceReviews});
  assert.equal(assessSignal(f.signal,f.now).alert,false);
});
test('one reviewed source cannot corroborate',()=>assert.equal(assess(setup([0])).confidence,'SINGLE_SOURCE'));
for (const [name,index] of [['shared owner',2],['syndicated origin',3],['same document',4]]) {
  test(`${name} collapses distinct domains`,()=>{const r=blocked(setup([0,index]));assert.equal(r.sourceCount,1);});
}
test('shared editorial desk collapses independent owners',()=>{const f=setup();f.registry.sources[1].editorialGroupId=f.registry.sources[0].editorialGroupId;assert.equal(blocked(f).sourceCount,1);});
test('transitive dependence is conservative and independent of input order',()=>{
  const f=setup([0,1,2]); f.registry.sources[2].editorialGroupId=f.registry.sources[1].editorialGroupId;
  assert.equal(blocked(f).sourceCount,1); f.signal.sources.reverse();assert.equal(blocked(f).sourceCount,1);
});
for (const url of ['https://','http://beta.example.org/report','https://user:pass@beta.example.org/report',
 'https://beta.example.org.evil.org/report','https://evil.org/?next=https://beta.example.org/report',
 'https://beta.example.org:8443/report','https://beta.example.org./report','https://%62eta.example.org/report',
 'https://βeta.example.org/report','https://xn--bta-bma.example.org/report','https://localhost/report',
 'https://127.0.0.1/report','https://2130706433/report','https://[::1]/report',' https://beta.example.org/report',
 'https://beta.example.org/has space','https://beta.example.org/\nreport','https://beta.example.org\\@evil.org/report',
 'https://beta.example.org/%ZZ','https://beta.example.org:/report',
 'https:////beta.example.org/report','https:///beta.example.org/report','https://beta.example.org/%0areport']) {
  test(`untrusted or malformed URL rejected: ${JSON.stringify(url)}`,()=>{const f=setup();f.signal.sources[1].url=url;blocked(f);});
}
test('exact host matching: unreviewed subdomain is rejected',()=>{const f=setup();f.signal.sources[1].url='https://news.beta.example.org/report';blocked(f,'SOURCE_NOT_APPROVED');});
test('tracking and fragment variants deduplicate; case and default port normalize',()=>{
  const f=setup([0,0]); f.signal.sources[1].url='https://ALPHA.example.org:443/report?utm_source=copy#section';
  const r=blocked(f,'DUPLICATE_EVIDENCE'); assert.equal(r.sourceCount,1);
});
test('query sorting retains identity parameters',()=>{
 assert.equal(canonicalURL('https://alpha.example.org/a?z=2&a=1#x'),'https://alpha.example.org/a?a=1&z=2');
 assert.notEqual(canonicalURL('https://alpha.example.org/a?id=1'),canonicalURL('https://alpha.example.org/a?id=2'));
});
test('same bytes on different domains do not corroborate',()=>{
  const f=setup();f.signal.sources[1].contentSha256=f.signal.sources[0].contentSha256;f.evidenceReviews[1].contentSha256=f.signal.sources[0].contentSha256;
  blocked(f,'DUPLICATE_EVIDENCE');
});
for (const key of ['contentSha256','url']) test(`changed ${key} invalidates document review`,()=>{
 const f=setup();f.signal.sources[1][key]=key==='url'?'https://beta.example.org/another':'f'.repeat(64);blocked(f,'NO_CLAIM_REVIEW');
});
for (const key of ['sourceId','category','headline','eventAt','support','maxImpact','originId','documentId','reviewer','reviewNote']) {
 test(`claim review binds ${key}`,()=>{const f=setup();f.evidenceReviews[1][key]=key==='maxImpact'?2:'';blocked(f,'UNSUPPORTED_CLAIM');});
}
test('ambiguous claim reviews fail closed',()=>{const f=setup();f.evidenceReviews.push({...f.evidenceReviews[1]});blocked(f,'AMBIGUOUS_REVIEW');});
test('missing digest fails closed',()=>{const f=setup();delete f.signal.sources[1].contentSha256;blocked(f,'MISSING_CONTENT_DIGEST');});
for (const status of ['pending','revoked']) test(`${status} sources cannot count`,()=>{const f=setup();f.registry.sources[1].status=status;blocked(f,'SOURCE_NOT_APPROVED');});
for (const [key,value] of [['reviewedAt','2026-10-18T00:00:00Z'],['expiresAt','2026-10-17T12:00:00Z']]) test(`registry ${key} enforced`,()=>{const f=setup();f.registry.sources[1][key]=value;blocked(f,'SOURCE_NOT_APPROVED');});
for (const key of ['ownerId','editorialGroupId','reviewer','reviewNote','reviewReferences']) test(`incomplete registry ${key} rejected`,()=>{const f=setup();delete f.registry.sources[1][key];assert.throws(()=>assess(f),TypeError);});
test('overlapping host assignments are a configuration error',()=>{const f=setup();f.registry.sources[1].hosts=f.registry.sources[0].hosts;assert.throws(()=>assess(f),TypeError);});
test('duplicate source identities are a configuration error',()=>{const f=setup();f.registry.sources[1].id=f.registry.sources[0].id;assert.throws(()=>assess(f),TypeError);});
for (const [key,value] of [
 ['publishedAt','2026-10-13T10:00:00Z'],['publishedAt','2026-10-17T12:01:00Z'],
 ['retrievedAt','2026-10-17T09:00:00Z'],['verifiedAt','2026-10-17T10:00:00Z'],
 ['verifiedAt','2026-10-18T12:00:00Z'],['expiresAt','2026-10-17T12:00:00Z'],
 ['publishedAt','2026-02-30T10:00:00Z'],['publishedAt',null],
 ['publishedAt','2026-10-17'],['publishedAt','2026-10-17T10:30:00'],
 ['publishedAt','2026-10-17T12:30:00+02:00']]) {
 test(`misleading review timestamp ${key}=${value} blocked`,()=>{const f=setup();f.evidenceReviews[1][key]=value;blocked(f);});
}
test('old publication cannot be refreshed by retrieval or a fresh signal',()=>{const f=setup();f.evidenceReviews[1].publishedAt='2026-10-13T10:00:00Z';blocked(f,'STALE_EVIDENCE');});
for (const value of ['2026-10-13T10:00:00Z','2026-10-17T12:01:00Z']) test(`event age ${value} blocks eligibility`,()=>{const f=setup();f.signal.observedAt=value;f.evidenceReviews.forEach(r=>r.eventAt=value);assert.equal(blocked(f).confidence,'STALE');});
for (const value of [null,0,'2026-02-30T12:00:00Z','2026-10-17','2026-10-17T10:00:00','garbage']) test(`invalid event timestamp ${value} rejected`,()=>{const f=setup();f.signal.observedAt=value;assert.throws(()=>assess(f),TypeError);});
test('freshness boundary includes exactly 72 hours',()=>{
 const f=setup();f.signal.observedAt='2026-10-14T12:00:00Z';f.evidenceReviews.forEach(r=>{r.eventAt=f.signal.observedAt;r.publishedAt=f.signal.observedAt;});
 assert.equal(assess(f).alert,true);f.now=new Date(f.now.getTime()+1);assert.equal(blocked(f).confidence,'STALE');
});
test('invalid evaluation clock rejected',()=>{const f=setup();f.now=new Date('bad');assert.throws(()=>assess(f),TypeError);});
test('below threshold reviewed impact never alerts',()=>{const f=setup();f.signal.indicators=[{impact:2}];assert.equal(blocked(f).level,'ELEVATED');});
test('unsupported impact escalation invalidates claim review',()=>{const f=setup();f.signal.indicators=[{impact:4}];blocked(f,'UNSUPPORTED_CLAIM');});
test('invalid impact rejected',()=>{const f=setup();f.signal.indicators=[{impact:99}];assert.throws(()=>assess(f),TypeError);});
test('exact duplicate signals collapse but conflicting IDs fail closed',()=>{
 const f=setup();assert.equal(evaluateBatch([f.signal,f.signal],f.now,f).length,1);
 assert.throws(()=>evaluateBatch([f.signal,{...f.signal,headline:'Changed'}],f.now,f),/Conflicting duplicate/);
});
test('malformed source entries are reported without crashing the batch',()=>{const f=setup();f.signal.sources=[null,{},42,{url:'https://'}];assert.equal(blocked(f).rejectedEvidence.length,4);});
test('evaluation does not mutate signal, registry or evidence reviews',()=>{const f=setup();const before=structuredClone(f);assess(f);assert.deepEqual(f,before);});
test('duplicate bytes retain dependence links to other evidence',()=>{
 const f=setup([0,1,2]);
 f.signal.sources[1].contentSha256=f.signal.sources[0].contentSha256;
 f.evidenceReviews[1].contentSha256=f.signal.sources[0].contentSha256;
 f.registry.sources[2].ownerId=f.registry.sources[1].ownerId;
 const r=blocked(f,'DUPLICATE_EVIDENCE');assert.equal(r.sourceCount,1);
 f.signal.sources.reverse();assert.equal(blocked(f).sourceCount,1);
});
test('separate aliases of the same registered source cannot corroborate',()=>{
 const f=setup();f.registry.sources[0].hosts.push('beta.example.org');f.registry.sources.splice(1,1);
 f.evidenceReviews[1].sourceId='alpha';assert.equal(blocked(f).sourceCount,1);
});
test('changing the claim ID cannot reuse a review',()=>{const f=setup();f.signal.id='different';blocked(f,'NO_CLAIM_REVIEW');});
test('unsupported second report never corroborates',()=>{const f=setup();f.evidenceReviews[1].support='mentions';assert.equal(blocked(f,'UNSUPPORTED_CLAIM').sourceCount,1);});
