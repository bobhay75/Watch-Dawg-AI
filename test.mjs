import assert from 'node:assert/strict';
import fs from 'node:fs';
import{auditAllocation,reconcile,dawScore,runWatchDawg,explainAudit,sampleScenarios,createCorrectionPlan,applyApprovedCorrectionPlan}from'./watchdawg.js';

const clone=value=>JSON.parse(JSON.stringify(value));
const canonicalize=value=>Array.isArray(value)
  ?value.map(canonicalize)
  :value&&typeof value==='object'
    ?Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonicalize(value[key])]))
    :value;
const digestValue=async value=>{
  const bytes=new TextEncoder().encode(JSON.stringify(canonicalize(value)));
  const hash=await globalThis.crypto.subtle.digest('SHA-256',bytes);
  return[...new Uint8Array(hash)].map(byte=>byte.toString(16).padStart(2,'0')).join('');
};

assert.equal(auditAllocation({gross:500,rate:.1,vault:50,spend:450}).status,'VERIFIED');
assert.equal(auditAllocation({gross:500,rate:.1,vault:20,spend:480}).status,'REVIEW');
assert.equal(auditAllocation({gross:500,rate:1.5,vault:750,spend:-250}).status,'REVIEW');
assert.equal(auditAllocation({gross:'bad',rate:.1,vault:50}).status,'REVIEW');
assert.equal(auditAllocation({gross:null,rate:.1,vault:0}).status,'REVIEW');
assert.equal(auditAllocation({gross:'',rate:.1,vault:0}).status,'REVIEW');
assert.equal(auditAllocation({gross:false,rate:.1,vault:0}).status,'REVIEW');

const lower=reconcile({spendable:0,vaulted:0},[
  {type:'deposit',gross:1000,rate:.2,vault:200,spend:800},
  {type:'purchase',amount:125,rate:0,vault:0}
]);
assert.deepEqual({spendable:lower.spendable,vaulted:lower.vaulted,status:lower.status},{spendable:675,vaulted:200,status:'VERIFIED'});

const growContract=reconcile({spendable:0,vaulted:0},[
  {type:'Deposit',gross:500,rate:.1,vault:50,spend:450},
  {type:'Purchase',gross:40,amount:40,rate:.1,vault:4,spend:44}
]);
assert.deepEqual({spendable:growContract.spendable,vaulted:growContract.vaulted,status:growContract.status},{spendable:406,vaulted:54,status:'VERIFIED'});
assert.equal(dawScore(growContract),100);

const missingSpend=reconcile({spendable:0,vaulted:0},[{type:'Deposit',gross:100,rate:.1,vault:10}]);
assert.deepEqual({spendable:missingSpend.spendable,vaulted:missingSpend.vaulted},{spendable:90,vaulted:10});
assert.equal(missingSpend.status,'VERIFIED');

const badPurchase=reconcile({spendable:100,vaulted:0},[{type:'Purchase',gross:40,rate:.1,vault:-4}]);
assert.equal(badPurchase.status,'REVIEW');
assert.deepEqual({spendable:badPurchase.spendable,vaulted:badPurchase.vaulted},{spendable:100,vaulted:0});

const unknown=reconcile({spendable:10,vaulted:10},[{type:'mystery',amount:1}]);
assert.equal(unknown.status,'REVIEW');
assert.ok(dawScore(unknown)<100);

const ledgerRun=runWatchDawg(sampleScenarios.ledger);
assert.equal(ledgerRun.mode,'ledger');
assert.equal(ledgerRun.status,'VERIFIED');
assert.equal(ledgerRun.summary.entries.length,4);
assert.equal(ledgerRun.score,100);
assert.match(ledgerRun.report,/No anomalies detected/);

const anomalyRun=runWatchDawg(sampleScenarios.anomaly);
assert.equal(anomalyRun.mode,'ledger');
assert.equal(anomalyRun.status,'REVIEW');
assert.ok(anomalyRun.summary.reviews.length>=2);
assert.ok(anomalyRun.score<100);
assert.match(explainAudit(anomalyRun),/Review queue/);

const invalidJsonShape=runWatchDawg(null);
assert.equal(invalidJsonShape.mode,'transaction');
assert.equal(invalidJsonShape.status,'REVIEW');
const publicDemo=fs.readFileSync(new URL('./public-demo.html',import.meta.url),'utf8');
for(const id of ['demo','jump','score','headline','audit','s1','s2','s3','s4','approve','live','target','auth','hunt','liveout','proof','sentinel-field']){
  assert.match(publicDemo,new RegExp('id="'+id+'"'),'public demo must retain #'+id);
}
assert.match(publicDemo,/prefers-reduced-motion/,'public demo must respect reduced motion');
assert.match(publicDemo,/aria-live="polite"/,'dynamic demo output must be announced');
assert.match(publicDemo,/id="score"[^>]*aria-labelledby="score-label"[^>]*>—<\/output>/,'the DAWG score must start unknown and have an accessible name');
assert.match(publicDemo,/id="headline">SIMULATION READY</,'the demo must not claim an audit result before it runs');
assert.doesNotMatch(publicDemo,/>System standing watch</,'the public demo must not imply active monitoring before a run');
assert.doesNotMatch(publicDemo,/Run the 60-second hunt/,'the demo call to action must not promise a false duration');
assert.match(publicDemo,/id="sequence-title">Watch-Dawg operating sequence<\/h2>/,'the operating sequence must preserve the heading hierarchy');
assert.match(publicDemo,/byId\("target"\)\.focus\(\{ preventScroll: true \}\)/,'the authorized-site shortcut must move keyboard focus to the target field');
assert.match(publicDemo,/from\s+["']\.\/watchdawg\.js["']/,'public demo must use the tested audit core');
assert.match(publicDemo,/I own this target or have explicit authorization/,'live intake must keep its authorization gate');
assert.match(publicDemo,/No intrusive scan was launched from your browser/,'live intake must state its defensive boundary');

const correctionSource={opening:{spendable:300,vaulted:40},transactions:[
  {id:'GV-3001',type:'Deposit',gross:500,rate:.1,vault:20,spend:480},
  {id:'GV-3002',type:'mystery',amount:25}
]};
const correctionPlan=await createCorrectionPlan(correctionSource,{createdAt:'2026-09-17T00:00:00.000Z'});
assert.equal(correctionPlan.requiresHumanApproval,true);
assert.equal(correctionPlan.externalWritePerformed,false);
assert.deepEqual(correctionPlan.proposals[0].changes,{vault:50,spend:450});
assert.equal(correctionPlan.unhandledReviews.length,1);
const trustedApproval={
  decision:'APPROVE',
  approver:'Robert',
  planDigest:correctionPlan.planDigest,
  approvedAt:'2026-09-17T00:01:00.000Z',
  expiresAt:'2026-09-17T01:00:00.000Z',
  keyId:'test-root',
  signature:'trusted-test-signature'
};
const approvalOptions={
  now:'2026-09-17T00:30:00.000Z',
  verifyApproval:async({approval,plan})=>approval.keyId==='test-root'
    &&approval.signature==='trusted-test-signature'
    &&approval.planDigest===plan.planDigest
};
await assert.rejects(
  applyApprovedCorrectionPlan(correctionSource,correctionPlan,trustedApproval),
  /trusted approval verifier/
);
await assert.rejects(
  applyApprovedCorrectionPlan(correctionSource,correctionPlan,{...trustedApproval,signature:'forged'},approvalOptions),
  /Trusted approval verification failed/
);
await assert.rejects(
  applyApprovedCorrectionPlan(correctionSource,correctionPlan,{...trustedApproval,planDigest:'wrong'},approvalOptions),
  /Exact human approval/
);
const approved=await applyApprovedCorrectionPlan(correctionSource,correctionPlan,trustedApproval,approvalOptions);
assert.equal(approved.corrected.transactions[0].vault,50);
assert.equal(approved.corrected.transactions[0].spend,450);
assert.equal(correctionSource.transactions[0].vault,20);
assert.equal(approved.receipt.externalWritePerformed,false);
await assert.rejects(
  applyApprovedCorrectionPlan(
    {...correctionSource,opening:{spendable:301,vaulted:40}},
    correctionPlan,
    trustedApproval,
    approvalOptions
  ),
  /Ledger changed/
);

for(const field of ['gross','type']){
  const arbitraryFieldPlan=clone(correctionPlan);
  arbitraryFieldPlan.proposals[0].changes[field]=field==='gross'?500:'vault-withdrawal';
  arbitraryFieldPlan.proposals[0].before[field]=correctionSource.transactions[0][field];
  await assert.rejects(
    applyApprovedCorrectionPlan(correctionSource,arbitraryFieldPlan,trustedApproval,approvalOptions),
    /only matching vault and spend fields/
  );
}

const prototypePlan=clone(correctionPlan);
prototypePlan.proposals[0].changes=JSON.parse(
  '{"vault":50,"spend":450,"__proto__":{"watchDawgPolluted":true}}'
);
await assert.rejects(
  applyApprovedCorrectionPlan(correctionSource,prototypePlan,trustedApproval,approvalOptions),
  /forbidden object key/
);
assert.equal({}.watchDawgPolluted,undefined);

const duplicatePlan=clone(correctionPlan);
duplicatePlan.proposals.push(clone(duplicatePlan.proposals[0]));
await assert.rejects(
  applyApprovedCorrectionPlan(correctionSource,duplicatePlan,trustedApproval,approvalOptions),
  /duplicate proposal IDs/
);

const unknownPlanField=clone(correctionPlan);
unknownPlanField.executeExternalWrite=true;
await assert.rejects(
  applyApprovedCorrectionPlan(correctionSource,unknownPlanField,trustedApproval,approvalOptions),
  /unknown or forbidden field/
);

const malformedPlan=clone(correctionPlan);
malformedPlan.proposals[0].transactionIndex=.5;
await assert.rejects(
  applyApprovedCorrectionPlan(correctionSource,malformedPlan,trustedApproval,approvalOptions),
  /invalid transaction index/
);

const tamperedPlan=clone(correctionPlan);
tamperedPlan.proposals[0].changes.vault=49;
const tamperedUnsigned={...tamperedPlan};
delete tamperedUnsigned.planDigest;
tamperedPlan.planDigest=await digestValue(tamperedUnsigned);
await assert.rejects(
  applyApprovedCorrectionPlan(
    correctionSource,
    tamperedPlan,
    {...trustedApproval,planDigest:tamperedPlan.planDigest},
    {now:approvalOptions.now,verifyApproval:async()=>true}
  ),
  /does not match the deterministic ledger corrections/
);

await assert.rejects(
  applyApprovedCorrectionPlan(
    correctionSource,
    correctionPlan,
    {...trustedApproval,expiresAt:'2026-09-17T00:10:00.000Z'},
    {...approvalOptions,now:'2026-09-17T00:10:00.000Z'}
  ),
  /Approval has expired/
);
console.log('Watch-Dawg tests passed');
