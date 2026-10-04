import assert from 'node:assert/strict';
import fs from 'node:fs';
import{auditAllocation,reconcile,dawScore,runWatchDawg,explainAudit,sampleScenarios,createCorrectionPlan,applyApprovedCorrectionPlan}from'./watchdawg.js';
import{auditFieldSecuritySite,buildFieldSecurityAiSummary,createFieldSecurityReceipt,sampleFieldSecurityPilot}from'./field-security.js';

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
await assert.rejects(
  applyApprovedCorrectionPlan(correctionSource,correctionPlan,{decision:'APPROVE',approver:'Robert',planDigest:'wrong'}),
  /Exact human approval/
);
const approved=await applyApprovedCorrectionPlan(correctionSource,correctionPlan,{
  decision:'APPROVE',approver:'Robert',planDigest:correctionPlan.planDigest,approvedAt:'2026-09-17T00:01:00.000Z'
});
assert.equal(approved.corrected.transactions[0].vault,50);
assert.equal(approved.corrected.transactions[0].spend,450);
assert.equal(correctionSource.transactions[0].vault,20);
assert.equal(approved.receipt.externalWritePerformed,false);
await assert.rejects(
  applyApprovedCorrectionPlan({...correctionSource,opening:{spendable:301,vaulted:40}},correctionPlan,{
    decision:'APPROVE',approver:'Robert',planDigest:correctionPlan.planDigest
  }),
  /Ledger changed/
);

const fieldAudit=auditFieldSecuritySite(sampleFieldSecurityPilot);
assert.equal(fieldAudit.mode,'field-security');
assert.equal(fieldAudit.status,'REVIEW');
assert.equal(fieldAudit.summary.zones,3);
assert.equal(fieldAudit.summary.openIncidents,2);
assert.equal(fieldAudit.summary.evidenceItems,3);
assert.ok(fieldAudit.score<100);
assert.match(fieldAudit.report,/Human review queue/);
assert.match(buildFieldSecurityAiSummary(fieldAudit),/evidence-only|provided zone/);
const fieldReceipt=await createFieldSecurityReceipt(sampleFieldSecurityPilot,fieldAudit,{createdAt:'2026-09-28T12:00:00.000Z'});
assert.equal(fieldReceipt.version,1);
assert.equal(fieldReceipt.proofState,fieldAudit.proofState);
assert.match(fieldReceipt.sourceDigest,/^[a-f0-9]{64}$/);
assert.match(fieldReceipt.auditDigest,/^[a-f0-9]{64}$/);
assert.match(fieldReceipt.receiptDigest,/^[a-f0-9]{64}$/);
assert.equal(fieldReceipt.findings,fieldAudit.findings.length);

const cleanFieldAudit=auditFieldSecuritySite({
  siteId:'WD-CLEAN-001',siteName:'Clean closeout',authorizedUse:true,capturedAt:'2026-09-28T12:05:00.000Z',
  ownerContact:{primary:'Owner'},
  zones:[{id:'ZONE-1',name:'Drive',boundaryType:'open',status:'normal'}],
  incidents:[{id:'INC-OK',zoneId:'ZONE-1',title:'Delivery matched',severity:'low',status:'resolved',reviewStatus:'human-reviewed',evidence:[{id:'EV-OK',type:'note',description:'Matched ticket'}]}]
});
assert.equal(cleanFieldAudit.status,'VERIFIED');
assert.equal(cleanFieldAudit.proofState,'REVIEW_READY');
assert.equal(cleanFieldAudit.findings.length,0);

const fieldDemo=fs.readFileSync(new URL('./field-security-demo.html',import.meta.url),'utf8');
for(const phrase of ['Open boundaries. Secured peace.','Run Field Audit','Create Evidence Receipt','No live scan']){
  assert.match(fieldDemo,new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
}
assert.match(fieldDemo,/src="\.\/field-security-app\.js"/,'field security demo must load its app module');
const fieldApp=fs.readFileSync(new URL('./field-security-app.js',import.meta.url),'utf8');
assert.match(fieldApp,/from\s+["']\.\/field-security\.js["']/,'field security app must use the deterministic field-security core');

console.log('Watch-Dawg tests passed');
