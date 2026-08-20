import assert from 'node:assert/strict';
import{auditAllocation,reconcile,dawScore,runWatchDawg,explainAudit,sampleScenarios}from'./watchdawg.js';

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
console.log('Watch-Dawg tests passed');
