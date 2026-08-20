import assert from 'node:assert/strict';
import{auditAllocation,reconcile,dawScore}from'./watchdawg.js';

assert.equal(auditAllocation({gross:500,rate:.1,vault:50,spend:450}).status,'VERIFIED');
assert.equal(auditAllocation({gross:500,rate:.1,vault:20,spend:480}).status,'REVIEW');
assert.equal(auditAllocation({gross:500,rate:1.5,vault:750,spend:-250}).status,'REVIEW');
assert.equal(auditAllocation({gross:'bad',rate:.1,vault:50}).status,'REVIEW');

const lower=reconcile({spendable:0,vaulted:0},[
  {type:'deposit',gross:1000,rate:.2,vault:200,spend:800},
  {type:'purchase',amount:125,rate:0,vault:0}
]);
assert.deepEqual({spendable:lower.spendable,vaulted:lower.vaulted,status:lower.status},{spendable:675,vaulted:200,status:'VERIFIED'});

const growContract=reconcile({spendable:0,vaulted:0},[
  {type:'Deposit',gross:500,rate:.1,vault:50,spend:450},
  {type:'Purchase',gross:40,amount:40,rate:.1,vault:4,spend:0}
]);
assert.deepEqual({spendable:growContract.spendable,vaulted:growContract.vaulted,status:growContract.status},{spendable:406,vaulted:54,status:'VERIFIED'});
assert.equal(dawScore(growContract),100);

const unknown=reconcile({spendable:10,vaulted:10},[{type:'mystery',amount:1}]);
assert.equal(unknown.status,'REVIEW');
assert.ok(dawScore(unknown)<100);
console.log('Watch-Dawg tests passed');