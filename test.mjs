import assert from 'node:assert/strict';import{auditAllocation,reconcile,dawScore}from'./watchdawg.js';
assert.equal(auditAllocation({gross:500,rate:.1,vault:50,spend:450}).status,'VERIFIED');
assert.equal(auditAllocation({gross:500,rate:.1,vault:20,spend:480}).status,'REVIEW');
const s=reconcile({spendable:0,vaulted:0},[{type:'deposit',gross:1000,rate:.2,vault:200,spend:800},{type:'purchase',amount:125}]);
assert.deepEqual({spendable:s.spendable,vaulted:s.vaulted,status:s.status},{spendable:675,vaulted:200,status:'VERIFIED'});assert.equal(dawScore(s),100);console.log('Watch-Dawg tests passed');