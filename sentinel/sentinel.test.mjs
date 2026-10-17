import test from 'node:test';
import assert from 'node:assert/strict';
import {assessSignal,evaluateBatch} from './sentinel.mjs';
const now=new Date('2026-10-17T12:00:00Z');
const signal={id:'a',category:'cybersecurity',headline:'Verified outage',observedAt:'2026-10-17T10:00:00Z',
 indicators:[{impact:3}],sources:[{url:'https://example.org/a',credible:true,independent:true},{url:'https://example.net/b',credible:true,independent:true}]};
test('corroborated high impact alerts but requires review',()=>{const r=assessSignal(signal,now);assert.equal(r.alert,true);assert.equal(r.reviewRequired,true);assert.equal(r.confidence,'CORROBORATED')});
test('single source cannot alert',()=>assert.equal(assessSignal({...signal,sources:signal.sources.slice(0,1)},now).alert,false));
test('stale evidence cannot alert',()=>assert.equal(assessSignal({...signal,observedAt:'2026-10-01T10:00:00Z'},now).alert,false));
test('duplicate IDs collapse',()=>assert.equal(evaluateBatch([signal,signal],now).length,1));
test('invalid impact rejected',()=>assert.throws(()=>assessSignal({...signal,indicators:[{impact:99}]},now)));
