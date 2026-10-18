import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, writeFileSync, readFileSync, rmSync, symlinkSync, truncateSync, mkdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {prepareEvidence,verifyDocument,runCLI,MAX_DOCUMENT_BYTES} from './prepare-evidence.mjs';
import {assessSignal} from './sentinel.mjs';
const now=new Date('2026-10-17T12:00:00Z');
const url='https://alpha.example.org/report';
const fixture=JSON.parse(readFileSync(new URL('./fixtures/evidence-review.json',import.meta.url),'utf8'));
function withFile(fn) {
 const directory=mkdtempSync(join(tmpdir(),'dawg-evidence-'));
 try { const file=join(directory,'capture.bin');writeFileSync(file,Buffer.from([0,255,13,10]));return fn(file,directory); }
 finally {rmSync(directory,{recursive:true,force:true});}
}
test('hashes exact bytes using a known SHA-256 vector, without approving evidence',()=>{
 const r=prepareEvidence(Buffer.from('abc'),url,now);
 assert.equal(r.source.contentSha256,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
 assert.equal(r.status,'pending');assert.equal(r.reviewDraft.support,'unreviewed');assert.equal(r.reviewDraft.status,'pending');
 assert.equal(r.reviewDraft.reviewer,null);assert.equal(r.reviewDraft.retrievedAt,null);
 assert.equal(r.reviewDraft.publishedAt,null);assert.equal(r.reviewDraft.verifiedAt,null);
 assert.equal(r.preparedAt,now.toISOString());
});
test('typed array slice hashes only the supplied bytes',()=>{
 const bytes=new Uint8Array([0,97,98,99,255]);
 assert.equal(prepareEvidence(bytes.subarray(1,4),url,now).source.contentSha256,prepareEvidence(Buffer.from('abc'),url,now).source.contentSha256);
});
test('line endings and binary byte changes invalidate a digest',()=>{
 const bytes=Buffer.from([0,255,13,10]);const r=prepareEvidence(bytes,url,now);
 assert.equal(verifyDocument(bytes,r.source.contentSha256),true);
 assert.equal(verifyDocument(Buffer.from([0,255,10]),r.source.contentSha256),false);
});
test('empty preserved documents are hashable but remain unreviewed',()=>{
 const r=prepareEvidence(Buffer.alloc(0),url,now);assert.equal(r.capture.byteLength,0);assert.equal(r.status,'pending');
});
test('captures submitted URL separately from canonical review identity',()=>{
 const original=url+'?utm_source=copy#excerpt';const r=prepareEvidence(Buffer.from('abc'),original,now);
 assert.equal(r.capture.submittedURL,original);assert.equal(r.source.url,url);
});
test('pending draft cannot corroborate even with an approved source registry',()=>{
 const r=prepareEvidence(Buffer.from('abc'),url,now);
 const draft={...r.reviewDraft,claimId:fixture.signal.id};
 const signal={...fixture.signal,sources:[r.source]};
 const result=assessSignal(signal,now,{registry:fixture.registry,evidenceReviews:[draft]});
 assert.equal(result.alert,false);assert.equal(result.confidence,'UNVERIFIED');
 assert.equal(result.rejectedEvidence[0].reason,'REVIEW_NOT_APPROVED');
});
test('requires byte input, valid HTTPS URL, bounded size and valid clock',()=>{
 assert.throws(()=>prepareEvidence('abc',url,now),TypeError);
 assert.throws(()=>prepareEvidence(Buffer.alloc(MAX_DOCUMENT_BYTES+1),url,now),TypeError);
 assert.throws(()=>prepareEvidence(Buffer.from('abc'),'https://',now),TypeError);
 assert.throws(()=>prepareEvidence(Buffer.from('abc'),url,new Date('bad')),TypeError);
 assert.throws(()=>verifyDocument(Buffer.from('abc'),'invalid'),TypeError);
});
test('CLI reads preserved binary bytes and verifies expected digest',()=>withFile(file=>{
 const digest=prepareEvidence(readFileSync(file),url,now).source.contentSha256;
 const r=runCLI(['--file',file,'--url',url,'--expected-sha256',digest],now);
 assert.equal(r.source.contentSha256,digest);assert.equal(r.capture.byteLength,4);
 assert.equal(JSON.stringify(r).includes(file),false);
}));
test('mismatched digest fails without producing a review',()=>withFile(file=>{
 assert.throws(()=>runCLI(['--file',file,'--url',url,'--expected-sha256','a'.repeat(64)],now),/mismatch/);
}));
test('ambiguous CLI arguments and URL failures occur before file access',()=>{
 for(const args of [[],['--file','missing'],['--file','missing','--url',url,'--url',url],['--file','missing','--url',url,'--approve','true']]) assert.throws(()=>runCLI(args,now),TypeError);
 assert.throws(()=>runCLI(['--file','missing','--url','http://example.org'],now),TypeError);
});
test('rejects directories, final-component symlinks and oversized files',()=>withFile((file,directory)=>{
 const args=path=>['--file',path,'--url',url];
 const dir=join(directory,'dir');mkdirSync(dir);assert.throws(()=>runCLI(args(dir),now),/regular file/);
 const link=join(directory,'link');symlinkSync(file,link);assert.throws(()=>runCLI(args(link),now));
 truncateSync(file,MAX_DOCUMENT_BYTES+1);assert.throws(()=>runCLI(args(file),now),/16 MiB/);
}));
test('CLI writes JSON to stdout only; no approval, local path or document bytes leaked',()=>withFile((file,directory)=>{
 const r=spawnSync(process.execPath,[new URL('./prepare-evidence.mjs',import.meta.url).pathname,'--file',file,'--url',url],{encoding:'utf8'});
 assert.equal(r.status,0,r.stderr);assert.equal(r.stderr,'');
 assert.equal(JSON.parse(r.stdout).status,'pending');assert.equal(r.stdout.includes(directory),false);
 assert.deepEqual([...readFileSync(file)],[0,255,13,10]);
}));
test('CLI digest failure has nonzero status and empty stdout',()=>withFile(file=>{
 const r=spawnSync(process.execPath,[new URL('./prepare-evidence.mjs',import.meta.url).pathname,'--file',file,'--url',url,'--expected-sha256','0'.repeat(64)],{encoding:'utf8'});
 assert.equal(r.status,1);assert.equal(r.stdout,'');assert.match(r.stderr,/SHA-256 mismatch/);
 assert.equal(r.stderr.includes(file),false);
}));

test('expected digest cannot contain a trailing newline',()=>{
 assert.throws(()=>verifyDocument(Buffer.from('abc'),'a'.repeat(64)+'\n'),TypeError);
});
