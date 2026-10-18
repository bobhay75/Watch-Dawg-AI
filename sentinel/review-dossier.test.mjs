import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,writeFileSync,copyFileSync,rmSync,symlinkSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {reviewDossier,runDossierCLI} from './review-dossier.mjs';
const fixtureURL=new URL('./fixtures/offline-demo.json',import.meta.url);
const now=new Date('2026-10-17T12:00:00Z');
const make=()=>JSON.parse(readFileSync(fixtureURL,'utf8'));
const load=name=>readFileSync(new URL(`./fixtures/${name}`,import.meta.url));
function withDossier(fn) {
 const directory=mkdtempSync(join(tmpdir(),'dawg-dossier-'));
 try {
  const dossier=make(),file=join(directory,'dossier.json');
  for(const d of dossier.documents)copyFileSync(new URL(`./fixtures/${d.path}`,import.meta.url),join(directory,d.path));
  writeFileSync(file,JSON.stringify(dossier));return fn({directory,dossier,file,save:()=>writeFileSync(file,JSON.stringify(dossier))});
 } finally {rmSync(directory,{recursive:true,force:true});}
}
test('synthetic end-to-end report verifies original bytes and remains review-only',()=>{
 const dossier=make(),before=structuredClone(dossier);const r=reviewDossier(dossier,load,now);
 assert.equal(r.synthetic,true);assert.equal(r.mode,'review-only');assert.equal(r.reviewRequired,true);
 assert.equal(r.documentChecks.length,2);assert.ok(r.documentChecks.every(c=>c.hashVerified));
 assert.equal(r.results[0].confidence,'CORROBORATED');assert.equal(r.results[0].reviewOnly,true);assert.equal(r.results[0].sourceCount,2);
 assert.deepEqual(dossier,before);assert.equal(JSON.stringify(r).includes('Stipulated original report'),false);
});
test('modified preserved bytes abort the report rather than downgrade silently',()=>{
 assert.throws(()=>reviewDossier(make(),()=>Buffer.from('tampered'),now),/SHA-256 mismatch/);
});
test('a claimed hash cannot override actual document bytes',()=>{
 const d=make();d.documents[1].contentSha256='a'.repeat(64);d.signals[0].sources[1].contentSha256='a'.repeat(64);d.evidenceReviews[1].contentSha256='a'.repeat(64);
 assert.throws(()=>reviewDossier(d,load,now),/SHA-256 mismatch/);
});
test('missing capture mapping aborts before reading a document',()=>{
 const d=make();d.documents.pop();let reads=0;
 assert.throws(()=>reviewDossier(d,()=>{reads++;return Buffer.alloc(0);},now),/Missing preserved/);assert.equal(reads,0);
});
for(const path of ['../secret','/etc/passwd','nested/file.txt','nested\\file.txt','.','..','capture.txt\n']) test(`rejects capture path ${JSON.stringify(path)} before file access`,()=>{
 const d=make();d.documents[0].path=path;assert.throws(()=>reviewDossier(d,()=>{throw new Error('must not read');},now),/manifest entry/);
});
test('duplicate manifest identities are ambiguous',()=>{
 const d=make();d.documents.push({...d.documents[0]});assert.throws(()=>reviewDossier(d,load,now),/Ambiguous/);
});
test('valid documents cannot promote an unreviewed claim',()=>{
 const d=make();d.evidenceReviews[1].support='unreviewed';const r=reviewDossier(d,load,now);
 assert.equal(r.results[0].alert,false);assert.equal(r.results[0].confidence,'SINGLE_SOURCE');
});
test('valid documents cannot promote unregistered sources',()=>{
 const d=make();d.registry.sources=[];const r=reviewDossier(d,load,now);assert.equal(r.results[0].confidence,'UNVERIFIED');
});
test('expired evidence remains stale despite unchanged document bytes',()=>{
 const r=reviewDossier(make(),load,new Date('2026-10-21T12:00:00Z'));assert.equal(r.results[0].confidence,'STALE');assert.equal(r.results[0].alert,false);
});
test('non-byte capture loaders fail closed',()=>assert.throws(()=>reviewDossier(make(),()=> 'text',now),/return bytes/));
test('oversized and malformed dossiers fail before capture I/O',()=>{
 for(const d of [null,{...make(),mode:'live'},{...make(),documents:Array(257).fill(make().documents[0])},{...make(),signals:Array(257).fill(make().signals[0])}])assert.throws(()=>reviewDossier(d,()=>{throw new Error('must not read');},now),TypeError);
});
test('cumulative capture budget is enforced',()=>{
 const d=make();d.documents=[];d.signals=[];
 for(let i=0;i<5;i++)d.documents.push({path:`capture-${i}.txt`,url:`https://alpha.example.org/${i}`,contentSha256:'0'.repeat(64)});
 // A zero-copy repeated view tests the total bound without disk or huge files.
 // Each digest still needs to match, so use the computed digest of the view.
 const bytes=Buffer.alloc(16*1024*1024);
 return import('node:crypto').then(({createHash})=>{
  const hash=createHash('sha256').update(bytes).digest('hex');d.documents.forEach(x=>x.contentSha256=hash);
  assert.throws(()=>reviewDossier(d,()=>bytes,now),/64 MiB/);
 });
});
test('CLI explicit replay is labeled and emits JSON only',()=>withDossier(({file})=>{
 const r=runDossierCLI(['--dossier',file,'--at',now.toISOString()]);assert.equal(r.clockMode,'explicit-historical-replay');assert.equal(r.evaluatedAt,now.toISOString());
}));
test('CLI default clock is labeled separately from replay',()=>withDossier(({file})=>{
 assert.equal(runDossierCLI(['--dossier',file]).clockMode,'current-clock');
}));
test('CLI rejects malformed, duplicate and unsupported arguments',()=>{
 for(const args of [[],['--dossier','missing','--at','2026-02-30T12:00:00Z'],['--dossier','missing','--dossier','other'],['--dossier','missing','--send','yes']])assert.throws(()=>runDossierCLI(args),TypeError);
});
test('CLI capture symlinks fail closed',()=>withDossier(({directory,dossier,file})=>{
 const path=join(directory,dossier.documents[0].path);rmSync(path);symlinkSync(join(directory,dossier.documents[1].path),path);
 assert.throws(()=>runDossierCLI(['--dossier',file,'--at',now.toISOString()]));
}));
test('CLI malformed JSON returns no report, raw evidence or local paths',()=>withDossier(({file})=>{
 writeFileSync(file,'{"private_secret": malformed-private-value}');
 const r=spawnSync(process.execPath,[new URL('./review-dossier.mjs',import.meta.url).pathname,'--dossier',file],{encoding:'utf8'});
 assert.equal(r.status,1);assert.equal(r.stdout,'');assert.match(r.stderr,/Invalid dossier JSON/);
 assert.equal(r.stderr.includes('private_secret'),false);assert.equal(r.stderr.includes(file),false);
}));
test('CLI tampered capture has nonzero exit and no partial report',()=>withDossier(({directory,dossier,file})=>{
 writeFileSync(join(directory,dossier.documents[1].path),'tampered');
 const r=spawnSync(process.execPath,[new URL('./review-dossier.mjs',import.meta.url).pathname,'--dossier',file,'--at',now.toISOString()],{encoding:'utf8'});
 assert.equal(r.status,1);assert.equal(r.stdout,'');assert.match(r.stderr,/SHA-256 mismatch/);
}));
