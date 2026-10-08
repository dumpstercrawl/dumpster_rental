import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import worker from '../worker/index.js';
// Real SQLite SQL/transactions, with D1's binding/result shape; in-memory R2 adapter.
class Database {
 constructor(path){this.path=path;this.fail=false;this.exec([{sql:readFileSync('migrations/0001_secure_rentals.sql','utf8'),schema:true}]);}
 exec(statements){
  if(this.fail && statements.some(s=>s.sql.startsWith('INSERT INTO rentals')))throw new Error('injected DB failure');
  const result=spawnSync('python',['-c',`import sqlite3,json,sys
con=sqlite3.connect(sys.argv[1]);con.row_factory=sqlite3.Row
out=[]
try:
 for s in json.load(sys.stdin):
  if s.get('schema'): con.executescript(s['sql']);out.append({});continue
  cur=con.execute(s['sql'],s.get('args',[]));rows=[dict(r) for r in cur.fetchall()] if cur.description else []
  out.append({'results':rows,'meta':{'changes':max(cur.rowcount,0)}})
 con.commit();print(json.dumps(out))
except: con.rollback();raise
finally: con.close()`,this.path],{input:JSON.stringify(statements),encoding:'utf8'});
  if(result.status)throw new Error(result.stderr);return JSON.parse(result.stdout);
 }
 prepare(sql){const db=this;return {sql,args:[],bind(...args){this.args=args;return this;},async run(){return db.exec([this])[0];},async all(){return db.exec([this])[0];},async first(){return db.exec([this])[0].results[0]||null;}};}
 async batch(statements){return this.exec(statements);}
}
function setup(t){const dir=mkdtempSync(join(tmpdir(),'v4-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));const objects=new Map();return {DB:new Database(join(dir,'test.sqlite')),STAFF_PASSWORD:'test-password-long-and-random',BUCKET:{async put(k,v){objects.set(k,new Uint8Array(v));},async get(k){return objects.has(k)?{body:objects.get(k)}:null;},async delete(k){objects.delete(k);}},objects};}
async function call(env,path,options={}){return worker.fetch(new Request('https://v4.test'+path,options),env);}
async function login(env){const response=await call(env,'/api/login',{method:'POST',headers:{origin:'https://v4.test','content-type':'application/json'},body:JSON.stringify({password:env.STAFF_PASSWORD})});assert.equal(response.status,200);return response.headers.get('set-cookie').split(';')[0];}
const payload={customer:'Test Customer',phone:'2625550100',address:'Test street',signatureName:'Test Customer',liabilityAccepted:true,packageId:'20-1',delivery:'2026-10-15'};
function upload(env,cookie,{bytes=new Uint8Array([137,80,78,71,13,10,26,10,1,2,3]),type='image/png',rental=payload}={}){const form=new FormData();form.append('rental',JSON.stringify(rental));form.append('photoId',new Blob([bytes],{type}),'private-test.png');return call(env,'/api/rentals',{method:'POST',headers:{origin:'https://v4.test',cookie},body:form});}
test('upload, persistent association, byte retrieval, immutable acceptance and audit',async t=>{
 const env=setup(t),cookie=await login(env),response=await upload(env,cookie);assert.equal(response.status,201);const {rental}=await response.json();assert.equal(rental.photoIdReceived,true);assert.equal(rental.signatureName,payload.signatureName);assert.match(rental.agreementSha256,/^[a-f0-9]{64}$/);assert.equal(env.objects.size,1);
 const document=await call(env,`/api/rentals/${rental.id}/photo-id`,{headers:{cookie}});assert.equal(document.status,200);assert.deepEqual(new Uint8Array(await document.arrayBuffer()),[...env.objects.values()][0]);assert.equal(document.headers.get('cache-control'),'private, no-store');assert.match(document.headers.get('content-disposition'),/^attachment/);
 const evidence=await call(env,`/api/rentals/${rental.id}/agreement`,{headers:{cookie}});assert.deepEqual(await evidence.json(),rental);
 const changed=await call(env,`/api/rentals/${rental.id}`,{method:'PATCH',headers:{origin:'https://v4.test',cookie,'content-type':'application/json'},body:JSON.stringify({status:'completed',signatureName:'Tampered'})});assert.equal(changed.status,200);
 const list=await call(env,'/api/rentals',{headers:{cookie}});const saved=(await list.json()).rentals[0];assert.equal(saved.signatureName,payload.signatureName);assert.equal(saved.status,'completed');assert.equal(saved.agreementHtml,rental.agreementHtml);
 assert.equal((await env.DB.prepare("SELECT * FROM audit WHERE action = 'photo-id-read'").all()).results.length,1);
});
test('anonymous, forged and expired sessions cannot retrieve records/documents or submit',async t=>{
 const env=setup(t),cookie=await login(env),{rental}=await (await upload(env,cookie)).json();
 for(const path of ['/api/rentals',`/api/rentals/${rental.id}/photo-id`,`/api/rentals/${rental.id}/agreement`]){
  assert.equal((await call(env,path)).status,401);assert.equal((await call(env,path,{headers:{cookie:'v4_session='+'f'.repeat(64)}})).status,401);
 }
 await env.DB.prepare('UPDATE sessions SET expires_at = 0').run();assert.equal((await call(env,`/api/rentals/${rental.id}/photo-id`,{headers:{cookie}})).status,401);assert.equal((await upload(env,cookie)).status,401);
});
test('invalid type, spoofed contents, empty/oversize ID, missing agreement and cross origin rejected',async t=>{
 const env=setup(t),cookie=await login(env);
 for(const opts of [{bytes:new Uint8Array([1,2,3])},{type:'text/html'},{bytes:new Uint8Array()},{rental:{...payload,liabilityAccepted:false}},{rental:{...payload,signatureName:''}},{rental:{...payload,delivery:'2026-02-31'}}])assert.equal((await upload(env,cookie,opts)).status,400);
 assert.equal((await upload(env,cookie,{bytes:new Uint8Array(10*1024*1024+1)})).status,413);
 assert.equal((await call(env,'/api/logout',{method:'POST',headers:{origin:'https://attacker.test',cookie}})).status,403);assert.equal(env.objects.size,0);
});
test('failed upload/database does not create received flag or leave objects',async t=>{
 const env=setup(t),cookie=await login(env);env.DB.fail=true;assert.equal((await upload(env,cookie)).status,503);assert.equal(env.objects.size,0);env.DB.fail=false;
 env.BUCKET.put=async()=>{throw new Error('storage unavailable');};assert.equal((await upload(env,cookie)).status,503);assert.equal((await env.DB.prepare('SELECT * FROM rentals').all()).results.length,0);
});
test('correct rental ID association and unknown rental has no document access',async t=>{
 const env=setup(t),cookie=await login(env);const a=(await (await upload(env,cookie)).json()).rental;const bytes=new Uint8Array([137,80,78,71,13,10,26,10,9]);const b=(await (await upload(env,cookie,{bytes})).json()).rental;assert.notEqual(a.id,b.id);assert.notEqual(a.dumpster,b.dumpster);
 const response=await call(env,`/api/rentals/${b.id}/photo-id`,{headers:{cookie}});assert.deepEqual(new Uint8Array(await response.arrayBuffer()),bytes);assert.equal((await call(env,'/api/rentals/00000000-0000-0000-0000-000000000000/photo-id',{headers:{cookie}})).status,404);
});
test('logout revokes token and login rate limit works',async t=>{
 const env=setup(t),cookie=await login(env);assert.equal((await call(env,'/api/logout',{method:'POST',headers:{origin:'https://v4.test',cookie}})).status,200);assert.equal((await call(env,'/api/rentals',{headers:{cookie}})).status,401);
 for(let i=0;i<4;i++)assert.equal((await call(env,'/api/login',{method:'POST',headers:{origin:'https://v4.test'},body:JSON.stringify({password:'bad'})})).status,401);
 assert.equal((await call(env,'/api/login',{method:'POST',headers:{origin:'https://v4.test'},body:JSON.stringify({password:'bad'})})).status,429);
});
test('unconfigured service fails closed and browser does not persist identity records',async t=>{
 assert.equal((await call({},'/api/rentals')).status,503);const html=readFileSync('index.html','utf8');assert.doesNotMatch(html,/localStorage\.setItem\(\s*["']dumpsterCrawlV3(?:Rentals|Customers)/);assert.match(html,/formData.append\('photoId',photoIdFile\)/);
});
test('capacity conflict cleans uploaded object; completed rental releases capacity',async t=>{
 const env=setup(t),cookie=await login(env);let first;
 for(let i=0;i<5;i++){const response=await upload(env,cookie);assert.equal(response.status,201);const {rental}=await response.json();first??=rental;}
 assert.equal((await upload(env,cookie)).status,409);assert.equal(env.objects.size,5);
 await call(env,`/api/rentals/${first.id}`,{method:'PATCH',headers:{cookie,origin:'https://v4.test'},body:JSON.stringify({status:'completed'})});
 assert.equal((await upload(env,cookie)).status,201);
});
