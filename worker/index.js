import { agreementHtml, agreementVersion } from './agreement.js';
const MAX = 10 * 1024 * 1024;
const enc = new TextEncoder();
export const hash = async data => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', typeof data === 'string' ? enc.encode(data) : data)), b => b.toString(16).padStart(2,'0')).join('');
const json = (body, status=200) => new Response(JSON.stringify(body), {status, headers:{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'}});
const now = () => new Date().toISOString();
const packages = {'20-1':389,'20-2':469,'20-3':529,'30-4':595,'30-5':659};
export function fileType(bytes) {
 const b = new Uint8Array(bytes), text = new TextDecoder('latin1');
 if(b[0]===255 && b[1]===216 && b[2]===255) return 'image/jpeg';
 if([137,80,78,71,13,10,26,10].every((v,i)=>b[i]===v)) return 'image/png';
 if(text.decode(b.slice(0,4))==='RIFF' && text.decode(b.slice(8,12))==='WEBP') return 'image/webp';
 if(text.decode(b.slice(0,5))==='%PDF-') return 'application/pdf';
 return null;
}
async function session(request, env) {
 const token = request.headers.get('cookie')?.match(/(?:^|;\s*)v4_session=([a-f0-9]{64})(?:;|$)/)?.[1];
 return token && await env.DB.prepare('SELECT token_hash FROM sessions WHERE token_hash = ? AND expires_at > ?').bind(await hash(token), Date.now()).first();
}
async function audit(env,id,action) {await env.DB.prepare('INSERT INTO audit (rental_id, action, occurred_at) VALUES (?, ?, ?)').bind(id,action,now()).run();}
export async function handle(request, env) {
 const url=new URL(request.url), path=url.pathname;
 if(!env.DB || !env.BUCKET || !env.STAFF_PASSWORD || env.STAFF_PASSWORD.length<20) return json({error:'Secure storage is not configured. Contact the owner.'},503);
 if(request.method!=='GET' && request.headers.get('origin')!==url.origin) return json({error:'Invalid origin'},403);
 if(Number(request.headers.get('content-length'))>MAX+65536) return json({error:'Upload too large'},413);
 if(path==='/api/login' && request.method==='POST') {
  const client=await hash(request.headers.get('CF-Connecting-IP') || 'local');
  await env.DB.prepare('INSERT INTO login_attempts VALUES (?, 1, ?) ON CONFLICT(client_hash) DO UPDATE SET attempts = CASE WHEN window_start < ? THEN 1 ELSE attempts + 1 END, window_start = CASE WHEN window_start < ? THEN excluded.window_start ELSE window_start END').bind(client,Date.now(),Date.now()-900000,Date.now()-900000).run();
  const attempt=await env.DB.prepare('SELECT attempts FROM login_attempts WHERE client_hash = ?').bind(client).first();
  if(attempt.attempts>5) return json({error:'Too many attempts. Try again in 15 minutes.'},429);
  const body=await request.json();
  if(typeof body.password!=='string' || await hash(body.password)!==await hash(env.STAFF_PASSWORD)) return json({error:'Incorrect staff password'},401);
  const token=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
  await env.DB.prepare('INSERT INTO sessions VALUES (?, ?)').bind(await hash(token),Date.now()+8*3600000).run();
  await audit(env,null,'staff-login');
  const response=json({ok:true}); response.headers.set('set-cookie',`v4_session=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800`); return response;
 }
 if(!await session(request,env)) return json({error:'Staff sign-in required'},401);
 if(path==='/api/logout' && request.method==='POST') {
  const token=request.headers.get('cookie').match(/v4_session=([a-f0-9]{64})/)[1];
  await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await hash(token)).run();
  const response=json({ok:true}); response.headers.set('set-cookie','v4_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0'); return response;
 }
 if(path==='/api/rentals' && request.method==='GET') {
  const rows=await env.DB.prepare('SELECT id, record, status FROM rentals ORDER BY created_at DESC').all();
  return json({rentals:rows.results.map(row=>({...JSON.parse(row.record),status:row.status}))});
 }
 if(path==='/api/rentals' && request.method==='POST') {
  const form=await request.formData(), photo=form.get('photoId');
  if(!photo || typeof photo==='string' || !photo.size) return json({error:'A photo ID is required'},400);
  if(photo.size>MAX) return json({error:'Photo ID must be 10 MB or smaller'},413);
  const bytes=await photo.arrayBuffer(), type=fileType(bytes);
  if(!type || type!==photo.type) return json({error:'Photo ID contents do not match a supported file type'},400);
  let body; try {body=JSON.parse(form.get('rental'));} catch {return json({error:'Invalid rental'},400);}
  if(!body || !['customer','phone','address','signatureName'].every(k=>typeof body[k]==='string' && body[k].trim() && body[k].length<=1000) || body.liabilityAccepted!==true || !Object.hasOwn(packages,body.packageId)) return json({error:'Complete required fields and accept the agreement'},400);
  if(!/^\d{4}-\d{2}-\d{2}$/.test(body.delivery)) return json({error:'Invalid delivery date'},400);
  const date=new Date(body.delivery+'T00:00:00Z');
  if(!Number.isFinite(date.getTime()) || date.toISOString().slice(0,10)!==body.delivery) return json({error:'Invalid delivery date'},400);
  date.setUTCDate(date.getUTCDate()+10);
  const id=crypto.randomUUID(), key=`private-ids/${id}/${crypto.randomUUID()}`, createdAt=now();
  const record={id,customer:body.customer.trim(),phone:body.phone.trim(),address:body.address.trim(),email:String(body.email||'').slice(0,254),placement:String(body.placement||'').slice(0,2000),notes:String(body.notes||'').slice(0,2000),packageId:body.packageId,delivery:body.delivery,pickup:date.toISOString().slice(0,10),price:packages[body.packageId],dumpster:body.packageId.startsWith('20')?'20-01':'30-01',paymentStatus:'Unpaid',status:'active',createdAt,liabilityAccepted:true,liabilityAcceptedAt:createdAt,signatureName:body.signatureName.trim(),agreementVersion,agreementHtml,agreementSha256:await hash(agreementHtml),photoIdReceived:true,photoIdFileType:type,photoIdFileSize:photo.size,photoIdSha256:await hash(bytes)};
  // UUID object keys never include the customer filename. Bucket is private.
  await env.BUCKET.put(key,bytes,{httpMetadata:{contentType:type},customMetadata:{rentalId:id}});
  try {
   const units=body.packageId.startsWith('20')?['20-01','20-02','20-03','20-04','20-05']:['30-01'];
   let saved=false;
   for(const unit of units) {
    record.dumpster=unit;
    // Conditional insert serializes inventory allocation with the database write.
    const results=await env.DB.batch([
     env.DB.prepare(`INSERT INTO rentals (id, record, document_key, document_type, document_hash, created_at)
      SELECT ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM rentals WHERE status = 'active'
       AND json_extract(record, '$.dumpster') = ? AND json_extract(record, '$.delivery') <= ? AND json_extract(record, '$.pickup') >= ?)`)
      .bind(id,JSON.stringify(record),key,type,record.photoIdSha256,createdAt,unit,record.pickup,record.delivery),
     env.DB.prepare('INSERT INTO audit (rental_id, action, occurred_at) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM rentals WHERE id = ?)').bind(id,'rental-created',createdAt,id)
    ]);
    if(results[0].meta.changes===1){saved=true;break;}
   }
   if(!saved){await env.BUCKET.delete(key);return json({error:'No dumpster is available for these dates'},409);}
  } catch(error) {await env.BUCKET.delete(key); throw error;}
  return json({rental:record},201);
 }
 const match=path.match(/^\/api\/rentals\/([a-f0-9-]{36})(?:\/(photo-id|agreement))?$/);
 if(match) {
  const row=await env.DB.prepare('SELECT * FROM rentals WHERE id = ?').bind(match[1]).first();
  if(!row) return json({error:'Not found'},404);
  if(request.method==='GET' && match[2]==='photo-id') {
   const object=await env.BUCKET.get(row.document_key);
   if(!object) return json({error:'Document unavailable'},404);
   await audit(env,row.id,'photo-id-read');
   return new Response(object.body,{headers:{'content-type':row.document_type,'content-disposition':'attachment; filename="photo-id"','cache-control':'private, no-store','x-content-type-options':'nosniff','content-security-policy':"sandbox; default-src 'none'"}});
  }
  if(request.method==='GET' && match[2]==='agreement') {await audit(env,row.id,'agreement-read');return json(JSON.parse(row.record));}
  if(request.method==='PATCH' && !match[2]) {
   const body=await request.json();
   if(!['completed','cancelled'].includes(body.status)) return json({error:'Invalid status'},400);
   await env.DB.batch([env.DB.prepare('UPDATE rentals SET status = ? WHERE id = ?').bind(body.status,row.id),env.DB.prepare('INSERT INTO audit (rental_id, action, occurred_at) VALUES (?, ?, ?)').bind(row.id,body.status,now())]);
   return json({ok:true});
  }
 }
 return json({error:'Not found'},404);
}
export default {async fetch(request,env) {
 try {
  if(!new URL(request.url).pathname.startsWith('/api/')) return env.ASSETS.fetch(request);
  // Bound streamed bodies too; Content-Length is optional and untrusted.
  if(request.body){
   const reader=request.body.getReader(), chunks=[];let size=0;
   while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;
    if(size>MAX+65536){await reader.cancel();return json({error:'Upload too large'},413);}chunks.push(value);}
   const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
   request=new Request(request.url,{method:request.method,headers:request.headers,body:bytes});
  }
  return await handle(request,env);
 } catch {return json({error:'The request could not be saved. Please try again or contact the owner.'},503);}
}};
