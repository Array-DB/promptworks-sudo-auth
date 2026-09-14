import 'dotenv/config';
import Fastify from 'fastify';
import rateLimit from '@fastify/rate-limit';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { z } from 'zod';

const required = (name: string) => {
  const v = process.env[name]?.trim();
  if (!v) throw new Error(`FATAL: ${name} is required; refusing insecure startup`);
  return v;
};
const ADMIN_TOKEN = required('PW_ADMIN_TOKEN');
if (ADMIN_TOKEN.length < 32) throw new Error('FATAL: PW_ADMIN_TOKEN must be at least 32 characters');
const PAIRING_MASTER_HEX = required('PW_PAIRING_MASTER_HEX');
if (!/^[0-9a-fA-F]{64}$/.test(PAIRING_MASTER_HEX)) throw new Error('FATAL: PW_PAIRING_MASTER_HEX must be exactly 32 random bytes encoded as 64 hex characters');
const OFFLINE_HOST_ID = required('PW_OFFLINE_HOST_ID');
const PAIRING_ID = required('PW_PAIRING_ID');
const HOST_PUBLIC_KEY_PATH = required('PW_HOST_PUBLIC_KEY_PATH');
const HOST_PUBLIC_KEY_PEM = fs.readFileSync(HOST_PUBLIC_KEY_PATH, 'utf8');
const HOST_PUBLIC_KEY_FINGERPRINT = crypto.createHash('sha256').update(crypto.createPublicKey(HOST_PUBLIC_KEY_PEM).export({type:'spki',format:'der'})).digest('hex');

const tlsCert = process.env.PW_TLS_CERT?.trim();
const tlsKey = process.env.PW_TLS_KEY?.trim();
const https = tlsCert && tlsKey ? { cert: fs.readFileSync(tlsCert), key: fs.readFileSync(tlsKey) } : undefined;
const app = Fastify({ logger: true, trustProxy: false, bodyLimit: 32 * 1024, ...(https ? { https } : {}) });
await app.register(rateLimit, { global: true, max: 120, timeWindow: '1 minute' });
const db = new Database(process.env.PW_DB_PATH ?? './promptworks-auth.sqlite');
db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON'); db.pragma('secure_delete = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS clients(
 id TEXT PRIMARY KEY,name TEXT NOT NULL,key_hash TEXT UNIQUE NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,
 service_scope TEXT,user_scope TEXT,created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enroll(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at TEXT NOT NULL,used_at TEXT);
CREATE TABLE IF NOT EXISTS devices(
 id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT NOT NULL,approval_public_key_pem TEXT NOT NULL,
 transport_public_key_pem TEXT NOT NULL,approval_key_fingerprint TEXT,transport_key_fingerprint TEXT,pairing_id TEXT,
 enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,last_seen_at TEXT,ready_at TEXT
);
CREATE TABLE IF NOT EXISTS device_nonces(
 nonce_hash TEXT PRIMARY KEY,device_id TEXT NOT NULL,purpose TEXT NOT NULL,expires_at TEXT NOT NULL,used_at TEXT,
 FOREIGN KEY(device_id) REFERENCES devices(id)
);
CREATE TABLE IF NOT EXISTS requests(
 id TEXT PRIMARY KEY,client_id TEXT NOT NULL,user_id TEXT NOT NULL,service TEXT NOT NULL,device TEXT NOT NULL,
 location TEXT NOT NULL,action TEXT NOT NULL DEFAULT '',challenge TEXT NOT NULL,verification_code TEXT NOT NULL,
 status TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,receipt_code TEXT,approved_by TEXT,decided_at TEXT,
 FOREIGN KEY(client_id) REFERENCES clients(id)
);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL,data TEXT NOT NULL,prev_hash TEXT NOT NULL,
 entry_hash TEXT UNIQUE NOT NULL,created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_user_status ON requests(user_id,status,created_at);
CREATE INDEX IF NOT EXISTS idx_requests_client ON requests(client_id,id);
`);

// Safe forward migrations for older starter databases.
for (const sql of [
  "ALTER TABLE clients ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
  "ALTER TABLE clients ADD COLUMN service_scope TEXT",
  "ALTER TABLE clients ADD COLUMN user_scope TEXT",
  "ALTER TABLE devices ADD COLUMN approval_public_key_pem TEXT",
  "ALTER TABLE devices ADD COLUMN transport_public_key_pem TEXT",
  "ALTER TABLE devices ADD COLUMN last_seen_at TEXT",
  "ALTER TABLE devices ADD COLUMN approval_key_fingerprint TEXT",
  "ALTER TABLE devices ADD COLUMN transport_key_fingerprint TEXT",
  "ALTER TABLE devices ADD COLUMN pairing_id TEXT",
  "ALTER TABLE devices ADD COLUMN ready_at TEXT",
  "ALTER TABLE requests ADD COLUMN action TEXT NOT NULL DEFAULT ''",
  "ALTER TABLE requests ADD COLUMN verification_code TEXT",
  "ALTER TABLE requests ADD COLUMN receipt_code TEXT",
  "ALTER TABLE audit ADD COLUMN prev_hash TEXT NOT NULL DEFAULT 'LEGACY'",
  "ALTER TABLE audit ADD COLUMN entry_hash TEXT",
]) { try { db.exec(sql); } catch {} }
try { db.exec("UPDATE devices SET approval_public_key_pem=public_key_pem WHERE approval_public_key_pem IS NULL"); } catch {}
try { db.exec("UPDATE devices SET transport_public_key_pem=approval_public_key_pem WHERE transport_public_key_pem IS NULL"); } catch {}
try { db.exec("UPDATE requests SET verification_code=printf('%03d', abs(random()) % 1000) WHERE verification_code IS NULL"); } catch {}
try {
  db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_exactly_one_enabled ON devices((1)) WHERE enabled=1");
} catch {
  throw new Error('FATAL: provisioning database contains more than one enabled device; refusing ambiguous pairing. Remove the temporary provisioning state and re-run pairing deliberately.');
}

const legacyAuditRows = db.prepare('SELECT id,event,data,created_at,prev_hash,entry_hash FROM audit ORDER BY id ASC').all() as any[];
if (legacyAuditRows.some(r => !r.entry_hash || r.prev_hash === 'LEGACY')) {
  let prev='GENESIS';
  const upd=db.prepare('UPDATE audit SET prev_hash=?, entry_hash=? WHERE id=?');
  db.transaction(()=>{ for(const row of legacyAuditRows){ const entry=crypto.createHash('sha256').update([prev,row.event,row.data,row.created_at].join('\n')).digest('hex');upd.run(prev,entry,row.id);prev=entry; } })();
}

const now = () => new Date().toISOString();
const plus = (s: number) => new Date(Date.now() + s * 1000).toISOString();
const rnd = (n = 32) => crypto.randomBytes(n).toString('base64url');
const hash = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const safeEq = (a: string, b: string) => { const A=Buffer.from(a),B=Buffer.from(b); return A.length===B.length && crypto.timingSafeEqual(A,B); };
const keyFingerprint = (pem:string) => crypto.createHash('sha256').update(crypto.createPublicKey(pem).export({type:'spki',format:'der'})).digest('hex');
const pairedSecret = (deviceId:string, approvalFp:string) => crypto.createHmac('sha256',Buffer.from(PAIRING_MASTER_HEX,'hex')).update(['promptworks-offline-pair-v1',PAIRING_ID,OFFLINE_HOST_ID,deviceId,approvalFp,HOST_PUBLIC_KEY_FINGERPRINT].join('\n')).digest('hex');
const bearer = (r: any) => String(r.headers.authorization ?? '').replace(/^Bearer\s+/i, '');

function audit(event: string, data: unknown) {
  const created = now();
  const prev = (db.prepare('SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1').get() as any)?.entry_hash ?? 'GENESIS';
  const body = JSON.stringify(data);
  const entry = hash([prev,event,body,created].join('\n'));
  db.prepare('INSERT INTO audit(event,data,prev_hash,entry_hash,created_at) VALUES(?,?,?,?,?)').run(event,body,prev,entry,created);
}
function admin(r:any,p:any){ if(!safeEq(bearer(r),ADMIN_TOKEN)){p.code(401).send({error:'unauthorized'});return false;} return true; }
function client(r:any,p:any){ const x=db.prepare('SELECT * FROM clients WHERE key_hash=? AND enabled=1').get(hash(bearer(r))) as any; if(!x){p.code(401).send({error:'bad_client_key'});return null;} return x; }
function expire(x:any){ if(x&&x.status==='pending'&&Date.parse(x.expires_at)<=Date.now()){db.prepare("UPDATE requests SET status='expired',decided_at=? WHERE id=? AND status='pending'").run(now(),x.id);x.status='expired';audit('auth.expired',{id:x.id});}return x; }
function verifySig(publicKeyPem:string,payload:string,sigB64:string){ try { const v=crypto.createVerify('SHA256');v.update(Buffer.from(payload));v.end();return v.verify(publicKeyPem,Buffer.from(sigB64,'base64')); } catch { return false; } }
function decisionPayload(q:any,decision:string,deviceId:string){ return ['promptworks-auth-v2',q.id,q.challenge,q.verification_code,q.user_id,q.service,q.device,q.location,q.action,q.expires_at,decision,deviceId].join('\n'); }

app.get('/healthz', async()=>({ok:true,version:4,mode:'single-device-offline-provisioning',pairingId:PAIRING_ID,hostId:OFFLINE_HOST_ID,hostKeyFingerprint:HOST_PUBLIC_KEY_FINGERPRINT}));
app.post('/v1/admin/clients',{config:{rateLimit:{max:20,timeWindow:'1 minute'}}},async(r,p)=>{
  if(!admin(r,p))return;
  const b=z.object({name:z.string().min(1).max(100),serviceScope:z.string().min(1).max(200).optional(),userScope:z.string().min(1).max(200).optional()}).parse(r.body);
  const id='client_'+crypto.randomUUID(),key='pwk_'+rnd(32);
  db.prepare('INSERT INTO clients(id,name,key_hash,enabled,service_scope,user_scope,created_at) VALUES(?,?,?,?,?,?,?)').run(id,b.name,hash(key),1,b.serviceScope??null,b.userScope??null,now());
  audit('client.created',{id,name:b.name,serviceScope:b.serviceScope??null,userScope:b.userScope??null});
  return{id,name:b.name,clientKey:key};
});
app.post('/v1/admin/clients/:id/revoke',async(r:any,p)=>{if(!admin(r,p))return;db.prepare('UPDATE clients SET enabled=0 WHERE id=?').run(r.params.id);audit('client.revoked',{id:r.params.id});return{ok:true};});
app.post('/v1/admin/enrollment-tokens',{config:{rateLimit:{max:10,timeWindow:'1 minute'}}},async(r,p)=>{
  if(!admin(r,p))return; const b=z.object({userId:z.string().min(1).max(200),ttlSeconds:z.number().int().min(60).max(3600).default(300)}).parse(r.body);
  const token='pwe_'+rnd(32),expiresAt=plus(b.ttlSeconds);db.prepare('INSERT INTO enroll(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hash(token),b.userId,expiresAt);audit('enrollment.created',{userId:b.userId,expiresAt});return{token,userId:b.userId,expiresAt};
});
app.post('/v1/devices/enroll',{config:{rateLimit:{max:8,timeWindow:'5 minutes'}}},async(r,p)=>{
  const b=z.object({token:z.string(),deviceName:z.string().min(1).max(200),approvalPublicKeyPem:z.string().min(100).max(5000),transportPublicKeyPem:z.string().min(100).max(5000)}).parse(r.body);
  const e=db.prepare('SELECT * FROM enroll WHERE token_hash=?').get(hash(b.token)) as any;
  if(!e||e.used_at||Date.parse(e.expires_at)<=Date.now())return p.code(400).send({error:'invalid_enrollment'});
  let approvalFp:string, transportFp:string;
  try { approvalFp=keyFingerprint(b.approvalPublicKeyPem);transportFp=keyFingerprint(b.transportPublicKeyPem); } catch { return p.code(400).send({error:'invalid_public_key'}); }
  const existing=db.prepare('SELECT * FROM devices WHERE enabled=1 ORDER BY created_at ASC LIMIT 1').get() as any;
  let id:string;
  if(existing){
    const existingApproval=existing.approval_key_fingerprint||keyFingerprint(existing.approval_public_key_pem);
    const existingTransport=existing.transport_key_fingerprint||keyFingerprint(existing.transport_public_key_pem);
    if(existingApproval!==approvalFp||existingTransport!==transportFp||existing.user_id!==e.user_id){
      audit('device.enrollment_rejected',{reason:'host_already_bound',existingId:existing.id,attemptedApprovalFingerprint:approvalFp});
      return p.code(409).send({error:'host_already_bound',message:'This PromptWorks host is already paired to a different APK installation. Run sudo promptworksctl reset-pairing before pairing another phone.'});
    }
    id=existing.id;
    db.prepare('UPDATE devices SET name=?,approval_key_fingerprint=?,transport_key_fingerprint=?,pairing_id=? WHERE id=?').run(b.deviceName,approvalFp,transportFp,PAIRING_ID,id);
  } else {
    id='dev_'+crypto.randomUUID();
    db.prepare('INSERT INTO devices(id,user_id,name,approval_public_key_pem,transport_public_key_pem,approval_key_fingerprint,transport_key_fingerprint,pairing_id,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,e.user_id,b.deviceName,b.approvalPublicKeyPem,b.transportPublicKeyPem,approvalFp,transportFp,PAIRING_ID,1,now());
  }
  db.prepare('UPDATE enroll SET used_at=? WHERE token_hash=?').run(now(),hash(b.token));
  const secret=pairedSecret(id,approvalFp);
  audit('device.enrolled',{id,userId:e.user_id,name:b.deviceName,mode:'single-device-offline',pairingId:PAIRING_ID,approvalFingerprint:approvalFp});
  return{deviceId:id,userId:e.user_id,offlineSecretHex:secret,offlineHostId:OFFLINE_HOST_ID,offlineSuite:'PW-TIME-MATCH-HMAC-SHA256-8:v1',pairingId:PAIRING_ID,hostPublicKeyPem:HOST_PUBLIC_KEY_PEM,hostKeyFingerprint:HOST_PUBLIC_KEY_FINGERPRINT,approvalKeyFingerprint:approvalFp};
});
app.post('/v1/devices/:id/offline-ready',{config:{rateLimit:{max:8,timeWindow:'5 minutes'}}},async(r:any,p)=>{
  const d=db.prepare('SELECT * FROM devices WHERE id=? AND enabled=1').get(r.params.id) as any;if(!d)return p.code(404).send({error:'device_not_found'});
  const b=z.object({proof:z.string().regex(/^[0-9a-fA-F]{64}$/),pairingId:z.string(),hostKeyFingerprint:z.string().regex(/^[0-9a-fA-F]{64}$/)}).parse(r.body);
  if(b.pairingId!==PAIRING_ID||b.hostKeyFingerprint.toLowerCase()!==HOST_PUBLIC_KEY_FINGERPRINT)return p.code(403).send({error:'binding_mismatch'});
  const approvalFp=d.approval_key_fingerprint||keyFingerprint(d.approval_public_key_pem);
  const secret=pairedSecret(d.id,approvalFp);
  const expected=crypto.createHmac('sha256',Buffer.from(secret,'hex')).update(['promptworks-offline-ready-v2',PAIRING_ID,OFFLINE_HOST_ID,d.id,d.user_id,approvalFp,HOST_PUBLIC_KEY_FINGERPRINT].join('\n')).digest('hex');
  if(!safeEq(expected,b.proof.toLowerCase()))return p.code(403).send({error:'bad_offline_proof'});
  db.prepare('UPDATE devices SET ready_at=?,approval_key_fingerprint=?,pairing_id=? WHERE id=?').run(now(),approvalFp,PAIRING_ID,d.id);
  audit('device.offline_ready',{id:d.id,userId:d.user_id,name:d.name,mode:'single-device-offline',pairingId:PAIRING_ID,approvalFingerprint:approvalFp,hostKeyFingerprint:HOST_PUBLIC_KEY_FINGERPRINT});return{ok:true};
});
app.get('/v1/admin/pairing',async(r,p)=>{
  if(!admin(r,p))return;
  const d=db.prepare('SELECT * FROM devices WHERE enabled=1 ORDER BY created_at ASC LIMIT 1').get() as any;
  if(!d)return p.code(404).send({error:'not_paired'});
  const approvalFp=d.approval_key_fingerprint||keyFingerprint(d.approval_public_key_pem);
  return{pairingId:PAIRING_ID,hostId:OFFLINE_HOST_ID,hostPublicKeyPem:HOST_PUBLIC_KEY_PEM,hostKeyFingerprint:HOST_PUBLIC_KEY_FINGERPRINT,deviceId:d.id,userId:d.user_id,deviceName:d.name,approvalPublicKeyPem:d.approval_public_key_pem,approvalKeyFingerprint:approvalFp,readyAt:d.ready_at||null};
});
app.post('/v1/devices/:id/nonce',{config:{rateLimit:{max:30,timeWindow:'1 minute'}}},async(r:any,p)=>{
  const d=db.prepare('SELECT id FROM devices WHERE id=? AND enabled=1').get(r.params.id) as any;if(!d)return p.code(404).send({error:'device_not_found'});
  const nonce=rnd(32),expiresAt=plus(30);db.prepare('INSERT INTO device_nonces(nonce_hash,device_id,purpose,expires_at) VALUES(?,?,?,?)').run(hash(nonce),d.id,'requests',expiresAt);return{nonce,expiresAt};
});
app.get('/v1/devices/:id/requests',{config:{rateLimit:{max:30,timeWindow:'1 minute'}}},async(r:any,p)=>{
  const d=db.prepare('SELECT * FROM devices WHERE id=? AND enabled=1').get(r.params.id) as any;if(!d)return p.code(404).send({error:'device_not_found'});
  const nonce=String(r.headers['x-pw-nonce']??''),signature=String(r.headers['x-pw-signature']??'');
  const n=db.prepare("SELECT * FROM device_nonces WHERE nonce_hash=? AND device_id=? AND purpose='requests'").get(hash(nonce),d.id) as any;
  if(!n||n.used_at||Date.parse(n.expires_at)<=Date.now())return p.code(401).send({error:'invalid_device_nonce'});
  const payload=['promptworks-device-auth-v1',d.id,nonce].join('\n');if(!verifySig(d.transport_public_key_pem,payload,signature))return p.code(401).send({error:'bad_device_signature'});
  const used=db.prepare('UPDATE device_nonces SET used_at=? WHERE nonce_hash=? AND used_at IS NULL').run(now(),hash(nonce));if(used.changes!==1)return p.code(409).send({error:'nonce_reused'});
  db.prepare('UPDATE devices SET last_seen_at=? WHERE id=?').run(now(),d.id);
  const rows=(db.prepare("SELECT id,user_id,service,device,location,action,challenge,verification_code,status,created_at,expires_at FROM requests WHERE user_id=? AND status='pending' ORDER BY created_at DESC LIMIT 10").all(d.user_id) as any[]).map(expire);
  return rows.filter(x=>x.status==='pending');
});

// Long-poll endpoint used by the Android foreground runtime. A single authenticated
// request waits up to 25 seconds for work, avoiding fragile high-frequency polling
// and Android/GrapheneOS scheduling gaps while keeping the private LAN transport.
app.get('/v1/devices/:id/requests/wait',{config:{rateLimit:{max:12,timeWindow:'1 minute'}}},async(r:any,p)=>{
  const d=db.prepare('SELECT * FROM devices WHERE id=? AND enabled=1').get(r.params.id) as any;if(!d)return p.code(404).send({error:'device_not_found'});
  const nonce=String(r.headers['x-pw-nonce']??''),signature=String(r.headers['x-pw-signature']??'');
  const n=db.prepare("SELECT * FROM device_nonces WHERE nonce_hash=? AND device_id=? AND purpose='requests'").get(hash(nonce),d.id) as any;
  if(!n||n.used_at||Date.parse(n.expires_at)<=Date.now())return p.code(401).send({error:'invalid_device_nonce'});
  const payload=['promptworks-device-auth-v1',d.id,nonce].join('\n');if(!verifySig(d.transport_public_key_pem,payload,signature))return p.code(401).send({error:'bad_device_signature'});
  const used=db.prepare('UPDATE device_nonces SET used_at=? WHERE nonce_hash=? AND used_at IS NULL').run(now(),hash(nonce));if(used.changes!==1)return p.code(409).send({error:'nonce_reused'});
  const rawTimeout=Number((r.query??{}).timeoutSeconds??25);const timeoutMs=Math.max(1,Math.min(25,Number.isFinite(rawTimeout)?rawTimeout:25))*1000;
  const deadline=Date.now()+timeoutMs;
  while(true){
    const rows=(db.prepare("SELECT id,user_id,service,device,location,action,challenge,verification_code,status,created_at,expires_at FROM requests WHERE user_id=? AND status='pending' ORDER BY created_at DESC LIMIT 10").all(d.user_id) as any[]).map(expire).filter(x=>x.status==='pending');
    if(rows.length){db.prepare('UPDATE devices SET last_seen_at=? WHERE id=?').run(now(),d.id);return rows;}
    if(Date.now()>=deadline){db.prepare('UPDATE devices SET last_seen_at=? WHERE id=?').run(now(),d.id);return [];}
    await new Promise(resolve=>setTimeout(resolve,250));
  }
});
app.post('/v1/auth/requests',{config:{rateLimit:{max:12,timeWindow:'1 minute'}}},async(r,p)=>{
  const c=client(r,p);if(!c)return;
  const b=z.object({userId:z.string().min(1).max(200),service:z.string().min(1).max(200),device:z.string().max(300).default('Unknown device'),location:z.string().max(300).default('Unknown location'),action:z.string().max(2000).default(''),ttlSeconds:z.number().int().min(20).max(120).default(60)}).parse(r.body);
  if(c.service_scope && c.service_scope!==b.service)return p.code(403).send({error:'service_scope_violation'});
  if(c.user_scope && c.user_scope!==b.userId)return p.code(403).send({error:'user_scope_violation'});
  const active=(db.prepare("SELECT COUNT(*) n FROM requests WHERE client_id=? AND user_id=? AND status='pending' AND expires_at>?").get(c.id,b.userId,now()) as any).n;
  if(active>=3)return p.code(429).send({error:'too_many_pending_requests'});
  const id='req_'+crypto.randomUUID(),challenge=rnd(32),verificationCode=String(crypto.randomInt(0,1000)).padStart(3,'0'),receiptCode=String(crypto.randomInt(0,100000000)).padStart(8,'0'),createdAt=now(),expiresAt=plus(b.ttlSeconds);
  db.prepare('INSERT INTO requests(id,client_id,user_id,service,device,location,action,challenge,verification_code,status,created_at,expires_at,receipt_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id,c.id,b.userId,b.service,b.device,b.location,b.action,challenge,verificationCode,'pending',createdAt,expiresAt,receiptCode);
  audit('auth.created',{id,clientId:c.id,userId:b.userId,service:b.service,device:b.device,action:b.action});
  return{id,challenge,verificationCode,status:'pending',createdAt,expiresAt};
});
app.get('/v1/auth/requests/:id',async(r:any,p)=>{const c=client(r,p);if(!c)return;const x=expire(db.prepare('SELECT id,status,service,device,location,action,verification_code,created_at,expires_at,receipt_code,approved_by,decided_at FROM requests WHERE id=? AND client_id=?').get(r.params.id,c.id) as any);if(!x)return p.code(404).send({error:'not_found'});if(x.status==='pending')delete x.receipt_code;return x;});
app.post('/v1/auth/requests/:id/decision',{config:{rateLimit:{max:30,timeWindow:'1 minute'}}},async(r:any,p)=>{
  const b=z.object({deviceId:z.string(),decision:z.enum(['approve','deny']),signature:z.string().min(20)}).parse(r.body);
  const q=expire(db.prepare('SELECT * FROM requests WHERE id=?').get(r.params.id) as any);
  if(!q)return p.code(404).send({error:'not_found'});
  const d=db.prepare('SELECT * FROM devices WHERE id=? AND user_id=? AND enabled=1').get(b.deviceId,q.user_id) as any;
  if(!d)return p.code(403).send({error:'device_not_authorized'});
  // Always authenticate the decision payload, including on retries. This makes the
  // endpoint safely idempotent without allowing an unauthenticated status oracle.
  if(!verifySig(d.approval_public_key_pem,decisionPayload(q,b.decision,b.deviceId),b.signature))return p.code(403).send({error:'bad_signature'});
  const wanted=b.decision==='approve'?'approved':'denied';
  if(q.status===wanted && q.approved_by===b.deviceId){
    return{id:q.id,status:q.status,receiptCode:q.receipt_code,decidedAt:q.decided_at,replayed:true};
  }
  if(q.status!=='pending')return p.code(409).send({error:'not_pending',status:q.status});
  const decidedAt=now();
  const result=db.prepare('UPDATE requests SET status=?,approved_by=?,decided_at=? WHERE id=? AND status=\'pending\' AND expires_at>?').run(wanted,b.deviceId,decidedAt,q.id,decidedAt);
  if(result.changes!==1)return p.code(409).send({error:'request_race_or_expired'});
  audit('auth.'+wanted,{id:q.id,deviceId:b.deviceId});
  return{id:q.id,status:wanted,receiptCode:q.receipt_code,decidedAt,replayed:false};
});
app.post('/v1/admin/devices/:id/revoke',async(r:any,p)=>{if(!admin(r,p))return;db.prepare('UPDATE devices SET enabled=0 WHERE id=?').run(r.params.id);audit('device.revoked',{id:r.params.id});return{ok:true};});
app.get('/v1/admin/audit',async(r,p)=>{if(!admin(r,p))return;return db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 500').all();});
app.get('/v1/admin/audit/verify',async(r,p)=>{if(!admin(r,p))return;const rows=db.prepare('SELECT * FROM audit ORDER BY id ASC').all() as any[];let prev='GENESIS';for(const row of rows){const expected=hash([prev,row.event,row.data,row.created_at].join('\n'));if(row.prev_hash!==prev||row.entry_hash!==expected)return{ok:false,brokenAt:row.id};prev=row.entry_hash;}return{ok:true,count:rows.length,head:prev};});
app.setErrorHandler((e:any,_r,p)=>{app.log.error(e);if(e instanceof z.ZodError)return p.code(400).send({error:'invalid_request',details:e.issues});return p.code(500).send({error:'internal_error'});});
await app.listen({host:process.env.PW_HOST??'127.0.0.1',port:Number(process.env.PW_PORT??8787)});
