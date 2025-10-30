// server.js — Webhook único (Fastify)
// Roteia MENSAGENS para <subdomain>.incoming e STATUS para <subdomain>.status
// - Resolução de tenant:
//   1) public.tenant_channel_connections(channel, external_id)    // WhatsApp -> phone_number_id
//   2) public.tenant_channel_connections(channel, account_id)     // WhatsApp -> WABA_ID
//   3) public.tenants.*_external_id (LEGADO)
//
// ⚠️ Idempotência REMOVIDA (mensagens e status)

'use strict';

const Fastify = require('fastify');
const rawBody = require('fastify-raw-body');
const crypto = require('crypto');
const amqplib = require('amqplib');
const pg = require('pg');

// ========= ENV =========
const PORT = Number(process.env.PORT || 3000);

// Meta (modo permissivo: não bloqueia se faltar)
const META_APP_SECRET = process.env.META_APP_SECRET || '';
const META_VERIFY_TOKEN = process.env.META_VERIFY_TOKEN || '';

// Telegram (modo permissivo: não bloqueia se faltar)
const TELEGRAM_SECRET = process.env.TELEGRAM_SECRET || '';

// Postgres
const { Pool } = pg;
const pool = new Pool({
  host: process.env.PGHOST,
  port: Number(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  max: 10,
  idleTimeoutMillis: 10000
});

// Rabbit
const DEFAULT_AMQP_URL = process.env.DEFAULT_AMQP_URL || 'amqp://guest:guest@rabbitmq:5672/';
const FALLBACK_QUEUE   = process.env.FALLBACK_QUEUE   || 'hmg.incoming';

// Template de fila (ex.: "%s.incoming" -> "hmg.incoming")
const QUEUE_TEMPLATE = process.env.QUEUE_TEMPLATE || '%s.incoming';

// fila de STATUS por tenant (ex.: "%s.status" -> "hmg.status")
const STATUS_QUEUE_TEMPLATE = process.env.STATUS_QUEUE_TEMPLATE || '%s.status';

// Cache de tenant (em memória)
const TENANT_CACHE_TTL   = parseInt(process.env.TENANT_CACHE_TTL   || '300',  10); // s

// ========= Utils =========
const now = () => new Date().toISOString();
const safe = (o) => { try { return JSON.stringify(o, null, 2); } catch { return '[unserializable]'; } };
const redact = (u) => String(u || '').replace(/(\/\/[^:]+:)([^@]+)(@)/, '$1***$3');
const normMsisdn = (s='') => String(s).replace(/\D/g, '');

// ========= TTL Cache simples (para resolução de tenant) =========
class TTLCache {
  constructor(maxSize = 5000) {
    this.map = new Map();
    this.maxSize = maxSize;
  }
  _now() { return Date.now(); }
  get(key) {
    const it = this.map.get(key);
    if (!it) return null;
    if (this._now() > it.expires) {
      this.map.delete(key);
      return null;
    }
    return it.value;
  }
  set(key, ttlSec, value) {
    this.map.set(key, { value, expires: this._now() + ttlSec * 1000 });
    this._cleanup();
  }
  _cleanup() {
    if (this.map.size <= this.maxSize) return;
    const now = this._now();
    for (const [k, v] of this.map) {
      if (v.expires <= now) this.map.delete(k);
      if (this.map.size <= this.maxSize) return;
    }
    while (this.map.size > this.maxSize) {
      const k = this.map.keys().next().value;
      this.map.delete(k);
    }
  }
}
const tenantCache = new TTLCache(5000);

// ========= Detect/Verify =========
function detectChannel(body, headers) {
  const lh = Object.fromEntries(Object.entries(headers || {}).map(([k, v]) => [String(k).toLowerCase(), v]));
  if ('x-hub-signature-256' in lh || 'x-hub-signature' in lh) {
    const obj = body?.object;
    if (obj === 'whatsapp_business_account') return 'whatsapp';
    if (obj === 'instagram') return 'instagram';
    if (obj === 'page') return 'facebook';
  }
  if (body && typeof body === 'object' && 'update_id' in body) return 'telegram';
  return 'unknown';
}

function verifyMetaSignature(sigHeader256, rawBuf) {
  if (!META_APP_SECRET) return true; // permissivo
  if (!sigHeader256 || !String(sigHeader256).startsWith('sha256=')) return false;
  const recv = String(sigHeader256).split('=')[1];
  const calc = crypto.createHmac('sha256', META_APP_SECRET).update(rawBuf).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(recv)); } catch { return false; }
}

function verifyTelegramSecret(tokenHeader) {
  if (!TELEGRAM_SECRET) return true; // permissivo
  return tokenHeader === TELEGRAM_SECRET;
}

// ========= Extração de IDs =========
/** external_id/account_id para resolver TENANT (já existia) */
function extractLookupId(channel, body, headersLower) {
  if (channel === 'whatsapp') {
    const entry  = body?.entry?.[0];
    const change = entry?.changes?.[0]?.value;
    const phoneId = change?.metadata?.phone_number_id || change?.phone_number_id || null;
    if (phoneId) return phoneId; // preferir phone_number_id
    const wabaId = entry?.id;    // WABA ID (fallback de resolução de tenant)
    if (wabaId) return wabaId;
    return null;
  }
  if (channel === 'instagram') {
    return body?.entry?.[0]?.id || null;
  }
  if (channel === 'facebook') {
    const entryId = body?.entry?.[0]?.id || null;
    return entryId;
  }
  if (channel === 'telegram') {
    return headersLower['x-telegram-bot-api-secret-token'] || null;
  }
  return null;
}

/** channel_key (resource_id) para o bot (NOVO — obrigatório p/ publicar) */
function extractResourceId(channel, body, headersLower) {
  if (channel === 'whatsapp') {
    const val = body?.entry?.[0]?.changes?.[0]?.value || {};
    return (
      val?.metadata?.phone_number_id ||
      val?.phone_number_id ||
      val?.metadata?.display_phone_number_id ||
      null
    );
  }
  if (channel === 'facebook') {
    const m = body?.entry?.[0]?.messaging?.[0];
    return m?.recipient?.id || null; // page_id
  }
  if (channel === 'instagram') {
    const entry = body?.entry?.[0];
    const m1 = entry?.messaging?.[0];
    const v2 = entry?.changes?.[0]?.value;
    return m1?.recipient?.id || v2?.id || v2?.page?.id || null; // ig user/page id
  }
  if (channel === 'telegram') {
    return headersLower['x-telegram-bot-api-secret-token'] || null; // bot_id/secret token
  }
  return null;
}

// ========= Normalização de evento =========
function normalizeEvent(channel, body) {
  const out = {
    channel,
    received_at: Date.now(),
    event_type: 'message.received',
    aggregate_id: null,  // SEMPRE o usuário/contato
    payload: body
  };

  try {
    if (channel === 'whatsapp') {
      const change = body?.entry?.[0]?.changes?.[0]?.value;
      // usuário = msg.from / contacts[0].wa_id
      const msg = change?.messages?.[0];
      out.aggregate_id = msg?.from || change?.contacts?.[0]?.wa_id || null;
    } else if (channel === 'instagram') {
      // como contato, use o "from" quando houver, senão um id genérico do entry
      const entry = body?.entry?.[0];
      const v2 = entry?.changes?.[0]?.value;
      const m1 = entry?.messaging?.[0];
      out.aggregate_id = (v2?.messages?.[0]?.from) || (m1?.sender?.id) || String(entry?.id ?? 'ig');
    } else if (channel === 'facebook') {
      const m = body?.entry?.[0]?.messaging?.[0];
      out.aggregate_id = m?.sender?.id ?? null; // PSID
    } else if (channel === 'telegram') {
      const m = body?.message || body?.edited_message || {};
      out.aggregate_id = m?.chat?.id != null ? String(m.chat.id) : null;
    }
  } catch (e) {
    console.warn('normalizeEvent erro:', e?.message);
  }
  return out;
}

// ========= Roteamento via Postgres (com cache de tenant) =========
async function resolveTenantAndQueue({ channel, lookupId }) {
  console.log(`🔎 resolveTenantAndQueue: channel=${channel} lookupId=${lookupId}`);

  if (!lookupId) {
    console.warn('⚠️ lookupId vazio — usando fallback');
    return { queue: FALLBACK_QUEUE, source: 'fallback', tenant: null };
  }

  const cacheKey = `tenantByExt:${channel}:${lookupId}`;
  const cached = tenantCache.get(cacheKey);
  if (cached) return cached;

  const client = await pool.connect();
  try {
    // 1) external_id
    const sqlExternal = `
      SELECT subdomain
        FROM public.tenant_channel_connections
       WHERE channel = $1
         AND external_id = $2
         AND is_active = true
       LIMIT 1
    `;
    let r = await client.query(sqlExternal, [channel, String(lookupId)]);
    if (r.rows[0]?.subdomain) {
      const sd = r.rows[0].subdomain;
      const queue = (QUEUE_TEMPLATE || '%s.incoming').replace('%s', sd);
      const res = { queue, source: 'tcc_external', tenant: sd };
      tenantCache.set(cacheKey, TENANT_CACHE_TTL, res);
      return res;
    }

    // 2) account_id
    const sqlAccount = `
      SELECT subdomain
        FROM public.tenant_channel_connections
       WHERE channel = $1
         AND account_id = $2
         AND is_active = true
       LIMIT 1
    `;
    r = await client.query(sqlAccount, [channel, String(lookupId)]);
    if (r.rows[0]?.subdomain) {
      const sd = r.rows[0].subdomain;
      const queue = (QUEUE_TEMPLATE || '%s.incoming').replace('%s', sd);
      const res = { queue, source: 'tcc_account', tenant: sd };
      tenantCache.set(cacheKey, TENANT_CACHE_TTL, res);
      return res;
    }

    // 3) LEGADO: colunas em public.tenants
    const legacyCol =
      channel === 'whatsapp' ? 'whatsapp_external_id'  :
      channel === 'telegram' ? 'telegram_external_id'  :
      channel === 'instagram'? 'instagram_external_id' :
      channel === 'facebook' ? 'facebook_external_id'  :
      null;

    if (legacyCol) {
      const sqlTenant = `
        SELECT subdomain
          FROM public.tenants
         WHERE ${legacyCol} = $1
         LIMIT 1
      `;
      const t = await client.query(sqlTenant, [String(lookupId)]);
      if (t.rows[0]?.subdomain) {
        const sd = t.rows[0].subdomain;
        const queue  = (QUEUE_TEMPLATE || '%s.incoming').replace('%s', sd);
        const res = { queue, source: 'tenants_legacy', tenant: sd };
        tenantCache.set(cacheKey, Math.min(TENANT_CACHE_TTL, 120), res);
        return res;
      }
    }

    return { queue: FALLBACK_QUEUE, source: 'fallback', tenant: null };
  } finally {
    client.release();
  }
}

// ========= Publisher Rabbit (confirm channel) =========
const amqpPool = new Map();
async function getConfirmChannel(url) {
  const amqpUrl = url || DEFAULT_AMQP_URL;
  const cached = amqpPool.get(amqpUrl);
  if (cached?.ch && !cached.closed) return cached.ch;

  console.log(`📡 Conectando ao RabbitMQ: ${redact(amqpUrl)}`);
  const conn = await amqplib.connect(amqpUrl, { heartbeat: 15 });
  const ch = await conn.createConfirmChannel();
  ch.on('error', (e) => console.error('[amqp ch error]', e));
  ch.on('close', () => { console.warn('[amqp ch closed]'); cached && (cached.closed = true); });
  conn.on('error', (e) => console.error('[amqp conn error]', e));
  conn.on('close', () => { console.warn('[amqp conn closed]'); cached && (cached.closed = true); });
  amqpPool.set(amqpUrl, { conn, ch, closed: false });
  return ch;
}

async function publishToQueue({ queue, body, headers }) {
  const ch = await getConfirmChannel(DEFAULT_AMQP_URL);
  const payload = Buffer.from(JSON.stringify(body));
  console.log(`📤 Publicando (messages) queue=${queue} payload_len=${payload.length}`);

  const ok = ch.publish('', queue, payload, {
    persistent: true,
    contentType: 'application/json',
    headers: headers || {}
  });
  if (!ok) {
    console.warn('⚠️ Buffer cheio — aguardando drain...');
    await new Promise((res) => ch.once('drain', res));
  }
  await ch.waitForConfirms();
  console.log('✅ confirmado pelo RabbitMQ (messages)');
}

// Publisher de STATUS (sem idempotência)
async function publishTenantStatus({ tenant, meta, statuses }) {
  if (!tenant || !Array.isArray(statuses) || !statuses.length) return;
  const queue = (STATUS_QUEUE_TEMPLATE || '%s.status').replace('%s', tenant);

  const ch = await getConfirmChannel(DEFAULT_AMQP_URL);
  await ch.assertQueue(queue, { durable: true });

  let published = 0;
  for (const st of statuses) {
    const id = st?.id;
    const s  = String(st?.status || '').toLowerCase();
    const ts = String(st?.timestamp || '');
    if (!id || !s || !ts) continue;

    const payload = {
      kind: 'waba_status',
      tenant,
      channel: 'whatsapp',
      phone_number_id: meta?.phone_number_id,
      display_phone_number: meta?.display_phone_number,
      status: {
        id: id,
        status: s,
        timestamp: ts,
        recipient_msisdn: normMsisdn(st?.recipient_id),
        conversation: st?.conversation || null,
        pricing: st?.pricing || null
      }
    };

    const ok = ch.publish('', queue, Buffer.from(JSON.stringify(payload)), {
      persistent: true,
      contentType: 'application/json',
      headers: { 'x-tenant': tenant, 'x-kind': 'waba_status' }
    });
    if (!ok) await new Promise(res => ch.once('drain', res));
    published++;
  }

  await ch.waitForConfirms();
  console.log(`✅ status publicados: tenant=${tenant} queue=${queue} count=${published}`);
}

// ========= Fastify =========
const app = Fastify({
  logger: { level: 'info' },
  bodyLimit: 2 * 1024 * 1024,
  trustProxy: true
});

app.register(rawBody, {
  field: 'rawBody',
  global: true,
  encoding: 'utf8',
  runFirst: true,
  routes: []
});

// Health
app.get('/healthz', async () => ({ ok: true, ts: now() }));
app.get('/readyz', async (_req, reply) => {
  try {
    await pool.query('SELECT 1');
    const c = await amqplib.connect(DEFAULT_AMQP_URL, { heartbeat: 5 }); await c.close();
    return reply.send({ ready: true, ts: now() });
  } catch (e) {
    return reply.code(500).send({ ready: false, error: e?.message, ts: now() });
  }
});

// GET /webhook (Meta verify)
app.get('/webhook', async (req, reply) => {
  const q = req.query || {};
  const mode = q['hub.mode'] || q.hub_mode;
  const challenge = q['hub.challenge'] || q.hub_challenge;
  const verifyToken = q['hub.verify_token'] || q.hub_verify_token;

  if (mode === 'subscribe' && verifyToken === META_VERIFY_TOKEN) {
    return reply.type('text/plain').send(challenge ?? '');
  }
  return reply.code(403).send({ error: 'verification failed' });
});

// POST /webhook (principal)
app.post('/webhook', async (req, reply) => {
  console.log('\n===== 📥 POST /webhook =====');
  console.log('🕒', now());
  console.log('➡️ Headers:', safe(req.headers));
  console.log('➡️ Body:', safe(req.body));

  const raw = Buffer.isBuffer(req.rawBody)
    ? req.rawBody
    : Buffer.from(typeof req.rawBody === 'string' ? req.rawBody : JSON.stringify(req.body || {}));

  const channel = detectChannel(req.body, req.headers);
  console.log('🎯 channel:', channel);
  if (channel === 'unknown') return reply.code(400).send({ error: 'unknown channel' });

  // validações permissivas:
  if (channel === 'telegram') {
    const ok = verifyTelegramSecret(String(req.headers['x-telegram-bot-api-secret-token'] || ''));
    if (!ok) console.warn('⚠️ Telegram secret inválido (permitindo p/ compat)');
  } else {
    const ok = verifyMetaSignature(req.headers['x-hub-signature-256'], raw);
    if (!ok) console.warn('⚠️ Meta assinatura inválida (permitindo)');
  }

  const headersLower = Object.fromEntries(Object.entries(req.headers || {}).map(([k, v]) => [String(k).toLowerCase(), v]));

  // 1) Resolve tenant/queue pelo external_id do canal (já existente)
  const lookupId = extractLookupId(channel, req.body || {}, headersLower);
  const route = await resolveTenantAndQueue({ channel, lookupId });
  console.log('🛣️ rota:', safe(route));
  const tenant = route.tenant;

  // 2) Extrai o resource_id (channel_key) — obrigatório para publicar
  const resourceId = extractResourceId(channel, req.body || {}, headersLower);
  console.log('🔑 resource_id (channel_key):', resourceId);

  // 3) Normaliza o evento (com aggregate_id = usuário SEMPRE)
  const baseEvt = normalizeEvent(channel, req.body || {});

  // 4) WhatsApp: "messages" e/ou "statuses"
  if (channel === 'whatsapp') {
    const val = req.body?.entry?.[0]?.changes?.[0]?.value || {};
    const meta = val?.metadata || {};
    const statuses = Array.isArray(val?.statuses) ? val.statuses : [];
    const messages = Array.isArray(val?.messages) ? val.messages : [];

    // STATUS → fila dedicada (sem idempotência)
    if (tenant && statuses.length) {
      try {
        await publishTenantStatus({ tenant, meta, statuses });
      } catch (e) {
        console.error('❌ publish status falhou:', e?.message);
      }
    }

    // MENSAGENS → publicar apenas se tiver resource_id (sem fallback)
    if (messages.length) {
      if (!resourceId) {
        console.warn('[webhook] WhatsApp: sem resource_id (phone_number_id) — NÃO publicar');
        return reply.code(202).send({ status: 'accepted_noop', reason: 'no_channel_key' });
      }
      try {
        await publishToQueue({
          queue: route.queue || FALLBACK_QUEUE,
          body: {
            ...baseEvt,
            id: `webhook:${crypto.randomUUID()}`,
            tenant_id: tenant || null,
            resource_id: resourceId,           // <- NOVO
            meta: { channel_key: resourceId }, // <- NOVO
            channel_lookup_external_id: lookupId
          },
          headers: {
            'x-channel': channel,
            'x-external-id': String(lookupId || ''),
            'x-tenant': String(tenant || ''),
            'x-channel-key': String(resourceId)
          }
        });
      } catch (e) {
        console.error('❌ publish mensagem falhou:', e?.message);
        return reply.code(202).send({ status: 'accepted_parking' });
      }
    }

    console.log('🏁 done → 200');
    return reply.code(200).send({ status: 'accepted' });
  }

  // Canais não-WA: publicar somente se tiver resource_id (sem fallback)
  if (!resourceId) {
    console.warn(`[webhook] ${channel}: sem resource_id (channel_key) — NÃO publicar`);
    return reply.code(202).send({ status: 'accepted_noop', reason: 'no_channel_key' });
  }

  const evt = {
    ...baseEvt,
    id: `webhook:${crypto.randomUUID()}`,
    tenant_id: route.tenant || null,
    resource_id: resourceId,           // <- NOVO
    meta: { channel_key: resourceId }, // <- NOVO
    channel_lookup_external_id: lookupId
  };

  try {
    await publishToQueue({
      queue: route.queue || FALLBACK_QUEUE,
      body: evt,
      headers: {
        'x-channel': channel,
        'x-external-id': String(lookupId || ''),
        'x-tenant': String(route.tenant || ''),
        'x-channel-key': String(resourceId)
      }
    });
  } catch (e) {
    console.error('❌ publish falhou:', e?.message);
    return reply.code(202).send({ status: 'accepted_parking' });
  }

  console.log('🏁 done → 200');
  return reply.code(200).send({ status: 'accepted' });
});

// boot
(async () => {
  try { await pool.query('SELECT 1'); console.log('✅ Postgres OK'); } catch (e) { console.warn('Postgres pendente:', e?.message); }
  await app.listen({ port: PORT, host: '0.0.0.0' });
  app.log.info('🚀 Webhook listening on :' + PORT);
})();

// graceful shutdown
async function shutdown(r) {
  console.log('🛑 shutdown:', r, now());
  try { await app.close(); } catch {}
  try { await pool.end(); } catch {}
  for (const [url, obj] of amqpPool.entries()) {
    try { await obj?.ch?.close(); } catch {}
    try { await obj?.conn?.close(); } catch {}
    console.log('AMQP fechado:', redact(url));
  }
  process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('unhandledRejection', (e) => console.error('unhandledRejection', e));
process.on('uncaughtException', (e) => console.error('uncaughtException', e));
