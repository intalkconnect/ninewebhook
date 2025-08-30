// server.js — Webhook único (Fastify)
// Roteia MENSAGENS para <subdomain>.incoming e STATUS para <subdomain>.status
// - Resolução de tenant:
//   1) public.tenant_channel_connections(channel, external_id)    // WhatsApp -> phone_number_id
//   2) public.tenant_channel_connections(channel, account_id)     // WhatsApp -> WABA_ID
//   3) public.tenants.*_external_id (LEGADO)
//
// ⚠️ Mensagens e Status têm idempotência separada:
//    - Mensagens: por msg.id (wamid de "messages")
//    - Status: por (status.id + status + timestamp)

'use strict';

const Fastify = require('fastify');
const rawBody = require('fastify-raw-body');
const crypto = require('crypto');
const amqplib = require('amqplib');
const pg = require('pg');
const Redis = require('ioredis');

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

// Redis (idempotência + cache)
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis',
  port: Number(process.env.REDIS_PORT || 6379),
  lazyConnect: true,
  retryStrategy: (t) => Math.min(t * 50, 1500),
});

// Rabbit
const DEFAULT_AMQP_URL = process.env.DEFAULT_AMQP_URL || 'amqp://guest:guest@rabbitmq:5672/';
const FALLBACK_QUEUE   = process.env.FALLBACK_QUEUE   || 'hmg.incoming';

// Template de fila (ex.: "%s.incoming" -> "hmg.incoming")
const QUEUE_TEMPLATE = process.env.QUEUE_TEMPLATE || '%s.incoming';

// ✅ NOVO: fila de STATUS por tenant (ex.: "%s.status" -> "hmg.status")
const STATUS_QUEUE_TEMPLATE = process.env.STATUS_QUEUE_TEMPLATE || '%s.status';
// TTL (segundos) para idempotência de STATUS (WA pode reenviar dentro de ~20min)
const STATUS_IDEMP_TTL = parseInt(process.env.STATUS_IDEMP_TTL || '3600', 10);

// ========= Utils =========
const now = () => new Date().toISOString();
const safe = (o) => { try { return JSON.stringify(o, null, 2); } catch { return '[unserializable]'; } };
const redact = (u) => String(u || '').replace(/(\/\/[^:]+:)([^@]+)(@)/, '$1***$3');
const normMsisdn = (s='') => String(s).replace(/\D/g, '');

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
// ATENÇÃO: isto define o external_id usado para localizar o tenant
function extractLookupId(channel, body, headersLower) {
  if (channel === 'whatsapp') {
    const entry  = body?.entry?.[0];
    const change = entry?.changes?.[0]?.value;
    // 1) preferir phone_number_id (mais granular por número)
    const phoneId = change?.metadata?.phone_number_id;
    if (phoneId) return phoneId;
    // 2) fallback: WABA_ID
    const wabaId = entry?.id;
    if (wabaId) return wabaId;
    return null;
  }
  if (channel === 'instagram') {
    return body?.entry?.[0]?.id || null;
  }
  if (channel === 'facebook') {
    const msg = body?.entry?.[0]?.messaging?.[0];
    return msg?.sender?.id || body?.entry?.[0]?.id || null;
  }
  if (channel === 'telegram') {
    return headersLower['x-telegram-bot-api-secret-token'] || null;
  }
  return null;
}

// ========= Normalização de evento (para payload de mensagem) =========
function normalizeEvent(channel, body) {
  const out = {
    channel,
    received_at: Date.now(),
    event_type: 'message.received',
    aggregate_id: null,
    payload: body
  };

  try {
    if (channel === 'whatsapp') {
      const change = body?.entry?.[0]?.changes?.[0]?.value;
      const msg = change?.messages?.[0];
      out.aggregate_id = msg?.from || change?.metadata?.phone_number_id || null;
    } else if (channel === 'instagram') {
      out.aggregate_id = String(body?.entry?.[0]?.id ?? 'ig');
    } else if (channel === 'facebook') {
      const m = body?.entry?.[0]?.messaging?.[0];
      out.aggregate_id = m?.sender?.id ?? null;
    } else if (channel === 'telegram') {
      const m = body?.message || body?.edited_message || {};
      out.aggregate_id = m?.chat?.id != null ? String(m.chat.id) : null;
    }
  } catch (e) {
    console.warn('normalizeEvent erro:', e?.message);
  }
  return out;
}

// ========= Roteamento via Postgres/Redis =========
async function resolveTenantAndQueue({ channel, lookupId }) {
  console.log(`🔎 resolveTenantAndQueue: channel=${channel} lookupId=${lookupId}`);

  if (!lookupId) {
    console.warn('⚠️ lookupId vazio — usando fallback');
    return { queue: FALLBACK_QUEUE, source: 'fallback', tenant: null };
  }

  const cacheKey = `tenantByExt:${channel}:${lookupId}`;
  try {
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);
  } catch (e) {
    console.warn('Redis GET falhou (segue sem cache):', e?.message);
  }

  const client = await pool.connect();
  try {
    // 1) Match por external_id (ex.: WhatsApp -> phone_number_id)
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
      try { await redis.set(cacheKey, JSON.stringify(res), 'EX', 300); } catch {}
      return res;
    }

    // 2) Fallback por account_id (ex.: WABA_ID)
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
      try { await redis.set(cacheKey, JSON.stringify(res), 'EX', 300); } catch {}
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
        try { await redis.set(cacheKey, JSON.stringify(res), 'EX', 120); } catch {}
        return res;
      }
    }

    // Fallback final
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

// ✅ NOVO: publisher de STATUS do tenant (fila dedicada)
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

    // idempotência por evento (wamid + status + timestamp)
    const idemKey = `wa:status:${id}:${s}:${ts}`;
    try {
      const wrote = await redis.set(`idem:${idemKey}`, '1', 'EX', STATUS_IDEMP_TTL, 'NX');
      if (wrote !== 'OK') {
        console.log('♻️ duplicate (status), idemKey=', idemKey);
        continue;
      }
    } catch (e) {
      console.warn('Redis status NX falhou (segue):', e?.message);
      // mesmo sem cache, seguimos publicando
    }

    const payload = {
      kind: 'waba_status',
      tenant,
      channel: 'whatsapp',
      phone_number_id: meta?.phone_number_id,
      display_phone_number: meta?.display_phone_number,
      status: {
        id: id,                                  // wamid
        status: s,                               // sent|delivered|read|failed
        timestamp: ts,                           // epoch (string)
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
    try { await redis.ping(); } catch (e) { throw new Error('redis: ' + e?.message); }
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

  // Resolve tenant/queue pelo external_id do canal
  const headersLower = Object.fromEntries(Object.entries(req.headers || {}).map(([k, v]) => [String(k).toLowerCase(), v]));
  const lookupId = extractLookupId(channel, req.body || {}, headersLower);
  const route = await resolveTenantAndQueue({ channel, lookupId });
  console.log('🛣️ rota:', safe(route));
  const tenant = route.tenant;

  // ✅ WhatsApp: pode trazer "messages" (conteúdo) e/ou "statuses" (entrega/leitura)
  if (channel === 'whatsapp') {
    const val = req.body?.entry?.[0]?.changes?.[0]?.value || {};
    const meta = val?.metadata || {};
    const statuses = Array.isArray(val?.statuses) ? val.statuses : [];
    const messages = Array.isArray(val?.messages) ? val.messages : [];

    // 1) Publique STATUS na fila dedicada do tenant (não interfere na incoming)
    if (tenant && statuses.length) {
      try {
        await publishTenantStatus({ tenant, meta, statuses });
      } catch (e) {
        console.error('❌ publish status falhou:', e?.message);
        // não bloqueia o fluxo; seguimos com mensagens se houver
      }
    }

    // 2) Publique MENSAGENS na fila padrão do tenant (incoming)
    if (messages.length) {
      // idempotência de MENSAGEM por msg.id
      const msg = messages[0]; // normalmente vem 1 por webhook
      let idemKey = '';
      try {
        if (msg?.id) idemKey = `wa:msg:${msg.id}`;
      } catch {}
      if (!idemKey) {
        // fallback hash do raw (apenas para evitar reprocesso de pacotes idênticos)
        idemKey = 'wa:msg:' + crypto.createHash('sha1').update(raw).digest('hex');
      }

      const wrote = await redis.set(`idem:${idemKey}`, '1', 'EX', 300, 'NX');
      if (wrote !== 'OK') {
        console.log('♻️ duplicate (message), idemKey=', idemKey);
        return reply.send({ status: 'duplicate' });
      }

      const evt = normalizeEvent(channel, req.body || {});
      try {
        await publishToQueue({
          queue: route.queue || FALLBACK_QUEUE,
          body: {
            ...evt,
            channel_lookup_external_id: lookupId,
            tenant: tenant || null,
          },
          headers: {
            'x-idempotency-key': idemKey,
            'x-channel': channel,
            'x-external-id': String(lookupId || ''),
            'x-tenant': String(tenant || '')
          }
        });
      } catch (e) {
        console.error('❌ publish mensagem falhou:', e?.message);
        return reply.code(202).send({ status: 'accepted_parking' });
      }
    }

    console.log('🏁 done → 202');
    return reply.code(202).send({ status: 'accepted' });
  }

  // Canais não-WA: mantém fluxo antigo (uma única publicação no incoming)
  // idempotência genérica
  let idemKey;
  try {
    if (channel === 'telegram') {
      const up = req.body?.update_id;
      idemKey = (up != null) ? `tg:${String(up)}` : null;
    } else {
      idemKey = crypto.createHash('sha1').update(raw).digest('hex');
    }
  } catch {}
  if (!idemKey) idemKey = crypto.createHash('sha1').update(raw).digest('hex');

  const wrote = await redis.set(`idem:${idemKey}`, '1', 'EX', 300, 'NX');
  if (wrote !== 'OK') {
    console.log('♻️ duplicate, idemKey=', idemKey);
    return reply.send({ status: 'duplicate' });
  }

  const evt = normalizeEvent(channel, req.body || {});
  try {
    await publishToQueue({
      queue: route.queue || FALLBACK_QUEUE,
      body: {
        ...evt,
        channel_lookup_external_id: lookupId,
        tenant: route.tenant || null,
      },
      headers: {
        'x-idempotency-key': idemKey,
        'x-channel': channel,
        'x-external-id': String(lookupId || ''),
        'x-tenant': String(route.tenant || '')
      }
    });
  } catch (e) {
    console.error('❌ publish falhou:', e?.message);
    return reply.code(202).send({ status: 'accepted_parking' });
  }

  console.log('🏁 done → 202');
  return reply.code(202).send({ status: 'accepted' });
});

// boot
(async () => {
  try { await redis.connect(); console.log('✅ Redis conectado'); } catch (e) { console.warn('Redis pendente:', e?.message); }
  try { await pool.query('SELECT 1'); console.log('✅ Postgres OK'); } catch (e) { console.warn('Postgres pendente:', e?.message); }
  await app.listen({ port: PORT, host: '0.0.0.0' });
  app.log.info('🚀 Webhook listening on :' + PORT);
})();

// graceful shutdown
async function shutdown(r) {
  console.log('🛑 shutdown:', r, now());
  try { await app.close(); } catch {}
  try { await pool.end(); } catch {}
  try { await redis.quit(); } catch {}
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
