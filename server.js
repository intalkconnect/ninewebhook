// server.js — Webhook único (Fastify) — resolve fila como <subdomain>.incoming via public.tenants

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

// ========= Utils =========
const now = () => new Date().toISOString();
const safe = (o) => { try { return JSON.stringify(o, null, 2); } catch { return '[unserializable]'; } };
const redact = (u) => String(u || '').replace(/(\/\/[^:]+:)([^@]+)(@)/, '$1***$3');

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
  if (channel === 'whatsapp' || channel === 'instagram' || channel === 'facebook') {
    // Meta: sempre entry[0].id (ex.: phone_number_id para WA)
    return body?.entry?.[0]?.id || null;
  }
  if (channel === 'telegram') {
    // Telegram: header do "bot api secret token"
    return headersLower['x-telegram-bot-api-secret-token'] || null;
  }
  return null;
}

// ========= Normalização de evento (para payload) =========
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
// 1) tenta descobrir o tenant por external_id em public.tenants
// 2) se achar, retorna queue = <subdomain>.incoming
// 3) senão, tenta channel_endpoints(channel, external_id) -> queue
// 4) senão, FALLBACK_QUEUE
// 1) tenta descobrir o tenant por external_id em public.tenants
// 2) se achar -> queue = <subdomain>.incoming
// 3) se não achar -> FALLBACK_QUEUE (sem channel_endpoints)
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
    const col =
      channel === 'whatsapp' ? 'whatsapp_external_id'  :
      channel === 'telegram' ? 'telegram_external_id'  :
      channel === 'instagram'? 'instagram_external_id' :
      channel === 'facebook' ? 'facebook_external_id'  :
      null;

    if (col) {
      const sqlTenant = `
        SELECT subdomain
          FROM public.tenants
         WHERE ${col} = $1
         LIMIT 1
      `;
      const t = await client.query(sqlTenant, [String(lookupId)]);
      if (t.rows[0]?.subdomain) {
        const tenant = t.rows[0].subdomain;
        const queue  = (QUEUE_TEMPLATE || '%s.incoming').replace('%s', tenant);
        const res = { queue, source: 'tenants', tenant };
        try { await redis.set(cacheKey, JSON.stringify(res), 'EX', 300); } catch {}
        return res;
      }
    }

    // Sem channel_endpoints: caiu aqui, usa fila padrão
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
  console.log(`📤 Publicando no Rabbit (default exchange): queue=${queue}
  headers=${safe(headers)}
  payload_len=${payload.length}`);

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
  console.log('✅ confirmado pelo RabbitMQ');
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

  // idempotência
  let idemKey;
  try {
    if (channel === 'whatsapp') {
      const msgId = req.body?.entry?.[0]?.changes?.[0]?.value?.messages?.[0]?.id
                 || req.body?.entry?.[0]?.changes?.[0]?.value?.statuses?.[0]?.id;
      idemKey = msgId ? `wa:${msgId}` : null;
    } else if (channel === 'telegram') {
      const up = req.body?.update_id;
      idemKey = (up != null) ? `tg:${String(up)}` : null;
    } else {
      // IG/FB: usa hash do raw
      idemKey = crypto.createHash('sha1').update(raw).digest('hex');
    }
  } catch {}
  if (!idemKey) idemKey = crypto.createHash('sha1').update(raw).digest('hex');

  const wrote = await redis.set(`idem:${idemKey}`, '1', 'EX', 300, 'NX');
  if (wrote !== 'OK') {
    console.log('♻️ duplicate, idemKey=', idemKey);
    return reply.send({ status: 'duplicate' });
  }
  console.log('🔑 idempotency:', idemKey);

  // monta evento e resolve TENANT -> QUEUE
  const evt = normalizeEvent(channel, req.body || {});
  const headersLower = Object.fromEntries(Object.entries(req.headers || {}).map(([k, v]) => [String(k).toLowerCase(), v]));
  const lookupId = extractLookupId(channel, req.body || {}, headersLower);

  const route = await resolveTenantAndQueue({ channel, lookupId });
  console.log('🛣️ rota:', safe(route));

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
