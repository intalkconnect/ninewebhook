// server.js — Webhook único (Fastify) — usa channel_endpoints(channel, external_id, cluster_id, queue)

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
const TELEGRAM_ENDPOINT_ID = process.env.TELEGRAM_ENDPOINT_ID || '';

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

// Redis (idempotência)
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis',
  port: Number(process.env.REDIS_PORT || 6379),
  lazyConnect: true,
  retryStrategy: (t) => Math.min(t * 50, 1500),
});

// Rabbit
const DEFAULT_AMQP_URL = process.env.DEFAULT_AMQP_URL || 'amqp://guest:guest@rabbitmq:5672/';
const FALLBACK_QUEUE = process.env.FALLBACK_QUEUE || 'hmg.incoming';

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
// ATENÇÃO: isso define o external_id que será usado no SELECT ao Postgres.
function extractLookupId(channel, body, headers) {
  if (channel === 'whatsapp' || channel === 'instagram' || channel === 'facebook') {
    // *** COMO VOCÊ PEDIU: usar SEMPRE entry[0].id ***
    return body?.entry?.[0]?.id || null;
  }
  if (channel === 'telegram') {
    // *** COMO VOCÊ PEDIU: usar o header x-telegram-bot-api-secret-token ***
    return headers['x-telegram-bot-api-secret-token'] || null;
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

// ========= Roteamento via Postgres =========
// Usa TABELA: channel_endpoints(channel, external_id, cluster_id, queue)
// -> retorna { queue } ou null
async function resolveQueue({ channel, lookupId }) {
  console.log(`🔎 resolveQueue: channel=${channel} lookupId=${lookupId}`);
  if (!lookupId) {
    console.warn('⚠️ lookupId vazio — fallback');
    return { queue: FALLBACK_QUEUE, source: 'fallback' };
  }

  const key = `ce:${channel}:${lookupId}`;
  try {
    const cached = await redis.get(key);
    if (cached) {
      console.log(`💾 cache HIT ${key}`);
      return JSON.parse(cached);
    }
  } catch (e) {
    console.warn('Redis GET falhou (segue sem cache):', e?.message);
  }

  const client = await pool.connect();
  try {
    const sql = `
      SELECT queue
      FROM channel_endpoints
      WHERE channel = $1 AND external_id = $2
      LIMIT 1
    `;
    const { rows } = await client.query(sql, [channel, String(lookupId)]);
    if (rows[0]?.queue) {
      const res = { queue: rows[0].queue, source: 'db' };
      try { await redis.set(key, JSON.stringify(res), 'EX', 120); } catch {}
      return res;
    }
    console.warn('⚠️ NENHUMA fila encontrada no DB — fallback');
    return { queue: FALLBACK_QUEUE, source: 'fallback' };
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

  // default exchange => routingKey=queue
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
    const ok = verifyTelegramSecret(req.headers['x-telegram-bot-api-secret-token']);
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
      // IG/FB: usa timestamp/mid se existir — ou hash do raw
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

  // monta evento e resolve FILA por external_id:
  const evt = normalizeEvent(channel, req.body || {});
  const lookupId = extractLookupId(channel, req.body || {}, Object.fromEntries(
    Object.entries(req.headers || {}).map(([k, v]) => [String(k).toLowerCase(), v])
  ));

  console.log('🔎 resolveQueue: channel=%s external_id(lookup)=%s', channel, lookupId);
  const route = await resolveQueue({ channel, lookupId });
  console.log('🛣️ rota:', safe(route));

  try {
    await publishToQueue({
      queue: route.queue || FALLBACK_QUEUE,
      body: {
        ...evt,
        channel_lookup_external_id: lookupId, // informação útil no payload
      },
      headers: {
        'x-idempotency-key': idemKey,
        'x-channel': channel,
        'x-external-id': String(lookupId || '')
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
