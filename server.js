// server.js — Webhook único (Fastify) em CommonJS (require)
// Canais: WhatsApp, Instagram, Facebook (Meta) e Telegram

const Fastify = require('fastify');
const rawBody = require('fastify-raw-body');
const crypto = require('crypto');
const amqplib = require('amqplib');
const pg = require('pg');
const Redis = require('ioredis');

// ====== ENV ======
const PORT = process.env.PORT || 3000;
const META_APP_SECRET = process.env.META_APP_SECRET || '';
const META_VERIFY_TOKEN = process.env.META_VERIFY_TOKEN || '';
const TELEGRAM_SECRET = process.env.TELEGRAM_SECRET || '';
const TELEGRAM_ENDPOINT_ID = process.env.TELEGRAM_ENDPOINT_ID || '';

// Postgres externo
const { Pool } = pg;
const pool = new Pool({
  host: process.env.PGHOST,
  port: process.env.PGPORT,
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  max: 10, idleTimeoutMillis: 10000
});

// Redis interno
const redis = new Redis({ host: process.env.REDIS_HOST || 'localhost', port: process.env.REDIS_PORT || 6379 });

// Rabbit interno (URL default)
const DEFAULT_AMQP_URL = process.env.DEFAULT_AMQP_URL || 'amqp://guest:guest@localhost:5672/';

// ====== Helpers ======
function detectChannel(body, headers) {
  const lh = Object.fromEntries(Object.entries(headers || {}).map(([k,v]) => [k.toLowerCase(), v]));
  if ('x-hub-signature-256' in lh) {
    const obj = body?.object;
    if (obj === 'whatsapp_business_account') return 'whatsapp';
    if (obj === 'instagram') return 'instagram';
    if (obj === 'page') return 'facebook';
  }
  if ('update_id' in (body || {})) return 'telegram';
  return 'unknown';
}

function verifyMetaSignature(sigHeader, raw) {
  if (!META_APP_SECRET) return true; // dev
  if (!sigHeader || !sigHeader.startsWith('sha256=')) return false;
  const received = sigHeader.split('=')[1];
  const expected = crypto.createHmac('sha256', META_APP_SECRET).update(raw).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received));
}

function verifyTelegramSecret(tokenHeader) {
  if (!TELEGRAM_SECRET) return true; // dev
  return tokenHeader === TELEGRAM_SECRET;
}

function extractExternalIds(channel, body) {
  if (channel === 'whatsapp') {
    return {
      wabaId: body?.entry?.[0]?.id || null,
      phoneNumberId: body?.entry?.[0]?.changes?.[0]?.value?.metadata?.phone_number_id || null
    };
  }
  if (channel === 'instagram' || channel === 'facebook') {
    return {
      wabaId: String(body?.entry?.[0]?.id ?? '') || null
    };
  }
  if (channel === 'telegram') {
    return {
      wabaId: TELEGRAM_ENDPOINT_ID || null
    };
  }
  return {};
}

function normalizeEvent(channel, body) {
  const now = Date.now();
  const ids = extractExternalIds(channel, body);
  
  const evt = {
    channel,
    received_at: now,
    tenant_id: ids.wabaId, // WABA ID define o tenant
    event_type: 'message.received',
    aggregate_id: null,
    external_id: ids.phoneNumberId || ids.wabaId, // número ou fallback pro WABA
    payload: body
  };

  try {
    if (channel === 'whatsapp') {
      const change = body.entry?.[0]?.changes?.[0]?.value;
      const msg = change?.messages?.[0];
      evt.aggregate_id = msg?.from || ids.phoneNumberId || null;
    } else if (channel === 'instagram') {
      evt.aggregate_id = String(body.entry?.[0]?.id ?? 'ig');
    } else if (channel === 'facebook') {
      const messaging = body.entry?.[0]?.messaging?.[0];
      evt.aggregate_id = messaging?.sender?.id ?? null;
    } else if (channel === 'telegram') {
      const msg = body.message || body.edited_message || {};
      evt.aggregate_id = String(msg.chat?.id ?? '');
    }
  } catch {}

  return evt;
}

// Cache endpoint -> route
async function resolveRouting({ channel, external_id, tenant_id, event_type }) {
  const key = `endpoint:${channel}:${external_id || 'none'}`;
  const cached = await redis.get(key);
  if (cached) return JSON.parse(cached);

  const client = await pool.connect();
  try {
    const q1 = await client.query(
      `SELECT ce.channel, ce.external_id, ce.tenant_id, ce.cluster_id, ce.queue, ce.exchange, ce.routing_key, c.amqp_url
         FROM channel_endpoints ce
         JOIN clusters c ON c.cluster_id = ce.cluster_id
        WHERE ce.channel = $1 AND ce.external_id = $2
        LIMIT 1`, [channel, external_id]
    );
    if (q1.rows[0]) {
      await redis.set(key, JSON.stringify(q1.rows[0]), 'EX', 120);
      return q1.rows[0];
    }
    const q2 = await client.query(
      `SELECT rr.*, c.amqp_url
         FROM routing_rules rr
         JOIN clusters c ON c.cluster_id = rr.cluster_id
        WHERE (rr.tenant_id = $1 OR rr.tenant_id IS NULL)
          AND rr.channel = $2 AND rr.event_type = $3
        ORDER BY (rr.tenant_id IS NOT NULL) DESC, rr.priority DESC
        LIMIT 1`, [tenant_id, channel, event_type]
    );
    if (q2.rows[0]) {
      await redis.set(key, JSON.stringify(q2.rows[0]), 'EX', 60);
      return q2.rows[0];
    }
    return null;
  } finally {
    client.release();
  }
}

// Publisher com confirm channels
const pools = new Map();
async function getConfirmChannel(amqpUrl) {
  const existing = pools.get(amqpUrl);
  if (existing?.ch && existing.ch.connection?.connection?.stream) return existing.ch;
  const conn = await amqplib.connect(amqpUrl || DEFAULT_AMQP_URL, { heartbeat: 15 });
  const ch = await conn.createConfirmChannel();
  ch.on('error', (e)=>console.error('[amqp ch error]', e));
  conn.on('error', (e)=>console.error('[amqp conn error]', e));
  conn.on('close', ()=>console.warn('[amqp closed]', amqpUrl));
  pools.set(amqpUrl, { conn, ch });
  return ch;
}

async function publish({ amqpUrl, queue, exchange, routingKey, body, headers }) {
  const ch = await getConfirmChannel(amqpUrl || DEFAULT_AMQP_URL);
  const payload = Buffer.from(JSON.stringify(body));
  let ex = exchange || '';
  let rk = routingKey || '';
  if (queue && !exchange) {
    ex = '';
    rk = queue;
  }
  const ok = ch.publish(ex, rk, payload, { persistent: true, headers, contentType: 'application/json' });
  if (!ok) await new Promise(res => ch.once('drain', res));
  await ch.waitForConfirms();
}

// ====== Fastify app ======
const app = Fastify({ logger: true, bodyLimit: 2*1024*1024 });

app.register(rawBody, { field: 'rawBody', global: true, encoding: 'utf8', runFirst: true, routes: [] });

app.get('/healthz', async (_req, reply) => reply.send({ ok: true }));
app.get('/readyz', async (_req, reply) => {
  try {
    await pool.query('SELECT 1');
    await redis.ping();
    const conn = await amqplib.connect(DEFAULT_AMQP_URL, { heartbeat: 10 }); await conn.close();
    return reply.send({ ready: true });
  } catch (e) {
    return reply.code(500).send({ ready: false });
  }
});

app.get('/webhook', async (req, reply) => {
    console.log('📥 GET /webhook recebido:');
  console.log('➡️ Query Params:', JSON.stringify(req.query, null, 2));
  console.log('➡️ Headers:', JSON.stringify(req.headers, null, 2));
  const { 'hub.mode': hubMode, 'hub.challenge': hubChallenge, 'hub.verify_token': hubVerifyToken, hub_mode, hub_challenge, hub_verify_token } = req.query || {};
const mode = hubMode || hub_mode;
const challenge = hubChallenge || hub_challenge;
const verifyToken = hubVerifyToken || hub_verify_token;

  if (mode === 'subscribe' && verifyToken === META_VERIFY_TOKEN) {
    return reply.type('text/plain').send(challenge ?? '');
  }
  return reply.code(403).send({ error: 'verification failed' });
});

app.post('/webhook', async (req, reply) => {
    console.log('📥 POST /webhook recebido:');
  console.log('➡️ Headers:', JSON.stringify(req.headers, null, 2));
  console.log('➡️ Body:', JSON.stringify(req.body, null, 2));
  console.log('➡️ Raw Body:', req.rawBody);
  const raw = Buffer.isBuffer(req.rawBody) ? req.rawBody : Buffer.from(req.rawBody || JSON.stringify(req.body || {}));
  const headers = req.headers || {};
  const channel = detectChannel(req.body, headers);
  if (channel === 'unknown') return reply.code(400).send({ error: 'unknown channel' });

if (channel === 'telegram') {
  // Para manter compatibilidade com seu código atual, não exige secret
  // Apenas loga se vier sem o header
  if (!headers['x-telegram-bot-api-secret-token']) {
    req.log.warn('Telegram sem secret header — permitido para compatibilidade.');
  }
} else if (channel === 'whatsapp' || channel === 'instagram' || channel === 'facebook') {
  // Não valida assinatura para compatibilidade
  if (!headers['x-hub-signature-256']) {
    req.log.warn('Meta webhook sem assinatura — permitido para compatibilidade.');
  }
}


  const evt = normalizeEvent(channel, req.body || {});
  let msgId = channel === 'telegram' ? String(req.body?.update_id ?? '') : String(req.body?.entry?.[0]?.id ?? '');
  if (!msgId || msgId === 'undefined') msgId = crypto.createHash('sha1').update(raw).digest('hex');
  const hit = await redis.set(`idem:${msgId}`, '1', 'EX', 300, 'NX');
  if (hit !== 'OK') return reply.send({ status: 'duplicate' });

  const route = await resolveRouting({
    channel, external_id: evt.external_id, tenant_id: evt.tenant_id, event_type: evt.event_type
  });
  if (!route) return reply.code(422).send({ error: 'no routing for endpoint' });

  try {
    await publish({
      amqpUrl: route.amqp_url || DEFAULT_AMQP_URL,
      queue: route.queue,
      exchange: route.exchange,
      routingKey: route.routing_key,
      body: evt,
      headers: { 'x-idempotency-key': msgId, 'x-channel': channel }
    });
  } catch (e) {
    req.log.error({ e }, 'publish failed');
    return reply.code(202).send({ status: 'accepted_parking' });
  }

  return reply.code(202).send({ status: 'accepted' });
});

app.listen({ port: PORT, host: '0.0.0.0' }).then(() => {
  app.log.info('Webhook listening on :' + PORT);
}).catch((e)=>{ console.error(e); process.exit(1); });
