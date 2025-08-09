// server.js — Webhook único (Fastify) em CommonJS (require)
// Canais: WhatsApp, Instagram, Facebook (Meta) e Telegram
// Usa channel_endpoints (channel, external_id, cluster_id, queue) + clusters(amqp_url)
// Publica direto em fila (default exchange)

'use strict';

const Fastify = require('fastify');
const rawBody = require('fastify-raw-body');
const crypto = require('crypto');
const amqplib = require('amqplib');
const pg = require('pg');
const Redis = require('ioredis');

// ============ ENV ============
const PORT = Number(process.env.PORT) || 3000;

// Meta/Telegram (validação opcional — permissiva)
const META_APP_SECRET   = process.env.META_APP_SECRET   || '';
const META_VERIFY_TOKEN = process.env.META_VERIFY_TOKEN || '';
const TELEGRAM_SECRET   = process.env.TELEGRAM_SECRET   || '';
const TELEGRAM_ENDPOINT_ID = process.env.TELEGRAM_ENDPOINT_ID || '';

// Redis
const REDIS_HOST = process.env.REDIS_HOST || 'localhost';
const REDIS_PORT = Number(process.env.REDIS_PORT || 6379);

// Rabbit fallback
const DEFAULT_AMQP_URL = process.env.DEFAULT_AMQP_URL || 'amqp://guest:guest@localhost:5672/';
const INCOMING_QUEUE   = process.env.INCOMING_QUEUE   || ''; // se setado, usa SEMPRE esta fila
const INCOMING_PREFIX  = process.env.INCOMING_PREFIX  || ''; // se setado, usa <prefix>.<clientId>

// Postgres (para resolver fila por channel_endpoints)
const {
  PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD
} = process.env;

const { Pool } = pg;
const pool = new Pool({
  host: PGHOST,
  port: Number(PGPORT || 5432),
  database: PGDATABASE,
  user: PGUSER,
  password: PGPASSWORD,
  max: 10,
  idleTimeoutMillis: 10000
});

const redis = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT,
  lazyConnect: true,
  retryStrategy: (times) => Math.min(times * 50, 2000)
});

// ============ Utils ============
const nowIso = () => new Date().toISOString();
const safe = (o) => { try { return JSON.stringify(o, null, 2); } catch { return '[unserializable]'; } };
const redact = (url) => String(url || '').replace(/(\/\/[^:]+:)([^@]+)(@)/, '$1***$3');

// ============ Canal & IDs ============
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

function verifyMetaSignature(sig256, raw) {
  if (!META_APP_SECRET) return true; // permissivo em dev
  if (!sig256 || !String(sig256).startsWith('sha256=')) return false;
  const received = String(sig256).split('=')[1];
  const expected = crypto.createHmac('sha256', META_APP_SECRET).update(raw).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received)); }
  catch { return false; }
}

function extractClientId(channel, body) {
  try {
    if (channel === 'whatsapp') {
      // melhor clientId = phone_number_id
      const pnid = body?.entry?.[0]?.changes?.[0]?.value?.metadata?.phone_number_id;
      return pnid || (body?.entry?.[0]?.id || null);
    }
    if (channel === 'instagram' || channel === 'facebook') {
      return String(body?.entry?.[0]?.id ?? '') || null;
    }
    if (channel === 'telegram') {
      return TELEGRAM_ENDPOINT_ID || null; // 1 endpoint por bot
    }
  } catch {}
  return null;
}

function computeIdempotencyKey(channel, body, raw) {
  try {
    if (channel === 'whatsapp') {
      const chg = body?.entry?.[0]?.changes?.[0]?.value;
      const mid = chg?.messages?.[0]?.id || chg?.statuses?.[0]?.id;
      if (mid) return `wa:${mid}`;
    }
    if (channel === 'instagram' || channel === 'facebook') {
      const msg = body?.entry?.[0]?.messaging?.[0];
      const mid = msg?.message?.mid || msg?.delivery?.mids?.[0] || msg?.timestamp;
      if (mid) return `meta:${mid}`;
    }
    if (channel === 'telegram') {
      const up = body?.update_id;
      if (up != null) return `tg:${String(up)}`;
    }
  } catch {}
  return `raw:${crypto.createHash('sha1').update(raw).digest('hex')}`;
}

function normalizeEvent(channel, body) {
  const clientId = extractClientId(channel, body);
  const evt = {
    channel,
    received_at: Date.now(),
    client_id: clientId,         // << chave para roteamento por fila
    event_type: 'message.received',
    payload: body
  };
  // opcional: aggregate_id para auditoria
  try {
    if (channel === 'whatsapp') {
      const change = body?.entry?.[0]?.changes?.[0]?.value;
      const msg = change?.messages?.[0];
      evt.aggregate_id = msg?.from || clientId || null;
    } else if (channel === 'instagram') {
      evt.aggregate_id = String(body?.entry?.[0]?.id ?? 'ig');
    } else if (channel === 'facebook') {
      const messaging = body?.entry?.[0]?.messaging?.[0];
      evt.aggregate_id = messaging?.sender?.id ?? null;
    } else if (channel === 'telegram') {
      const msg = body?.message || body?.edited_message || {};
      evt.aggregate_id = msg?.chat?.id != null ? String(msg.chat.id) : null;
    }
  } catch {}
  return evt;
}

// ============ Resolvedor de fila (DB -> cache -> env) ============
async function resolveQueueAndAMQP(channel, clientId) {
  console.log(`🔎 resolveQueueAndAMQP: channel=${channel} clientId=${clientId}`);

  // 1) se INCOMING_QUEUE definido, usa sempre ele (ignora DB)
  if (INCOMING_QUEUE) {
    return { queue: INCOMING_QUEUE, amqp_url: DEFAULT_AMQP_URL, source: 'env:INCOMING_QUEUE' };
  }

  // 2) tenta cache redis
  const cacheKey = `ce:${channel}:${clientId || 'none'}`;
  try {
    const cached = await redis.get(cacheKey);
    if (cached) {
      const parsed = JSON.parse(cached);
      console.log(`💾 cache HIT ${cacheKey} ->`, parsed);
      return { ...parsed, source: 'cache' };
    }
  } catch (e) {
    console.warn('redis GET falhou (segue sem cache):', e?.message);
  }

  // 3) DB — channel_endpoints + clusters
  if (clientId) {
    const client = await pool.connect();
    try {
      const q = await client.query(
        `SELECT ce.queue, c.amqp_url
           FROM channel_endpoints ce
           JOIN clusters c ON c.cluster_id = ce.cluster_id
          WHERE ce.channel = $1 AND ce.external_id = $2
          LIMIT 1`,
        [channel, clientId]
      );
      if (q.rowCount) {
        const found = { queue: q.rows[0].queue, amqp_url: q.rows[0].amqp_url || DEFAULT_AMQP_URL };
        try { await redis.set(cacheKey, JSON.stringify(found), 'EX', 120); } catch {}
        console.log('✅ DB route:', found);
        return { ...found, source: 'db' };
      }
      console.warn('⚠️ DB não encontrou rota (channel_endpoints vazio p/ esse clientId)');
    } catch (e) {
      console.error('❌ query channel_endpoints falhou:', e?.message);
    } finally {
      client.release();
    }
  }

  // 4) Fallback por prefixo: <prefix>.<clientId>
  if (INCOMING_PREFIX && clientId) {
    const qname = `${INCOMING_PREFIX}.${clientId}`;
    console.log('↩️ fallback INCOMING_PREFIX ->', qname);
    return { queue: qname, amqp_url: DEFAULT_AMQP_URL, source: 'env:INCOMING_PREFIX' };
  }

  // 5) Fallback final
  console.log('↩️ fallback padrão -> hmg.incoming');
  return { queue: 'hmg.incoming', amqp_url: DEFAULT_AMQP_URL, source: 'default' };
}

// ============ AMQP (publish em fila) ============
const amqpPools = new Map();
async function getConfirmChannel(amqpUrl) {
  const url = amqpUrl || DEFAULT_AMQP_URL;
  const cached = amqpPools.get(url);
  if (cached?.ch && !cached.ch.connectionClosed) return cached.ch;

  console.log(`📡 Conectando Rabbit: ${redact(url)}`);
  const conn = await amqplib.connect(url, { heartbeat: 15 });
  const ch = await conn.createConfirmChannel();
  ch.on('error', (e) => console.error('[amqp ch error]', e));
  ch.on('close', () => console.warn('[amqp ch closed]'));
  conn.on('error', (e) => console.error('[amqp conn error]', e));
  conn.on('close', () => {
    console.warn('[amqp conn closed]', redact(url));
    const obj = amqpPools.get(url);
    if (obj) obj.ch.connectionClosed = true;
  });
  amqpPools.set(url, { conn, ch });
  return ch;
}

async function publishToQueue({ amqpUrl, queue, body, headers }) {
  const ch = await getConfirmChannel(amqpUrl);
  await ch.assertQueue(queue, { durable: true });

  const payloadStr = JSON.stringify(body);
  const buf = Buffer.from(payloadStr);

  console.log(`📤 Publicando em fila (default exchange):
    queue=${queue}
    headers=${safe(headers)}
    payload_len=${buf.length}
  `);

  const ok = ch.publish('', queue, buf, {
    persistent: true,
    headers: headers || {},
    contentType: 'application/json'
  });
  if (!ok) {
    console.warn('⚠️ buffer cheio — aguardando drain...');
    await new Promise((res) => ch.once('drain', res));
  }
  await ch.waitForConfirms();
  console.log('✅ confirmado pelo RabbitMQ');
}

// ============ Fastify ============
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

// Health/Ready
app.get('/healthz', async (_req, reply) => reply.send({ ok: true, ts: nowIso() }));
app.get('/readyz', async (_req, reply) => {
  try {
    await pool.query('SELECT 1');
    try { await redis.ping(); } catch (e) { throw new Error('redis: ' + e.message); }
    const c = await amqplib.connect(DEFAULT_AMQP_URL, { heartbeat: 10 });
    await c.close();
    return reply.send({ ready: true, ts: nowIso() });
  } catch (e) {
    return reply.code(500).send({ ready: false, error: e?.message, ts: nowIso() });
  }
});

// Verificação Meta
app.get('/webhook', async (req, reply) => {
  const q = req.query || {};
  const mode = q['hub.mode'] || q.hub_mode;
  const challenge = q['hub.challenge'] || q.hub_challenge;
  const token = q['hub.verify_token'] || q.hub_verify_token;

  if (mode === 'subscribe' && token === META_VERIFY_TOKEN) {
    req.log.info('✅ Meta verify OK');
    return reply.type('text/plain').send(challenge ?? '');
  }
  req.log.warn('❌ Meta verify FAIL');
  return reply.code(403).send({ error: 'verification failed' });
});

// Webhook principal
app.post('/webhook', async (req, reply) => {
  console.log('\n===== 📥 POST /webhook =====');
  console.log('🕒', nowIso());
  console.log('➡️ Headers:', safe(req.headers));
  console.log('➡️ Body:', safe(req.body));

  const raw = Buffer.isBuffer(req.rawBody)
    ? req.rawBody
    : Buffer.from(
        typeof req.rawBody === 'string' ? req.rawBody : JSON.stringify(req.body || {})
      );

  const channel = detectChannel(req.body, req.headers);
  console.log('🎯 channel:', channel);

  if (channel === 'unknown') {
    console.warn('❌ canal desconhecido');
    return reply.code(400).send({ error: 'unknown channel' });
  }

  // Validações permissivas (só loga)
  if (channel === 'telegram') {
    if (!req.headers['x-telegram-bot-api-secret-token']) {
      console.warn('⚠️ Telegram sem secret header (permitido)');
    } else if (TELEGRAM_SECRET && req.headers['x-telegram-bot-api-secret-token'] !== TELEGRAM_SECRET) {
      console.warn('❌ Telegram secret inválido (permitindo para teste)');
    }
  } else {
    const ok = verifyMetaSignature(req.headers['x-hub-signature-256'], raw);
    if (!ok) console.warn('⚠️ Meta assinatura inválida (permitindo)');
  }

  const evt = normalizeEvent(channel, req.body || {});
  const msgId = computeIdempotencyKey(channel, req.body || {}, raw);
  console.log('🔑 idempotency:', msgId);

  // Idempotência
  try {
    const wrote = await redis.set(`idem:${msgId}`, '1', 'EX', 300, 'NX');
    if (wrote !== 'OK') {
      console.log('♻️ duplicate');
      return reply.send({ status: 'duplicate' });
    }
  } catch (e) {
    console.warn('redis set idem falhou — seguindo:', e?.message);
  }

  // Descobre fila + AMQP url
  const clientId = evt.client_id || null;
  const route = await resolveQueueAndAMQP(channel, clientId);
  console.log('🛣️ rota:', route);

  try {
    await publishToQueue({
      amqpUrl: route.amqp_url || DEFAULT_AMQP_URL,
      queue: route.queue,
      body: evt,
      headers: { 'x-idempotency-key': msgId, 'x-channel': channel, 'x-client-id': clientId || '' }
    });
  } catch (e) {
    console.error('❌ publish falhou:', e?.message);
    return reply.code(202).send({ status: 'accepted_parking' });
  }

  console.log('🏁 done → 202');
  return reply.code(202).send({ status: 'accepted' });
});

// Boot
(async () => {
  console.log('🌐 boot...', nowIso());
  try { await redis.connect(); console.log('✅ redis OK'); } catch (e) { console.warn('redis pendente:', e?.message); }
  try { await pool.query('SELECT 1'); console.log('✅ postgres OK'); } catch (e) { console.warn('postgres pendente:', e?.message); }
  try {
    await app.listen({ port: PORT, host: '0.0.0.0' });
    app.log.info('🚀 listening on :' + PORT);
  } catch (e) {
    console.error('❌ falha ao subir:', e);
    process.exit(1);
  }
})();

// Shutdown
async function shutdown(reason) {
  console.log(`🛑 shutdown ${reason} @ ${nowIso()}`);
  try { await app.close(); } catch {}
  try { await pool.end(); } catch {}
  try { await redis.quit(); } catch {}
  for (const [url, obj] of amqpPools.entries()) {
    try { await obj?.ch?.close(); } catch {}
    try { await obj?.conn?.close(); } catch {}
    console.log('AMQP fechado:', redact(url));
  }
  process.exit(0);
}
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('unhandledRejection', (e) => console.error('unhandledRejection', e));
process.on('uncaughtException',  (e) => console.error('uncaughtException', e));
