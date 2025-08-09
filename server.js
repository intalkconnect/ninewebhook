// server.js — Webhook único (Fastify) em CommonJS (require)
// Canais: WhatsApp, Instagram, Facebook (Meta) e Telegram
// Objetivo: máximo de logs para rastrear recepção -> roteamento -> publicação RabbitMQ

'use strict';

const Fastify = require('fastify');
const rawBody = require('fastify-raw-body');
const crypto = require('crypto');
const amqplib = require('amqplib');
const pg = require('pg');
const Redis = require('ioredis');

// ============ ENV ============
const PORT = Number(process.env.PORT) || 3000;
const META_APP_SECRET = process.env.META_APP_SECRET || '';
const META_VERIFY_TOKEN = process.env.META_VERIFY_TOKEN || '';
const TELEGRAM_SECRET = process.env.TELEGRAM_SECRET || '';
const TELEGRAM_ENDPOINT_ID = process.env.TELEGRAM_ENDPOINT_ID || '';

// Postgres externo
const { Pool } = pg;
const pool = new Pool({
  host: process.env.PGHOST,
  port: Number(process.env.PGPORT) || 5432,
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  max: 10,
  idleTimeoutMillis: 10000
});

// Redis interno
const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: Number(process.env.REDIS_PORT) || 6379,
  lazyConnect: true,
  retryStrategy: (times) => Math.min(times * 50, 2000)
});

// Rabbit interno (URL default)
const DEFAULT_AMQP_URL = process.env.DEFAULT_AMQP_URL || 'amqp://guest:guest@localhost:5672/';

// ============ Utils ============
const nowIso = () => new Date().toISOString();
const safeJson = (obj) => {
  try { return JSON.stringify(obj, null, 2); } catch { return '[unserializable]'; }
};

// ============ Helpers ============
function detectChannel(body, headers) {
  const lh = Object.fromEntries(Object.entries(headers || {}).map(([k, v]) => [String(k).toLowerCase(), v]));
  if ('x-hub-signature-256' in lh) {
    const obj = body?.object;
    if (obj === 'whatsapp_business_account') return 'whatsapp';
    if (obj === 'instagram') return 'instagram';
    if (obj === 'page') return 'facebook';
  }
  if (body && typeof body === 'object' && 'update_id' in body) return 'telegram';
  return 'unknown';
}

function verifyMetaSignature(sigHeader, raw) {
  if (!META_APP_SECRET) return true; // modo dev/compat
  if (!sigHeader || !String(sigHeader).startsWith('sha256=')) return false;
  const received = String(sigHeader).split('=')[1];
  const expected = crypto.createHmac('sha256', META_APP_SECRET).update(raw).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received));
  } catch {
    return false;
  }
}

function verifyTelegramSecret(tokenHeader) {
  if (!TELEGRAM_SECRET) return true; // modo dev/compat
  return tokenHeader === TELEGRAM_SECRET;
}

function extractExternalIds(channel, body) {
  try {
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
  } catch (e) {
    console.error('extractExternalIds erro:', e);
    return {};
  }
}

function normalizeEvent(channel, body) {
  const now = Date.now();
  const ids = extractExternalIds(channel, body);

  const evt = {
    channel,
    received_at: now,
    tenant_id: ids.wabaId || null, // WABA ID define o tenant (ou null)
    event_type: 'message.received',
    aggregate_id: null,
    external_id: ids.phoneNumberId || ids.wabaId || null, // número ou fallback p/ WABA
    payload: body
  };

  try {
    if (channel === 'whatsapp') {
      const change = body?.entry?.[0]?.changes?.[0]?.value;
      const msg = change?.messages?.[0];
      evt.aggregate_id = msg?.from || ids.phoneNumberId || null;
    } else if (channel === 'instagram') {
      evt.aggregate_id = String(body?.entry?.[0]?.id ?? 'ig');
    } else if (channel === 'facebook') {
      const messaging = body?.entry?.[0]?.messaging?.[0];
      evt.aggregate_id = messaging?.sender?.id ?? null;
    } else if (channel === 'telegram') {
      const msg = body?.message || body?.edited_message || {};
      evt.aggregate_id = msg?.chat?.id != null ? String(msg.chat.id) : null;
    }
  } catch (e) {
    console.warn('normalizeEvent catch:', e);
  }

  return evt;
}

// Cache endpoint -> route
async function resolveRouting({ channel, external_id, tenant_id, event_type }) {
  console.log(`🔍 [${nowIso()}] resolveRouting START
  channel=${channel}
  external_id=${external_id}
  tenant_id=${tenant_id}
  event_type=${event_type}
  `);

  const key = `endpoint:${channel}:${external_id || 'none'}`;
  try {
    const cached = await redis.get(key);
    if (cached) {
      console.log(`💾 Cache HIT para chave ${key}`);
      return JSON.parse(cached);
    }
  } catch (e) {
    console.warn('Redis GET falhou (seguindo sem cache):', e?.message);
  }

  console.log(`💾 Cache MISS para chave ${key}, consultando Postgres...`);
  const client = await pool.connect();
  try {
    console.log('📡 Executando query 1 (channel_endpoints)...');
    const q1 = await client.query(
      `SELECT ce.channel, ce.external_id, ce.tenant_id, ce.cluster_id, ce.queue, ce.exchange, ce.routing_key, c.amqp_url
         FROM channel_endpoints ce
         JOIN clusters c ON c.cluster_id = ce.cluster_id
        WHERE ce.channel = $1 AND ce.external_id = $2
        LIMIT 1`, [channel, external_id]
    );
    console.log(`📊 Query 1 retornou ${q1.rowCount} linha(s)`);

    if (q1.rows[0]) {
      console.log('✅ Encontrado endpoint direto:', safeJson(q1.rows[0]));
      try { await redis.set(key, JSON.stringify(q1.rows[0]), 'EX', 120); } catch {}
      return q1.rows[0];
    }

    console.log('📡 Executando query 2 (routing_rules)...');
    const q2 = await client.query(
      `SELECT rr.*, c.amqp_url
         FROM routing_rules rr
         JOIN clusters c ON c.cluster_id = rr.cluster_id
        WHERE (rr.tenant_id = $1 OR rr.tenant_id IS NULL)
          AND rr.channel = $2 AND rr.event_type = $3
        ORDER BY (rr.tenant_id IS NOT NULL) DESC, rr.priority DESC
        LIMIT 1`, [tenant_id, channel, event_type]
    );
    console.log(`📊 Query 2 retornou ${q2.rowCount} linha(s)`);

    if (q2.rows[0]) {
      console.log('✅ Encontrada rota via regra:', safeJson(q2.rows[0]));
      try { await redis.set(key, JSON.stringify(q2.rows[0]), 'EX', 60); } catch {}
      return q2.rows[0];
    }

    console.warn('⚠️ Nenhuma rota encontrada para este evento');
    return null;
  } catch (e) {
    console.error('❌ Erro em resolveRouting:', e);
    return null;
  } finally {
    client.release();
    console.log(`🔍 [${nowIso()}] resolveRouting END`);
  }
}

// Publisher com confirm channels + pooling simples
const pools = new Map();
async function getConfirmChannel(amqpUrl) {
  const url = amqpUrl || DEFAULT_AMQP_URL;
  const existing = pools.get(url);
  if (existing?.ch && !existing.ch.connectionClosed) {
    return existing.ch;
  }
  console.log(`📡 [${nowIso()}] Conectando ao RabbitMQ: ${url}`);
  const conn = await amqplib.connect(url, { heartbeat: 15 });
  const ch = await conn.createConfirmChannel();
  ch.on('error', (e) => console.error('[amqp ch error]', e));
  ch.on('close', () => console.warn('[amqp ch closed]'));
  conn.on('error', (e) => console.error('[amqp conn error]', e));
  conn.on('close', () => {
    console.warn('[amqp conn closed]', url);
    const item = pools.get(url);
    if (item) {
      item.ch.connectionClosed = true;
    }
  });
  pools.set(url, { conn, ch });
  return ch;
}

async function publish({ amqpUrl, queue, exchange, routingKey, body, headers }) {
  const ch = await getConfirmChannel(amqpUrl || DEFAULT_AMQP_URL);

  const payloadStr = JSON.stringify(body);
  const payload = Buffer.from(payloadStr);

  let ex = exchange || '';
  let rk = routingKey || '';
  if (queue && !exchange) {
    ex = '';
    rk = queue;
  }

  console.log(`📤 [${nowIso()}] Publicando mensagem no RabbitMQ:
    Exchange: ${ex || '(default)'}
    Routing Key: ${rk}
    Queue: ${queue || '(nenhuma direta)'}
    Headers: ${safeJson(headers)}
    Payload length: ${payload.length}
  `);

  const ok = ch.publish(ex, rk, payload, {
    persistent: true,
    headers,
    contentType: 'application/json'
  });

  if (!ok) {
    console.warn('⚠️ Buffer cheio, aguardando RabbitMQ liberar (drain)...');
    await new Promise((res) => ch.once('drain', res));
  }

  console.log('⏳ Aguardando confirmação do RabbitMQ...');
  await ch.waitForConfirms();
  console.log('✅ Mensagem confirmada pelo RabbitMQ!');
}

// ============ Fastify app ============
const app = Fastify({
  logger: { level: 'info' },
  bodyLimit: 2 * 1024 * 1024, // 2MB
  trustProxy: true
});

app.register(rawBody, {
  field: 'rawBody',
  global: true,
  encoding: 'utf8',
  runFirst: true,
  routes: []
});

// Healthchecks
app.get('/healthz', async (_req, reply) => reply.send({ ok: true, ts: nowIso() }));

app.get('/readyz', async (_req, reply) => {
  try {
    await pool.query('SELECT 1');
    try { await redis.ping(); } catch (e) {
      console.warn('Redis ping falhou em /readyz:', e?.message);
      // ainda consideramos "not ready"
      throw e;
    }
    const conn = await amqplib.connect(DEFAULT_AMQP_URL, { heartbeat: 10 });
    await conn.close();
    return reply.send({ ready: true, ts: nowIso() });
  } catch (e) {
    return reply.code(500).send({ ready: false, error: e?.message, ts: nowIso() });
  }
});

// GET /webhook (Meta validation)
app.get('/webhook', async (req, reply) => {
  console.log('\n===== 📥 GET /webhook =====');
  console.log(`🕒 ${nowIso()}`);
  console.log('➡️ Query Params:', safeJson(req.query));
  console.log('➡️ Headers:', safeJson(req.headers));

  const {
    'hub.mode': hubMode,
    'hub.challenge': hubChallenge,
    'hub.verify_token': hubVerifyToken,
    hub_mode, hub_challenge, hub_verify_token
  } = req.query || {};
  const mode = hubMode || hub_mode;
  const challenge = hubChallenge || hub_challenge;
  const verifyToken = hubVerifyToken || hub_verify_token;

  if (mode === 'subscribe' && verifyToken === META_VERIFY_TOKEN) {
    console.log('✅ Verificação Meta OK — enviando challenge');
    return reply.type('text/plain').send(challenge ?? '');
  }
  console.warn('❌ Verificação Meta FALHOU');
  return reply.code(403).send({ error: 'verification failed' });
});

// POST /webhook (principal)
app.post('/webhook', async (req, reply) => {
  console.log('\n===== 📥 NOVO POST /webhook =====');
  console.log(`🕒 ${nowIso()}`);
  console.log('➡️ Headers:', safeJson(req.headers));
  console.log('➡️ Body:', safeJson(req.body));
  console.log('➡️ Raw Body:', typeof req.rawBody === 'string' ? req.rawBody : '[buffer/obj]');

  const raw = Buffer.isBuffer(req.rawBody)
    ? req.rawBody
    : Buffer.from(
        typeof req.rawBody === 'string'
          ? req.rawBody
          : JSON.stringify(req.body || {})
      );

  const headers = req.headers || {};
  const channel = detectChannel(req.body, headers);
  console.log(`🎯 Canal detectado: ${channel}`);

  if (channel === 'unknown') {
    console.warn('❌ Canal não reconhecido — retornando 400');
    return reply.code(400).send({ error: 'unknown channel' });
  }

  // Validações (permissivas para compatibilidade, mas logamos)
  if (channel === 'telegram') {
    const ok = verifyTelegramSecret(headers['x-telegram-bot-api-secret-token']);
    if (!ok) {
      console.warn('❌ Telegram secret inválido');
      return reply.code(401).send({ error: 'telegram secret invalid' });
    } else if (!TELEGRAM_SECRET) {
      console.warn('⚠️ Telegram sem TELEGRAM_SECRET definido — modo compat');
    }
  } else { // Meta
    const ok = verifyMetaSignature(headers['x-hub-signature-256'], raw);
    if (!ok) {
      console.warn('❌ Meta assinatura inválida');
      // Para compat: NÃO bloqueia se quiser, mas aqui vamos bloquear para segurança:
      // return reply.code(401).send({ error: 'meta signature invalid' });
      // Se preferir compat, comente a linha acima e use o warn.
    } else if (!META_APP_SECRET) {
      console.warn('⚠️ META_APP_SECRET vazio — validação skip (modo compat)');
    }
  }

  const evt = normalizeEvent(channel, req.body || {});
  console.log('📦 Evento normalizado:', safeJson(evt));

  // Geração do idempotency key
  let msgId;
  try {
    msgId = (channel === 'telegram')
      ? String(req.body?.update_id ?? '')
      : String(req.body?.entry?.[0]?.id ?? '');
  } catch {
    msgId = '';
  }
  if (!msgId || msgId === 'undefined') {
    msgId = crypto.createHash('sha1').update(raw).digest('hex');
  }
  console.log(`🔑 Idempotency Key: ${msgId}`);

  // Checagem idempotência
  try {
    const idemKey = `idem:${msgId}`;
    const hit = await redis.set(idemKey, '1', 'EX', 300, 'NX');
    console.log(`💾 Redis SET ${idemKey} => ${hit}`);
    if (hit !== 'OK') {
      console.log('♻️ Evento duplicado — retornando duplicate');
      return reply.send({ status: 'duplicate' });
    }
  } catch (e) {
    console.error('Redis SET falhou — seguindo mesmo assim:', e?.message);
  }

  console.log('📍 Resolvendo rota...');
  const route = await resolveRouting({
    channel,
    external_id: evt.external_id,
    tenant_id: evt.tenant_id,
    event_type: evt.event_type
  });
  console.log('🛣️ Rota obtida:', safeJson(route));

  if (!route) {
    console.warn('⚠️ Nenhuma rota encontrada — retornando 422');
    return reply.code(422).send({ error: 'no routing for endpoint' });
  }

  try {
    console.log('🚀 Publicando no RabbitMQ...');
    await publish({
      amqpUrl: route.amqp_url || DEFAULT_AMQP_URL,
      queue: route.queue,
      exchange: route.exchange,
      routingKey: route.routing_key,
      body: evt,
      headers: { 'x-idempotency-key': msgId, 'x-channel': channel }
    });
    console.log('✅ Publicação concluída');
  } catch (e) {
    console.error('❌ Erro ao publicar no RabbitMQ:', e);
    // Opcional: enviar p/ uma fila de “estacionamento”/DLQ se quiser.
    return reply.code(202).send({ status: 'accepted_parking' });
  }

  console.log('🏁 Fluxo finalizado — 202 Accepted');
  return reply.code(202).send({ status: 'accepted' });
});

// ============ Inicialização & Shutdown ============
(async () => {
  console.log('🌐 Boot iniciando...', nowIso());

  // Tenta conectar Redis de forma antecipada (para falhar cedo se necessário)
  try {
    await redis.connect();
    console.log('✅ Redis conectado');
  } catch (e) {
    console.warn('⚠️ Redis não conectou ainda (tentará retry automático):', e?.message);
  }

  // Teste rápido de Postgres (não bloqueante)
  try {
    await pool.query('SELECT 1');
    console.log('✅ Postgres OK');
  } catch (e) {
    console.warn('⚠️ Postgres indisponível no boot (readyz refletirá):', e?.message);
  }

  try {
    await app.listen({ port: PORT, host: '0.0.0.0' });
    app.log.info('🚀 Webhook listening on :' + PORT);
  } catch (e) {
    console.error('❌ Falha ao subir servidor:', e);
    process.exit(1);
  }
})();

// Encerramento gracioso
async function shutdown(reason) {
  console.log(`🛑 Shutdown iniciado: ${reason} — ${nowIso()}`);
  try { await app.close(); } catch (e) { console.warn('app.close erro:', e?.message); }
  try { await pool.end(); } catch (e) { console.warn('pool.end erro:', e?.message); }
  try { await redis.quit(); } catch (e) { console.warn('redis.quit erro:', e?.message); }
  for (const [url, obj] of pools.entries()) {
    try { await obj?.ch?.close(); } catch {}
    try { await obj?.conn?.close(); } catch {}
    console.log('AMQP fechado:', url);
  }
  console.log('✅ Shutdown concluído');
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('unhandledRejection', (err) => {
  console.error('UnhandledRejection:', err);
});
process.on('uncaughtException', (err) => {
  console.error('UncaughtException:', err);
});
