-- channel_endpoints: maps provider endpoint -> tenant/cluster/queue
CREATE TABLE IF NOT EXISTS channel_endpoints (
  id SERIAL PRIMARY KEY,
  channel TEXT NOT NULL,
  external_id TEXT NOT NULL,
  tenant_id TEXT,
  cluster_id TEXT NOT NULL REFERENCES clusters(cluster_id),
  queue TEXT,
  exchange TEXT,
  routing_key TEXT,
  metadata JSONB DEFAULT '{}'::jsonb,
  UNIQUE (channel, external_id)
);

CREATE INDEX IF NOT EXISTS idx_channel_endpoints_channel_ext ON channel_endpoints(channel, external_id);

INSERT INTO channel_endpoints (channel, external_id, tenant_id, cluster_id, queue, exchange, routing_key)
VALUES
  ('whatsapp','PHONE_NUMBER_ID_EXAMPLE', 'tenant-acme', 'rabbit-a', 'queue.whatsapp.inbound', NULL, NULL),
  ('telegram','@your_bot',               'tenant-acme', 'rabbit-b', 'queue.telegram.inbound', NULL, NULL),
  ('instagram','IG_BUSINESS_ID',         'tenant-acme', 'rabbit-a', NULL, 'msgs', 'instagram.inbound'),
  ('facebook','PAGE_ID_EXAMPLE',         'tenant-acme', 'rabbit-c', 'queue.facebook.inbound', NULL, NULL)
ON CONFLICT DO NOTHING;
