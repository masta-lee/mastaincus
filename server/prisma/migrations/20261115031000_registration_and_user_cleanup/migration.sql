CREATE TABLE registration_receipts (
  id UUID PRIMARY KEY,
  source TEXT NOT NULL,
  ip TEXT NOT NULL,
  user_id INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX registration_receipts_source_created_at_idx ON registration_receipts(source, created_at);
-- Preserve the current 24-hour quota across upgrades using existing successful
-- registration audit evidence. Invalid legacy addresses are ignored safely.
INSERT INTO registration_receipts (id, source, ip, user_id, created_at)
SELECT md5('registration:' || id::text)::uuid,
  CASE WHEN family(address) = 4 THEN host(address) ELSE host(set_masklen(address,64)::cidr) || '/64' END,
  host(address), user_id, created_at
FROM (
  SELECT id, user_id, created_at,
    CASE WHEN pg_input_is_valid(raw_ip, 'inet') THEN raw_ip::inet ELSE NULL END AS address
  FROM (
    SELECT id, user_id, created_at, substring(content FROM '\[IP: ([^]]+)\]') AS raw_ip
    FROM logs WHERE action = 'register_success' AND created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
  ) evidence
) valid WHERE address IS NOT NULL;
ALTER TABLE users ADD COLUMN deletion_intent JSONB;
CREATE TABLE deleted_payment_receipts (
  provider_id INTEGER NOT NULL,
  trade_hash TEXT NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (provider_id, trade_hash)
);
