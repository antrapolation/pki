-- Phase A: API Key & Service Config Redesign columns
-- Applied to both CA and RA schemas in tenant databases

-- RA schema: cert_profiles
ALTER TABLE ra.cert_profiles ADD COLUMN IF NOT EXISTS approval_mode character varying(255) DEFAULT 'manual' NOT NULL;
ALTER TABLE ra.cert_profiles ADD COLUMN IF NOT EXISTS validity_days integer;

-- RA schema: ra_api_keys
ALTER TABLE ra.ra_api_keys ADD COLUMN IF NOT EXISTS key_type character varying(255) DEFAULT 'client' NOT NULL;
ALTER TABLE ra.ra_api_keys ADD COLUMN IF NOT EXISTS allowed_profile_ids jsonb DEFAULT '[]'::jsonb;
ALTER TABLE ra.ra_api_keys ADD COLUMN IF NOT EXISTS ip_whitelist jsonb DEFAULT '[]'::jsonb;
ALTER TABLE ra.ra_api_keys ADD COLUMN IF NOT EXISTS webhook_url character varying(255);
ALTER TABLE ra.ra_api_keys ADD COLUMN IF NOT EXISTS webhook_secret character varying(255);

-- RA schema: csr_requests
ALTER TABLE ra.csr_requests ADD COLUMN IF NOT EXISTS submitted_by_key_id uuid;

-- RA schema: service_configs
ALTER TABLE ra.service_configs ADD COLUMN IF NOT EXISTS status character varying(255) DEFAULT 'active' NOT NULL;

-- Indexes
CREATE INDEX IF NOT EXISTS ra_api_keys_key_type_index ON ra.ra_api_keys (key_type);
CREATE INDEX IF NOT EXISTS csr_requests_submitted_by_key_id_index ON ra.csr_requests (submitted_by_key_id);

-- Normalize service types
UPDATE ra.service_configs SET service_type = 'ocsp_responder' WHERE service_type IN ('OCSP Responder', 'ocsp');
UPDATE ra.service_configs SET service_type = 'crl_distribution' WHERE service_type IN ('CRL Distribution', 'crl');
UPDATE ra.service_configs SET service_type = 'tsa' WHERE service_type IN ('TSA');
