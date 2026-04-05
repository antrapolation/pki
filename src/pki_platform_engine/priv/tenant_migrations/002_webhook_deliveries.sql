-- Webhook delivery tracking table
CREATE TABLE IF NOT EXISTS ra.webhook_deliveries (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    api_key_id uuid NOT NULL,
    csr_id uuid,
    event character varying(255) NOT NULL,
    url character varying(500) NOT NULL,
    status character varying(50) NOT NULL DEFAULT 'pending',
    attempts integer DEFAULT 0,
    last_http_status integer,
    last_error text,
    payload jsonb,
    inserted_at timestamp(0) without time zone NOT NULL DEFAULT now(),
    updated_at timestamp(0) without time zone NOT NULL DEFAULT now(),
    CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_api_key_id_index ON ra.webhook_deliveries (api_key_id);
CREATE INDEX IF NOT EXISTS webhook_deliveries_csr_id_index ON ra.webhook_deliveries (csr_id);
CREATE INDEX IF NOT EXISTS webhook_deliveries_status_index ON ra.webhook_deliveries (status);
CREATE INDEX IF NOT EXISTS webhook_deliveries_inserted_at_index ON ra.webhook_deliveries (inserted_at)
