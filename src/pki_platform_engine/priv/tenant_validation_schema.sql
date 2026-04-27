CREATE SCHEMA IF NOT EXISTS validation;

CREATE TABLE IF NOT EXISTS validation.certificate_status (
    id bigint NOT NULL,
    serial_number character varying(255) NOT NULL,
    issuer_key_id bigint NOT NULL,
    subject_dn character varying(255) NOT NULL,
    status character varying(255) DEFAULT 'active'::character varying NOT NULL,
    not_before timestamp(6) without time zone NOT NULL,
    not_after timestamp(6) without time zone NOT NULL,
    revoked_at timestamp(6) without time zone,
    revocation_reason character varying(255),
    issuer_name_hash bytea,
    inserted_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);
CREATE SEQUENCE IF NOT EXISTS validation.certificate_status_id_seq
    START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
ALTER SEQUENCE validation.certificate_status_id_seq OWNED BY validation.certificate_status.id;
ALTER TABLE ONLY validation.certificate_status ALTER COLUMN id SET DEFAULT nextval('validation.certificate_status_id_seq'::regclass);
ALTER TABLE ONLY validation.certificate_status
    ADD CONSTRAINT certificate_status_pkey PRIMARY KEY (id);
CREATE UNIQUE INDEX IF NOT EXISTS certificate_status_serial_number_index ON validation.certificate_status (serial_number);
CREATE INDEX IF NOT EXISTS certificate_status_status_index ON validation.certificate_status (status);
CREATE INDEX IF NOT EXISTS certificate_status_issuer_key_id_index ON validation.certificate_status (issuer_key_id);
CREATE INDEX IF NOT EXISTS certificate_status_issuer_key_id_serial_number_index ON validation.certificate_status (issuer_key_id, serial_number);
CREATE INDEX IF NOT EXISTS certificate_status_status_revoked_at_index ON validation.certificate_status (status, revoked_at);

CREATE TABLE IF NOT EXISTS validation.crl_metadata (
    id uuid NOT NULL,
    issuer_key_id uuid NOT NULL,
    crl_number bigint DEFAULT 1 NOT NULL,
    last_generated_at timestamp(6) without time zone,
    last_der_bytes bytea,
    last_der_size integer DEFAULT 0,
    generation_count integer DEFAULT 0 NOT NULL,
    inserted_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);
ALTER TABLE ONLY validation.crl_metadata
    ADD CONSTRAINT crl_metadata_pkey PRIMARY KEY (id);
CREATE UNIQUE INDEX IF NOT EXISTS crl_metadata_issuer_key_id_index ON validation.crl_metadata (issuer_key_id);

CREATE TABLE IF NOT EXISTS validation.signing_key_config (
    id uuid NOT NULL,
    issuer_key_id uuid NOT NULL,
    algorithm character varying(255) NOT NULL,
    certificate_pem text NOT NULL,
    encrypted_private_key bytea NOT NULL,
    not_before timestamp(6) without time zone NOT NULL,
    not_after timestamp(6) without time zone NOT NULL,
    status character varying(255) DEFAULT 'active'::character varying NOT NULL,
    inserted_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);
ALTER TABLE ONLY validation.signing_key_config
    ADD CONSTRAINT signing_key_config_pkey PRIMARY KEY (id);
CREATE INDEX IF NOT EXISTS signing_key_config_issuer_key_id_index ON validation.signing_key_config (issuer_key_id);
CREATE UNIQUE INDEX IF NOT EXISTS signing_key_config_one_active_per_issuer
    ON validation.signing_key_config (issuer_key_id) WHERE (status = 'active');
