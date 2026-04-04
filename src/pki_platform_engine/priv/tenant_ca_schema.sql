CREATE SCHEMA IF NOT EXISTS ca;
CREATE TABLE IF NOT EXISTS ca.audit_events (
    id bigint NOT NULL,
    event_id uuid NOT NULL,
    "timestamp" timestamp without time zone NOT NULL,
    node_name character varying(255) NOT NULL,
    actor_did character varying(255) NOT NULL,
    actor_role character varying(255) NOT NULL,
    action character varying(255) NOT NULL,
    resource_type character varying(255) NOT NULL,
    resource_id character varying(255) NOT NULL,
    details jsonb DEFAULT '{}'::jsonb,
    prev_hash character varying(64) NOT NULL,
    event_hash character varying(64) NOT NULL,
    ca_instance_id character varying(255)
);
CREATE SEQUENCE IF NOT EXISTS ca.audit_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE ca.audit_events_id_seq OWNED BY ca.audit_events.id;
CREATE TABLE IF NOT EXISTS ca.ca_instances (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    status character varying(255) DEFAULT 'initialized'::character varying NOT NULL,
    domain_info jsonb DEFAULT '{}'::jsonb,
    created_by character varying(255),
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL,
    parent_id uuid
);
CREATE TABLE IF NOT EXISTS ca.ca_users (
    id uuid NOT NULL,
    ca_instance_id uuid NOT NULL,
    username character varying(255),
    password_hash character varying(255),
    display_name character varying(255),
    role character varying(255) NOT NULL,
    status character varying(255) DEFAULT 'active'::character varying NOT NULL,
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL,
    must_change_password boolean DEFAULT false,
    credential_expires_at timestamp(0) without time zone,
    email character varying(255)
);
CREATE TABLE IF NOT EXISTS ca.credentials (
    id uuid NOT NULL,
    credential_type character varying(255) NOT NULL,
    algorithm character varying(255) NOT NULL,
    public_key bytea NOT NULL,
    encrypted_private_key bytea NOT NULL,
    salt bytea NOT NULL,
    certificate bytea,
    status character varying(255) DEFAULT 'active'::character varying NOT NULL,
    user_id uuid NOT NULL,
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL,
    attested_by_key bytea
);
CREATE TABLE IF NOT EXISTS ca.issued_certificates (
    id uuid NOT NULL,
    serial_number character varying(255) NOT NULL,
    issuer_key_id uuid NOT NULL,
    subject_dn character varying(255) NOT NULL,
    cert_der bytea,
    cert_pem text,
    not_before timestamp(0) without time zone NOT NULL,
    not_after timestamp(0) without time zone NOT NULL,
    status character varying(255) DEFAULT 'active'::character varying NOT NULL,
    revoked_at timestamp(0) without time zone,
    revocation_reason character varying(255),
    cert_profile_id character varying(255),
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL
);
CREATE TABLE IF NOT EXISTS ca.issuer_keys (
    id uuid NOT NULL,
    ca_instance_id uuid NOT NULL,
    key_alias character varying(255) NOT NULL,
    algorithm character varying(255) NOT NULL,
    status character varying(255) DEFAULT 'pending'::character varying NOT NULL,
    keystore_ref bytea,
    is_root boolean DEFAULT false,
    threshold_config jsonb DEFAULT '{}'::jsonb,
    certificate_der bytea,
    certificate_pem text,
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL
);
CREATE TABLE IF NOT EXISTS ca.key_ceremonies (
    id uuid NOT NULL,
    ca_instance_id uuid NOT NULL,
    issuer_key_id uuid,
    ceremony_type character varying(255) NOT NULL,
    status character varying(255) DEFAULT 'initiated'::character varying NOT NULL,
    initiated_by uuid,
    participants jsonb DEFAULT '{}'::jsonb,
    algorithm character varying(255),
    keystore_id uuid,
    threshold_k integer,
    threshold_n integer,
    domain_info jsonb DEFAULT '{}'::jsonb,
    window_expires_at timestamp(0) without time zone,
    auditor_user_id uuid,
    time_window_hours integer DEFAULT 24,
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL
);
CREATE TABLE IF NOT EXISTS ca.keypair_access (
    id uuid NOT NULL,
    issuer_key_id uuid NOT NULL,
    user_id uuid NOT NULL,
    granted_by uuid,
    granted_at timestamp(0) without time zone NOT NULL
);
CREATE TABLE IF NOT EXISTS ca.keypair_grants (
    id uuid NOT NULL,
    signed_envelope bytea NOT NULL,
    granted_at timestamp without time zone NOT NULL,
    revoked_at timestamp without time zone,
    managed_keypair_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL
);
CREATE TABLE IF NOT EXISTS ca.keystores (
    id uuid NOT NULL,
    ca_instance_id uuid NOT NULL,
    type character varying(255) NOT NULL,
    config bytea,
    status character varying(255) DEFAULT 'active'::character varying NOT NULL,
    provider_name character varying(255),
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL
);
CREATE TABLE IF NOT EXISTS ca.managed_keypairs (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    algorithm character varying(255) NOT NULL,
    protection_mode character varying(255) NOT NULL,
    public_key bytea,
    encrypted_private_key bytea,
    encrypted_password bytea,
    threshold_k integer,
    threshold_n integer,
    status character varying(255) DEFAULT 'pending'::character varying NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    ca_instance_id uuid NOT NULL,
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL,
    acl_kem_ciphertext bytea
);
CREATE TABLE IF NOT EXISTS ca.threshold_shares (
    id uuid NOT NULL,
    issuer_key_id uuid NOT NULL,
    custodian_user_id uuid NOT NULL,
    share_index integer NOT NULL,
    encrypted_share bytea,
    min_shares integer NOT NULL,
    total_shares integer NOT NULL,
    key_label varchar(255),
    status varchar(255) DEFAULT 'pending',
    accepted_at timestamp(0) without time zone,
    encrypted_password bytea,
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL
);
ALTER TABLE ONLY ca.audit_events ALTER COLUMN id SET DEFAULT nextval('ca.audit_events_id_seq'::regclass);
ALTER TABLE ONLY ca.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ca.ca_instances
    ADD CONSTRAINT ca_instances_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ca.ca_users
    ADD CONSTRAINT ca_users_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ca.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ca.issued_certificates
    ADD CONSTRAINT issued_certificates_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ca.issuer_keys
    ADD CONSTRAINT issuer_keys_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ca.key_ceremonies
    ADD CONSTRAINT key_ceremonies_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ca.keypair_access
    ADD CONSTRAINT keypair_access_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ca.keypair_grants
    ADD CONSTRAINT keypair_grants_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ca.keystores
    ADD CONSTRAINT keystores_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ca.managed_keypairs
    ADD CONSTRAINT managed_keypairs_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ca.threshold_shares
    ADD CONSTRAINT threshold_shares_pkey PRIMARY KEY (id);
CREATE INDEX IF NOT EXISTS audit_events_action_index ON ca.audit_events USING btree (action);
CREATE INDEX IF NOT EXISTS audit_events_actor_did_index ON ca.audit_events USING btree (actor_did);
CREATE INDEX IF NOT EXISTS audit_events_ca_instance_id_index ON ca.audit_events USING btree (ca_instance_id);
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_event_id_index ON ca.audit_events USING btree (event_id);
CREATE INDEX IF NOT EXISTS audit_events_resource_type_resource_id_index ON ca.audit_events USING btree (resource_type, resource_id);
CREATE INDEX IF NOT EXISTS audit_events_timestamp_index ON ca.audit_events USING btree ("timestamp");
CREATE UNIQUE INDEX IF NOT EXISTS ca_instances_name_index ON ca.ca_instances USING btree (name);
CREATE INDEX IF NOT EXISTS ca_instances_parent_id_index ON ca.ca_instances USING btree (parent_id);
CREATE INDEX IF NOT EXISTS ca_users_ca_instance_id_index ON ca.ca_users USING btree (ca_instance_id);
CREATE INDEX IF NOT EXISTS ca_users_role_index ON ca.ca_users USING btree (role);
CREATE INDEX IF NOT EXISTS ca_users_status_index ON ca.ca_users USING btree (status);
CREATE UNIQUE INDEX IF NOT EXISTS ca_users_username_index ON ca.ca_users USING btree (username);
CREATE INDEX IF NOT EXISTS credentials_user_id_credential_type_index ON ca.credentials USING btree (user_id, credential_type);
CREATE INDEX IF NOT EXISTS credentials_user_id_index ON ca.credentials USING btree (user_id);
CREATE INDEX IF NOT EXISTS issued_certificates_issuer_key_id_index ON ca.issued_certificates USING btree (issuer_key_id);
CREATE INDEX IF NOT EXISTS issued_certificates_issuer_key_id_status_index ON ca.issued_certificates USING btree (issuer_key_id, status);
CREATE INDEX IF NOT EXISTS issued_certificates_not_after_index ON ca.issued_certificates USING btree (not_after);
CREATE UNIQUE INDEX IF NOT EXISTS issued_certificates_serial_number_index ON ca.issued_certificates USING btree (serial_number);
CREATE INDEX IF NOT EXISTS issued_certificates_status_index ON ca.issued_certificates USING btree (status);
CREATE INDEX IF NOT EXISTS issuer_keys_ca_instance_id_index ON ca.issuer_keys USING btree (ca_instance_id);
CREATE UNIQUE INDEX IF NOT EXISTS issuer_keys_ca_instance_id_key_alias_index ON ca.issuer_keys USING btree (ca_instance_id, key_alias);
CREATE INDEX IF NOT EXISTS issuer_keys_ca_instance_id_status_index ON ca.issuer_keys USING btree (ca_instance_id, status);
CREATE INDEX IF NOT EXISTS issuer_keys_status_index ON ca.issuer_keys USING btree (status);
CREATE INDEX IF NOT EXISTS key_ceremonies_ca_instance_id_index ON ca.key_ceremonies USING btree (ca_instance_id);
CREATE INDEX IF NOT EXISTS key_ceremonies_issuer_key_id_index ON ca.key_ceremonies USING btree (issuer_key_id);
CREATE UNIQUE INDEX IF NOT EXISTS keypair_access_issuer_key_id_user_id_index ON ca.keypair_access USING btree (issuer_key_id, user_id);
CREATE INDEX IF NOT EXISTS keypair_access_user_id_index ON ca.keypair_access USING btree (user_id);
CREATE INDEX IF NOT EXISTS keypair_grants_credential_id_index ON ca.keypair_grants USING btree (credential_id);
CREATE UNIQUE INDEX IF NOT EXISTS keypair_grants_managed_keypair_id_credential_id_index ON ca.keypair_grants USING btree (managed_keypair_id, credential_id);
CREATE INDEX IF NOT EXISTS keystores_ca_instance_id_index ON ca.keystores USING btree (ca_instance_id);
CREATE INDEX IF NOT EXISTS managed_keypairs_ca_instance_id_index ON ca.managed_keypairs USING btree (ca_instance_id);
CREATE UNIQUE INDEX IF NOT EXISTS managed_keypairs_ca_instance_id_name_index ON ca.managed_keypairs USING btree (ca_instance_id, name);
CREATE INDEX IF NOT EXISTS managed_keypairs_status_index ON ca.managed_keypairs USING btree (status);
CREATE UNIQUE INDEX IF NOT EXISTS threshold_shares_issuer_key_id_custodian_user_id_index ON ca.threshold_shares USING btree (issuer_key_id, custodian_user_id);
CREATE INDEX IF NOT EXISTS threshold_shares_issuer_key_id_index ON ca.threshold_shares USING btree (issuer_key_id);
ALTER TABLE ONLY ca.ca_instances
    ADD CONSTRAINT ca_instances_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES ca.ca_instances(id) ON DELETE RESTRICT;
ALTER TABLE ONLY ca.ca_users
    ADD CONSTRAINT ca_users_ca_instance_id_fkey FOREIGN KEY (ca_instance_id) REFERENCES ca.ca_instances(id) ON DELETE CASCADE;
ALTER TABLE ONLY ca.credentials
    ADD CONSTRAINT credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES ca.ca_users(id) ON DELETE CASCADE;
ALTER TABLE ONLY ca.issued_certificates
    ADD CONSTRAINT issued_certificates_issuer_key_id_fkey FOREIGN KEY (issuer_key_id) REFERENCES ca.issuer_keys(id) ON DELETE RESTRICT;
ALTER TABLE ONLY ca.issuer_keys
    ADD CONSTRAINT issuer_keys_ca_instance_id_fkey FOREIGN KEY (ca_instance_id) REFERENCES ca.ca_instances(id) ON DELETE CASCADE;
ALTER TABLE ONLY ca.key_ceremonies
    ADD CONSTRAINT key_ceremonies_ca_instance_id_fkey FOREIGN KEY (ca_instance_id) REFERENCES ca.ca_instances(id) ON DELETE CASCADE;
-- initiated_by stores platform user ID (no FK — users live in platform DB)
ALTER TABLE ONLY ca.key_ceremonies
    ADD CONSTRAINT key_ceremonies_issuer_key_id_fkey FOREIGN KEY (issuer_key_id) REFERENCES ca.issuer_keys(id) ON DELETE CASCADE;
ALTER TABLE ONLY ca.key_ceremonies
    ADD CONSTRAINT key_ceremonies_keystore_id_fkey FOREIGN KEY (keystore_id) REFERENCES ca.keystores(id) ON DELETE SET NULL;
ALTER TABLE ONLY ca.keypair_access
    ADD CONSTRAINT keypair_access_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES ca.ca_users(id) ON DELETE SET NULL;
ALTER TABLE ONLY ca.keypair_access
    ADD CONSTRAINT keypair_access_issuer_key_id_fkey FOREIGN KEY (issuer_key_id) REFERENCES ca.issuer_keys(id) ON DELETE CASCADE;
ALTER TABLE ONLY ca.keypair_access
    ADD CONSTRAINT keypair_access_user_id_fkey FOREIGN KEY (user_id) REFERENCES ca.ca_users(id) ON DELETE CASCADE;
ALTER TABLE ONLY ca.keypair_grants
    ADD CONSTRAINT keypair_grants_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES ca.credentials(id) ON DELETE CASCADE;
ALTER TABLE ONLY ca.keypair_grants
    ADD CONSTRAINT keypair_grants_managed_keypair_id_fkey FOREIGN KEY (managed_keypair_id) REFERENCES ca.managed_keypairs(id) ON DELETE CASCADE;
ALTER TABLE ONLY ca.keystores
    ADD CONSTRAINT keystores_ca_instance_id_fkey FOREIGN KEY (ca_instance_id) REFERENCES ca.ca_instances(id) ON DELETE CASCADE;
ALTER TABLE ONLY ca.managed_keypairs
    ADD CONSTRAINT managed_keypairs_ca_instance_id_fkey FOREIGN KEY (ca_instance_id) REFERENCES ca.ca_instances(id) ON DELETE CASCADE;
-- custodian_user_id stores platform user ID (no FK — users live in platform DB)
ALTER TABLE ONLY ca.threshold_shares
    ADD CONSTRAINT threshold_shares_issuer_key_id_fkey FOREIGN KEY (issuer_key_id) REFERENCES ca.issuer_keys(id) ON DELETE CASCADE;
