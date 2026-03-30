CREATE SCHEMA IF NOT EXISTS ra;
CREATE TABLE IF NOT EXISTS ra.cert_profiles (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    subject_dn_policy jsonb DEFAULT '{}'::jsonb,
    issuer_policy jsonb DEFAULT '{}'::jsonb,
    key_usage character varying(255),
    ext_key_usage character varying(255),
    digest_algo character varying(255),
    validity_policy jsonb DEFAULT '{}'::jsonb,
    timestamping_policy jsonb DEFAULT '{}'::jsonb,
    crl_policy jsonb DEFAULT '{}'::jsonb,
    ocsp_policy jsonb DEFAULT '{}'::jsonb,
    ca_repository_url character varying(255),
    issuer_url character varying(255),
    included_extensions jsonb DEFAULT '{}'::jsonb,
    renewal_policy jsonb DEFAULT '{}'::jsonb,
    notification_profile jsonb DEFAULT '{}'::jsonb,
    cert_publish_policy jsonb DEFAULT '{}'::jsonb,
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL,
    ra_instance_id uuid,
    issuer_key_id character varying(255)
);
CREATE TABLE IF NOT EXISTS ra.credentials (
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
CREATE TABLE IF NOT EXISTS ra.csr_requests (
    id uuid NOT NULL,
    csr_der bytea,
    csr_pem text,
    subject_dn character varying(255) NOT NULL,
    cert_profile_id uuid NOT NULL,
    status character varying(255) DEFAULT 'pending'::character varying NOT NULL,
    submitted_at timestamp without time zone NOT NULL,
    reviewed_by uuid,
    reviewed_at timestamp without time zone,
    rejection_reason text,
    issued_cert_serial character varying(255),
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL
);
CREATE TABLE IF NOT EXISTS ra.ra_api_keys (
    id uuid NOT NULL,
    hashed_key character varying(255) NOT NULL,
    ra_user_id uuid NOT NULL,
    label character varying(255),
    expiry timestamp without time zone,
    rate_limit integer,
    status character varying(255) DEFAULT 'active'::character varying NOT NULL,
    revoked_at timestamp without time zone,
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL,
    ra_instance_id uuid
);
CREATE TABLE IF NOT EXISTS ra.ra_instances (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    status character varying(255) DEFAULT 'initialized'::character varying NOT NULL,
    created_by character varying(255),
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL
);
CREATE TABLE IF NOT EXISTS ra.ra_users (
    id uuid NOT NULL,
    username character varying(255),
    password_hash character varying(255),
    display_name character varying(255),
    role character varying(255) NOT NULL,
    status character varying(255) DEFAULT 'active'::character varying NOT NULL,
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL,
    tenant_id uuid,
    must_change_password boolean DEFAULT false,
    credential_expires_at timestamp(0) without time zone,
    email character varying(255),
    ra_instance_id uuid
);
CREATE TABLE IF NOT EXISTS ra.service_configs (
    id uuid NOT NULL,
    service_type character varying(255) NOT NULL,
    port integer,
    url character varying(255),
    rate_limit integer,
    ip_whitelist jsonb DEFAULT '{}'::jsonb,
    ip_blacklist jsonb DEFAULT '{}'::jsonb,
    connection_security character varying(255),
    credentials bytea,
    ca_engine_ref character varying(255),
    inserted_at timestamp(0) without time zone NOT NULL,
    updated_at timestamp(0) without time zone NOT NULL
);
ALTER TABLE ONLY ra.cert_profiles
    ADD CONSTRAINT cert_profiles_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ra.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ra.csr_requests
    ADD CONSTRAINT csr_requests_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ra.ra_api_keys
    ADD CONSTRAINT ra_api_keys_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ra.ra_instances
    ADD CONSTRAINT ra_instances_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ra.ra_users
    ADD CONSTRAINT ra_users_pkey PRIMARY KEY (id);
ALTER TABLE ONLY ra.service_configs
    ADD CONSTRAINT service_configs_pkey PRIMARY KEY (id);
CREATE INDEX IF NOT EXISTS cert_profiles_issuer_key_id_index ON ra.cert_profiles USING btree (issuer_key_id);
CREATE UNIQUE INDEX cert_profiles_name_index ON ra.cert_profiles USING btree (name);
CREATE INDEX IF NOT EXISTS cert_profiles_ra_instance_id_index ON ra.cert_profiles USING btree (ra_instance_id);
CREATE INDEX IF NOT EXISTS credentials_user_id_credential_type_index ON ra.credentials USING btree (user_id, credential_type);
CREATE INDEX IF NOT EXISTS credentials_user_id_index ON ra.credentials USING btree (user_id);
CREATE INDEX IF NOT EXISTS csr_requests_cert_profile_id_index ON ra.csr_requests USING btree (cert_profile_id);
CREATE INDEX IF NOT EXISTS csr_requests_reviewed_at_index ON ra.csr_requests USING btree (reviewed_at);
CREATE INDEX IF NOT EXISTS csr_requests_status_index ON ra.csr_requests USING btree (status);
CREATE INDEX IF NOT EXISTS csr_requests_submitted_at_index ON ra.csr_requests USING btree (submitted_at);
CREATE INDEX IF NOT EXISTS ra_api_keys_ra_instance_id_index ON ra.ra_api_keys USING btree (ra_instance_id);
CREATE UNIQUE INDEX ra_instances_name_index ON ra.ra_instances USING btree (name);
CREATE INDEX IF NOT EXISTS ra_users_ra_instance_id_index ON ra.ra_users USING btree (ra_instance_id);
CREATE INDEX IF NOT EXISTS ra_users_role_index ON ra.ra_users USING btree (role);
CREATE INDEX IF NOT EXISTS ra_users_status_index ON ra.ra_users USING btree (status);
CREATE INDEX IF NOT EXISTS ra_users_tenant_id_index ON ra.ra_users USING btree (tenant_id);
CREATE UNIQUE INDEX ra_users_username_index ON ra.ra_users USING btree (username);
CREATE UNIQUE INDEX ra_users_username_tenant_id_index ON ra.ra_users USING btree (username, tenant_id);
CREATE UNIQUE INDEX service_configs_service_type_index ON ra.service_configs USING btree (service_type);
ALTER TABLE ONLY ra.cert_profiles
    ADD CONSTRAINT cert_profiles_ra_instance_id_fkey FOREIGN KEY (ra_instance_id) REFERENCES ra.ra_instances(id) ON DELETE SET NULL;
ALTER TABLE ONLY ra.credentials
    ADD CONSTRAINT credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES ra.ra_users(id) ON DELETE CASCADE;
ALTER TABLE ONLY ra.csr_requests
    ADD CONSTRAINT csr_requests_cert_profile_id_fkey FOREIGN KEY (cert_profile_id) REFERENCES ra.cert_profiles(id) ON DELETE RESTRICT;
ALTER TABLE ONLY ra.csr_requests
    ADD CONSTRAINT csr_requests_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES ra.ra_users(id) ON DELETE SET NULL;
ALTER TABLE ONLY ra.ra_api_keys
    ADD CONSTRAINT ra_api_keys_ra_instance_id_fkey FOREIGN KEY (ra_instance_id) REFERENCES ra.ra_instances(id) ON DELETE SET NULL;
ALTER TABLE ONLY ra.ra_api_keys
    ADD CONSTRAINT ra_api_keys_ra_user_id_fkey FOREIGN KEY (ra_user_id) REFERENCES ra.ra_users(id) ON DELETE CASCADE;
ALTER TABLE ONLY ra.ra_users
    ADD CONSTRAINT ra_users_ra_instance_id_fkey FOREIGN KEY (ra_instance_id) REFERENCES ra.ra_instances(id) ON DELETE SET NULL;
