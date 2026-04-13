-- Add is_offline to ca_instances (CA engine migration 20260403200000)
ALTER TABLE ca.ca_instances ADD COLUMN IF NOT EXISTS is_offline boolean DEFAULT false;

-- Create dcv_challenges table (RA engine migration 20260404100000)
-- Use DO block to skip if table already exists (base schema may have created it)
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'ra' AND table_name = 'dcv_challenges') THEN
    CREATE TABLE ra.dcv_challenges (
        id uuid NOT NULL PRIMARY KEY,
        csr_id uuid NOT NULL,
        domain character varying(255) NOT NULL,
        method character varying(255) NOT NULL,
        token character varying(255) NOT NULL,
        token_value character varying(255) NOT NULL,
        status character varying(255) DEFAULT 'pending'::character varying NOT NULL,
        initiated_by uuid,
        verified_at timestamp(0) without time zone,
        expires_at timestamp(0) without time zone NOT NULL,
        attempts integer DEFAULT 0,
        last_checked_at timestamp(0) without time zone,
        error_details character varying(255),
        inserted_at timestamp(0) without time zone NOT NULL,
        updated_at timestamp(0) without time zone NOT NULL
    );
    CREATE INDEX dcv_challenges_csr_id_index ON ra.dcv_challenges USING btree (csr_id);
    CREATE UNIQUE INDEX dcv_challenges_csr_id_domain_method_index ON ra.dcv_challenges USING btree (csr_id, domain, method);
    ALTER TABLE ONLY ra.dcv_challenges
        ADD CONSTRAINT dcv_challenges_csr_id_fkey FOREIGN KEY (csr_id) REFERENCES ra.csr_requests(id) ON DELETE CASCADE;
  END IF;
END $$;

-- Create ra_ca_connections table (RA engine migration 20260405000001)
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'ra' AND table_name = 'ra_ca_connections') THEN
    CREATE TABLE ra.ra_ca_connections (
        id uuid NOT NULL PRIMARY KEY,
        ra_instance_id uuid NOT NULL,
        issuer_key_id character varying(255) NOT NULL,
        issuer_key_name character varying(255),
        algorithm character varying(255),
        ca_instance_name character varying(255),
        status character varying(255) DEFAULT 'active'::character varying NOT NULL,
        connected_at timestamp(0) without time zone NOT NULL,
        connected_by uuid,
        inserted_at timestamp(0) without time zone NOT NULL,
        updated_at timestamp(0) without time zone NOT NULL
    );
    CREATE UNIQUE INDEX ra_ca_connections_ra_instance_id_issuer_key_id_index ON ra.ra_ca_connections USING btree (ra_instance_id, issuer_key_id);
    CREATE INDEX ra_ca_connections_status_index ON ra.ra_ca_connections USING btree (status);
    ALTER TABLE ONLY ra.ra_ca_connections
        ADD CONSTRAINT ra_ca_connections_ra_instance_id_fkey FOREIGN KEY (ra_instance_id) REFERENCES ra.ra_instances(id) ON DELETE CASCADE;
  END IF;
END $$;
