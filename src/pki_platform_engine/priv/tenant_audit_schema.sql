CREATE SCHEMA IF NOT EXISTS audit;
CREATE TABLE IF NOT EXISTS audit.audit_events (
    id bigint NOT NULL,
    event_id uuid NOT NULL,
    "timestamp" timestamp(6) without time zone NOT NULL,
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
CREATE SEQUENCE IF NOT EXISTS audit.audit_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE audit.audit_events_id_seq OWNED BY audit.audit_events.id;
ALTER TABLE ONLY audit.audit_events ALTER COLUMN id SET DEFAULT nextval('audit.audit_events_id_seq'::regclass);
ALTER TABLE ONLY audit.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_event_id_index ON audit.audit_events (event_id);
CREATE INDEX IF NOT EXISTS audit_events_action_index ON audit.audit_events (action);
CREATE INDEX IF NOT EXISTS audit_events_actor_did_index ON audit.audit_events (actor_did);
CREATE INDEX IF NOT EXISTS audit_events_resource_type_resource_id_index ON audit.audit_events (resource_type, resource_id);
CREATE INDEX IF NOT EXISTS audit_events_timestamp_index ON audit.audit_events ("timestamp");
CREATE INDEX IF NOT EXISTS audit_events_ca_instance_id_index ON audit.audit_events (ca_instance_id);
