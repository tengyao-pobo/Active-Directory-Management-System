\set ON_ERROR_STOP on

CREATE SCHEMA agent_private AUTHORIZATION :"agent_definer_role";
REVOKE ALL ON SCHEMA agent_private FROM PUBLIC;

CREATE TABLE IF NOT EXISTS agent_private.agent_database_bindings (
    login_role name PRIMARY KEY,
    environment_id uuid NOT NULL,
    purpose text NOT NULL CHECK (purpose = 'Ingest')
);

CREATE TABLE IF NOT EXISTS agent_private.devices (
    environment_id uuid NOT NULL,
    device_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('Active','Disabled','Retired')),
    last_seen_at timestamptz NULL,
    last_heartbeat_receipt_id uuid NULL,
    PRIMARY KEY (environment_id, device_id)
);

CREATE TABLE IF NOT EXISTS agent_private.registrations (
    environment_id uuid NOT NULL,
    registration_id uuid NOT NULL,
    device_id uuid NOT NULL,
    registration_epoch bigint NOT NULL CHECK (registration_epoch > 0),
    device_guid uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('Active','Revoked','Replaced')),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    revoked_at timestamptz NULL,
    PRIMARY KEY (environment_id, registration_id),
    UNIQUE (environment_id, registration_id, registration_epoch),
    UNIQUE (environment_id, registration_id, registration_epoch, device_id),
    UNIQUE (environment_id, device_id, registration_epoch),
    FOREIGN KEY (environment_id, device_id)
        REFERENCES agent_private.devices (environment_id, device_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS registrations_one_active_device
    ON agent_private.registrations (environment_id, device_id)
    WHERE state = 'Active';
CREATE UNIQUE INDEX IF NOT EXISTS registrations_one_active_device_guid
    ON agent_private.registrations (environment_id, device_guid)
    WHERE state = 'Active';

CREATE TABLE IF NOT EXISTS agent_private.certificate_bindings (
    environment_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    registration_id uuid NOT NULL,
    leaf_der_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(leaf_der_sha256) = 32),
    state text NOT NULL CHECK (state IN ('Active','Revoked')),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    CHECK (not_before < not_after),
    PRIMARY KEY (environment_id, binding_id),
    UNIQUE (leaf_der_sha256),
    UNIQUE (environment_id, binding_id, registration_id),
    FOREIGN KEY (environment_id, registration_id)
        REFERENCES agent_private.registrations (environment_id, registration_id)
);

CREATE TABLE IF NOT EXISTS agent_private.replay_state (
    environment_id uuid NOT NULL,
    registration_id uuid NOT NULL,
    registration_epoch bigint NOT NULL,
    high_sequence bigint NOT NULL CHECK (high_sequence >= 0),
    PRIMARY KEY (environment_id, registration_id, registration_epoch),
    FOREIGN KEY (environment_id, registration_id, registration_epoch)
        REFERENCES agent_private.registrations (environment_id, registration_id, registration_epoch)
);

CREATE TABLE IF NOT EXISTS agent_private.receipts (
    environment_id uuid NOT NULL,
    registration_id uuid NOT NULL,
    registration_epoch bigint NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    receipt_id uuid NOT NULL UNIQUE,
    device_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    hash_version integer NOT NULL,
    protocol_version integer NOT NULL,
    device_guid uuid NOT NULL,
    request_id uuid NOT NULL,
    observed_utc_ticks bigint NOT NULL,
    received_at timestamptz NOT NULL,
    payload_hash text NOT NULL,
    envelope_hash text NOT NULL,
    kind integer NOT NULL,
    schema_version integer NOT NULL,
    PRIMARY KEY (environment_id, registration_id, registration_epoch, sequence),
    UNIQUE (environment_id, registration_id, registration_epoch, request_id),
    UNIQUE (environment_id, registration_id, registration_epoch, sequence, receipt_id),
    UNIQUE (environment_id, registration_id, registration_epoch, sequence, receipt_id, device_id),
    FOREIGN KEY (environment_id, registration_id, registration_epoch, device_id)
        REFERENCES agent_private.registrations (environment_id, registration_id, registration_epoch, device_id),
    FOREIGN KEY (environment_id, binding_id, registration_id)
        REFERENCES agent_private.certificate_bindings (environment_id, binding_id, registration_id)
);

CREATE TABLE IF NOT EXISTS agent_private.snapshot_history (
    environment_id uuid NOT NULL,
    registration_id uuid NOT NULL,
    registration_epoch bigint NOT NULL,
    sequence bigint NOT NULL,
    receipt_id uuid NOT NULL,
    normalized_payload jsonb NOT NULL,
    PRIMARY KEY (environment_id, registration_id, registration_epoch, sequence),
    UNIQUE (receipt_id),
    FOREIGN KEY (environment_id, registration_id, registration_epoch, sequence, receipt_id)
        REFERENCES agent_private.receipts (environment_id, registration_id, registration_epoch, sequence, receipt_id)
);

CREATE TABLE IF NOT EXISTS agent_private.inventory_projection (
    environment_id uuid NOT NULL,
    device_id uuid NOT NULL,
    registration_id uuid NOT NULL,
    registration_epoch bigint NOT NULL,
    sequence bigint NOT NULL,
    receipt_id uuid NOT NULL,
    normalized_payload jsonb NOT NULL,
    PRIMARY KEY (environment_id, device_id),
    FOREIGN KEY (environment_id, registration_id, registration_epoch, sequence, receipt_id, device_id)
        REFERENCES agent_private.receipts (environment_id, registration_id, registration_epoch, sequence, receipt_id, device_id)
);

ALTER TABLE agent_private.agent_database_bindings OWNER TO :"agent_definer_role";
ALTER TABLE agent_private.devices OWNER TO :"agent_definer_role";
ALTER TABLE agent_private.registrations OWNER TO :"agent_definer_role";
ALTER TABLE agent_private.certificate_bindings OWNER TO :"agent_definer_role";
ALTER TABLE agent_private.replay_state OWNER TO :"agent_definer_role";
ALTER TABLE agent_private.receipts OWNER TO :"agent_definer_role";
ALTER TABLE agent_private.snapshot_history OWNER TO :"agent_definer_role";
ALTER TABLE agent_private.inventory_projection OWNER TO :"agent_definer_role";

ALTER TABLE agent_private.agent_database_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.agent_database_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_private.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.devices FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_private.registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.registrations FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_private.certificate_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.certificate_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_private.replay_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.replay_state FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_private.receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_private.snapshot_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.snapshot_history FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_private.inventory_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.inventory_projection FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS definer_all ON agent_private.agent_database_bindings;
CREATE POLICY definer_all ON agent_private.agent_database_bindings TO :"agent_definer_role" USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS definer_all ON agent_private.devices;
CREATE POLICY definer_all ON agent_private.devices TO :"agent_definer_role" USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS definer_all ON agent_private.registrations;
CREATE POLICY definer_all ON agent_private.registrations TO :"agent_definer_role" USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS definer_all ON agent_private.certificate_bindings;
CREATE POLICY definer_all ON agent_private.certificate_bindings TO :"agent_definer_role" USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS definer_all ON agent_private.replay_state;
CREATE POLICY definer_all ON agent_private.replay_state TO :"agent_definer_role" USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS definer_all ON agent_private.receipts;
CREATE POLICY definer_all ON agent_private.receipts TO :"agent_definer_role" USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS definer_all ON agent_private.snapshot_history;
CREATE POLICY definer_all ON agent_private.snapshot_history TO :"agent_definer_role" USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS definer_all ON agent_private.inventory_projection;
CREATE POLICY definer_all ON agent_private.inventory_projection TO :"agent_definer_role" USING (true) WITH CHECK (true);

CREATE OR REPLACE FUNCTION agent_private.ingest_attested_envelope(
    certificate_fingerprint bytea,
    protocol_version integer,
    device_guid uuid,
    registration_epoch bigint,
    sequence bigint,
    request_id uuid,
    observed_utc_ticks bigint,
    payload_bytes bytea,
    payload_hash text,
    envelope_hash text)
RETURNS TABLE (
    outcome text,
    diagnostic_code text,
    receipt_id uuid,
    ack_schema_version integer,
    ack_protocol_version integer,
    ack_device_guid uuid,
    ack_registration_epoch bigint,
    ack_sequence bigint,
    ack_request_id uuid,
    ack_observed_utc_ticks bigint,
    ack_payload_hash text,
    ack_envelope_hash text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, agent_private, pg_temp
AS $function$
#variable_conflict use_variable
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_now_ticks bigint;
    v_environment_id uuid;
    v_device_id uuid;
    v_registration_id uuid;
    v_binding_id uuid;
    v_registered_guid uuid;
    v_registered_epoch bigint;
    v_payload jsonb;
    v_schema integer;
    v_kind integer;
    v_actual_payload_hash text;
    v_actual_envelope_hash text;
    v_high_sequence bigint;
    v_receipt agent_private.receipts%ROWTYPE;
    v_receipt_id uuid;
    v_collector jsonb;
    v_data jsonb;
    v_section jsonb;
    v_row jsonb;
    v_item jsonb;
    v_allowed_keys text[];
    v_expected_source text;
BEGIN
    IF certificate_fingerprint IS NULL OR protocol_version IS NULL OR device_guid IS NULL OR
       registration_epoch IS NULL OR sequence IS NULL OR request_id IS NULL OR
       observed_utc_ticks IS NULL OR payload_bytes IS NULL OR payload_hash IS NULL OR envelope_hash IS NULL OR
       pg_catalog.octet_length(certificate_fingerprint) <> 32 OR sequence <= 0 OR registration_epoch <= 0 OR
       observed_utc_ticks < 0 OR observed_utc_ticks > 3155378975999999999 THEN
        RETURN QUERY SELECT 'PermanentRejected', 'ProtocolRejected', NULL::uuid, NULL::integer,
            NULL::integer, NULL::uuid, NULL::bigint, NULL::bigint, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END IF;

    IF pg_catalog.octet_length(payload_bytes) > 524288 OR protocol_version <> 1 OR
       payload_hash !~ '^[0-9a-f]{64}$' OR envelope_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN QUERY SELECT 'PermanentRejected', 'ProtocolRejected', NULL::uuid, NULL::integer,
            NULL::integer, NULL::uuid, NULL::bigint, NULL::bigint, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END IF;

    v_actual_payload_hash := pg_catalog.encode(pg_catalog.sha256(payload_bytes), 'hex');
    IF v_actual_payload_hash <> payload_hash THEN
        RETURN QUERY SELECT 'IdentityConflict', 'AuthenticationFailed', NULL::uuid, NULL::integer,
            NULL::integer, NULL::uuid, NULL::bigint, NULL::bigint, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END IF;

    v_actual_envelope_hash := pg_catalog.encode(pg_catalog.sha256(
        pg_catalog.int4send(2) ||
        pg_catalog.int4send(protocol_version) ||
        pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(device_guid::text, 'UTF8'))) ||
        pg_catalog.convert_to(device_guid::text, 'UTF8') ||
        pg_catalog.int8send(registration_epoch) ||
        pg_catalog.int8send(sequence) ||
        pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(request_id::text, 'UTF8'))) ||
        pg_catalog.convert_to(request_id::text, 'UTF8') ||
        pg_catalog.int8send(observed_utc_ticks) ||
        pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(payload_hash, 'UTF8'))) ||
        pg_catalog.convert_to(payload_hash, 'UTF8')), 'hex');
    IF v_actual_envelope_hash <> envelope_hash THEN
        RETURN QUERY SELECT 'IdentityConflict', 'AuthenticationFailed', NULL::uuid, NULL::integer,
            NULL::integer, NULL::uuid, NULL::bigint, NULL::bigint, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END IF;

    SELECT binding.environment_id, registration.device_id, registration.registration_id,
           binding.binding_id, registration.device_guid, registration.registration_epoch
      INTO v_environment_id, v_device_id, v_registration_id, v_binding_id,
           v_registered_guid, v_registered_epoch
      FROM agent_private.agent_database_bindings database_binding
      JOIN agent_private.certificate_bindings binding
        ON binding.environment_id = database_binding.environment_id
       AND binding.leaf_der_sha256 = certificate_fingerprint
      JOIN agent_private.registrations registration
        ON registration.environment_id = binding.environment_id
       AND registration.registration_id = binding.registration_id
      JOIN agent_private.devices device
        ON device.environment_id = registration.environment_id
       AND device.device_id = registration.device_id
     WHERE database_binding.login_role = SESSION_USER::name
       AND database_binding.purpose = 'Ingest'
       AND binding.state = 'Active'
       AND binding.revoked_at IS NULL
       AND v_now >= binding.not_before
       AND v_now < binding.not_after
       AND registration.state = 'Active'
       AND registration.revoked_at IS NULL
       AND device.state = 'Active';

    IF v_registration_id IS NULL OR v_registered_guid <> device_guid OR v_registered_epoch <> registration_epoch THEN
        RETURN QUERY SELECT 'IdentityConflict', 'AuthenticationFailed', NULL::uuid, NULL::integer,
            NULL::integer, NULL::uuid, NULL::bigint, NULL::bigint, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END IF;

    INSERT INTO agent_private.replay_state(environment_id, registration_id, registration_epoch, high_sequence)
        VALUES (v_environment_id, v_registration_id, registration_epoch, 0)
        ON CONFLICT ON CONSTRAINT replay_state_pkey DO NOTHING;
    SELECT replay.high_sequence INTO v_high_sequence
      FROM agent_private.replay_state replay
     WHERE replay.environment_id = v_environment_id
       AND replay.registration_id = v_registration_id
       AND replay.registration_epoch = registration_epoch
     FOR UPDATE;

    SELECT * INTO v_receipt
      FROM agent_private.receipts existing
     WHERE existing.environment_id = v_environment_id
       AND existing.registration_id = v_registration_id
       AND existing.registration_epoch = registration_epoch
       AND existing.sequence = ingest_attested_envelope.sequence;
    IF FOUND THEN
        IF v_receipt.device_id = v_device_id AND
           v_receipt.hash_version = 2 AND v_receipt.protocol_version = protocol_version AND
           v_receipt.device_guid = device_guid AND v_receipt.request_id = request_id AND
           v_receipt.observed_utc_ticks = observed_utc_ticks AND
           v_receipt.payload_hash = payload_hash AND v_receipt.envelope_hash = envelope_hash THEN
            RETURN QUERY SELECT 'AlreadyAccepted', 'None', v_receipt.receipt_id, 1,
                v_receipt.protocol_version, v_receipt.device_guid, v_receipt.registration_epoch,
                v_receipt.sequence, v_receipt.request_id, v_receipt.observed_utc_ticks,
                v_receipt.payload_hash, v_receipt.envelope_hash;
        ELSE
            RETURN QUERY SELECT 'IdentityConflict', 'AuthenticationFailed', NULL::uuid, NULL::integer,
                NULL::integer, NULL::uuid, NULL::bigint, NULL::bigint, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        END IF;
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1 FROM agent_private.receipts existing
         WHERE existing.environment_id = v_environment_id
           AND existing.registration_id = v_registration_id
           AND existing.registration_epoch = registration_epoch
           AND existing.request_id = ingest_attested_envelope.request_id) THEN
        RETURN QUERY SELECT 'IdentityConflict', 'AuthenticationFailed', NULL::uuid, NULL::integer,
            NULL::integer, NULL::uuid, NULL::bigint, NULL::bigint, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END IF;

    BEGIN
        v_payload := pg_catalog.convert_from(payload_bytes, 'UTF8')::jsonb;
        IF pg_catalog.jsonb_typeof(v_payload) <> 'object' OR
           NOT (v_payload ?& ARRAY['schemaVersion','kind','body']) OR
           v_payload - ARRAY['schemaVersion','kind','body'] <> '{}'::jsonb OR
           pg_catalog.jsonb_typeof(v_payload->'schemaVersion') <> 'number' OR
           pg_catalog.jsonb_typeof(v_payload->'kind') <> 'number' OR
           pg_catalog.jsonb_typeof(v_payload->'body') <> 'object' THEN
            RAISE EXCEPTION USING ERRCODE = '22023';
        END IF;
        v_schema := (v_payload->>'schemaVersion')::integer;
        v_kind := (v_payload->>'kind')::integer;
        IF v_schema <> 1 OR v_kind NOT IN (0, 1) THEN
            RAISE EXCEPTION USING ERRCODE = '22023';
        END IF;

        IF v_kind = 0 THEN
            IF NOT ((v_payload->'body') ?& ARRAY['SchemaVersion','AgentVersion']) OR
               (v_payload->'body') - ARRAY['SchemaVersion','AgentVersion'] <> '{}'::jsonb OR
               pg_catalog.jsonb_typeof(v_payload->'body'->'SchemaVersion') <> 'number' OR
               (v_payload->'body'->>'SchemaVersion')::integer <> 1 OR
               pg_catalog.jsonb_typeof(v_payload->'body'->'AgentVersion') <> 'string' OR
               pg_catalog.length(v_payload->'body'->>'AgentVersion') NOT BETWEEN 1 AND 128 THEN
                RAISE EXCEPTION USING ERRCODE = '22023';
            END IF;
        ELSE
            IF NOT ((v_payload->'body') ?& ARRAY['SchemaVersion','CollectedAt','Collectors']) OR
               (v_payload->'body') - ARRAY['SchemaVersion','CollectedAt','Collectors'] <> '{}'::jsonb OR
               pg_catalog.jsonb_typeof(v_payload->'body'->'SchemaVersion') <> 'number' OR
               (v_payload->'body'->>'SchemaVersion')::integer <> 1 OR
               pg_catalog.jsonb_typeof(v_payload->'body'->'CollectedAt') <> 'string' OR
               (v_payload->'body'->>'CollectedAt')::timestamptz IS NULL OR
               pg_catalog.jsonb_typeof(v_payload->'body'->'Collectors') <> 'array' OR
               pg_catalog.jsonb_array_length(v_payload->'body'->'Collectors') > 32 THEN
                RAISE EXCEPTION USING ERRCODE = '22023';
            END IF;
            FOR v_collector IN SELECT value FROM pg_catalog.jsonb_array_elements(v_payload->'body'->'Collectors') LOOP
                IF pg_catalog.jsonb_typeof(v_collector) <> 'object' OR
                   NOT (v_collector ?& ARRAY['Collector','Status','Quality','Source','ObservedAt','Data','ItemCount','ErrorCode']) OR
                   v_collector - ARRAY['Collector','Status','Quality','Source','ObservedAt','Data','ItemCount','ErrorCode'] <> '{}'::jsonb OR
                   pg_catalog.jsonb_typeof(v_collector->'Collector') <> 'string' OR
                   pg_catalog.length(v_collector->>'Collector') NOT BETWEEN 1 AND 256 OR
                   v_collector->>'Collector' NOT IN ('basic-device','installed-software','hardware','bitlocker') OR
                   pg_catalog.jsonb_typeof(v_collector->'Source') <> 'string' OR
                   pg_catalog.length(v_collector->>'Source') NOT BETWEEN 1 AND 256 OR
                   pg_catalog.jsonb_typeof(v_collector->'Status') <> 'number' OR
                   (v_collector->>'Status')::integer NOT BETWEEN 0 AND 3 OR
                   pg_catalog.jsonb_typeof(v_collector->'Quality') <> 'number' OR
                   (v_collector->>'Quality')::integer NOT BETWEEN 0 AND 3 OR
                   pg_catalog.jsonb_typeof(v_collector->'ItemCount') <> 'number' OR
                   (v_collector->>'ItemCount')::integer NOT BETWEEN 0 AND 10000 OR
                   pg_catalog.jsonb_typeof(v_collector->'ObservedAt') <> 'string' OR
                   (v_collector->>'ObservedAt')::timestamptz IS NULL OR
                   NOT (v_collector->'ErrorCode' = 'null'::jsonb OR
                        v_collector->>'ErrorCode' IN ('timeout','collector_failed','output_limit_exceeded','invalid_output')) THEN
                    RAISE EXCEPTION USING ERRCODE = '22023';
                END IF;

                IF (v_collector->>'Status')::integer <> 0 THEN
                    IF v_collector->'Data' <> 'null'::jsonb OR (v_collector->>'ItemCount')::integer <> 0 THEN
                        RAISE EXCEPTION USING ERRCODE = '22023';
                    END IF;
                    IF v_collector->>'Collector' = 'bitlocker' AND (
                        (v_collector->>'Quality')::integer <> 1 OR v_collector->>'Source' <> 'bitlocker' OR
                        pg_catalog.jsonb_typeof(v_collector->'ErrorCode') <> 'string' OR
                        ((v_collector->>'Status')::integer = 1 AND v_collector->>'ErrorCode' <> 'timeout') OR
                        ((v_collector->>'Status')::integer = 2 AND v_collector->>'ErrorCode' NOT IN ('collector_failed','invalid_output')) OR
                        ((v_collector->>'Status')::integer = 3 AND v_collector->>'ErrorCode' <> 'output_limit_exceeded')) THEN
                        RAISE EXCEPTION USING ERRCODE = '22023';
                    END IF;
                    CONTINUE;
                END IF;
                v_data := v_collector->'Data';
                IF pg_catalog.jsonb_typeof(v_data) <> 'object' OR v_collector->'ErrorCode' <> 'null'::jsonb THEN
                    RAISE EXCEPTION USING ERRCODE = '22023';
                END IF;

                IF v_collector->>'Collector' = 'basic-device' THEN
                    IF NOT (v_data ?& ARRAY['HostName','OperatingSystem','NetworkInterfaces','IsTruncated']) OR
                       v_data - ARRAY['HostName','OperatingSystem','NetworkInterfaces','IsTruncated'] <> '{}'::jsonb OR
                       pg_catalog.jsonb_typeof(v_data->'HostName') <> 'string' OR pg_catalog.length(v_data->>'HostName') > 512 OR
                       pg_catalog.jsonb_typeof(v_data->'IsTruncated') <> 'boolean' OR
                       pg_catalog.jsonb_typeof(v_data->'OperatingSystem') <> 'object' OR
                       NOT ((v_data->'OperatingSystem') ?& ARRAY['Description','Version','Architecture']) OR
                       (v_data->'OperatingSystem') - ARRAY['Description','Version','Architecture'] <> '{}'::jsonb OR
                       EXISTS (SELECT 1 FROM pg_catalog.jsonb_each(v_data->'OperatingSystem') property
                               WHERE pg_catalog.jsonb_typeof(property.value) <> 'string' OR
                                     pg_catalog.length(property.value #>> '{}') > 512) OR
                       pg_catalog.jsonb_typeof(v_data->'NetworkInterfaces') <> 'array' OR
                       pg_catalog.jsonb_array_length(v_data->'NetworkInterfaces') > 64 THEN
                        RAISE EXCEPTION USING ERRCODE = '22023';
                    END IF;
                    FOR v_item IN SELECT value FROM pg_catalog.jsonb_array_elements(v_data->'NetworkInterfaces') LOOP
                        IF pg_catalog.jsonb_typeof(v_item) <> 'object' OR
                           NOT (v_item ?& ARRAY['Name','InterfaceType','Addresses','Gateways','DnsServers','MacAddress']) OR
                           v_item - ARRAY['Name','InterfaceType','Addresses','Gateways','DnsServers','MacAddress'] <> '{}'::jsonb OR
                           pg_catalog.jsonb_typeof(v_item->'Name') <> 'string' OR pg_catalog.length(v_item->>'Name') > 512 OR
                           pg_catalog.jsonb_typeof(v_item->'InterfaceType') <> 'string' OR pg_catalog.length(v_item->>'InterfaceType') > 512 OR
                           NOT (v_item->'MacAddress' = 'null'::jsonb OR
                               (pg_catalog.jsonb_typeof(v_item->'MacAddress') = 'string' AND pg_catalog.length(v_item->>'MacAddress') <= 512)) OR
                           EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(v_item->'Addresses') e
                                   WHERE pg_catalog.jsonb_typeof(e.value) <> 'string' OR pg_catalog.length(e.value #>> '{}') > 512) OR
                           EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(v_item->'Gateways') e
                                   WHERE pg_catalog.jsonb_typeof(e.value) <> 'string' OR pg_catalog.length(e.value #>> '{}') > 512) OR
                           EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(v_item->'DnsServers') e
                                   WHERE pg_catalog.jsonb_typeof(e.value) <> 'string' OR pg_catalog.length(e.value #>> '{}') > 512) OR
                           pg_catalog.jsonb_array_length(v_item->'Addresses') > 32 OR
                           pg_catalog.jsonb_array_length(v_item->'Gateways') > 32 OR
                           pg_catalog.jsonb_array_length(v_item->'DnsServers') > 32 THEN
                            RAISE EXCEPTION USING ERRCODE = '22023';
                        END IF;
                    END LOOP;
                ELSIF v_collector->>'Collector' = 'installed-software' THEN
                    IF NOT (v_data ?& ARRAY['Applications','IsTruncated']) OR
                       v_data - ARRAY['Applications','IsTruncated'] <> '{}'::jsonb OR
                       pg_catalog.jsonb_typeof(v_data->'Applications') <> 'array' OR
                       pg_catalog.jsonb_array_length(v_data->'Applications') > 10000 OR
                       pg_catalog.jsonb_typeof(v_data->'IsTruncated') <> 'boolean' THEN
                        RAISE EXCEPTION USING ERRCODE = '22023';
                    END IF;
                    FOR v_item IN SELECT value FROM pg_catalog.jsonb_array_elements(v_data->'Applications') LOOP
                        IF pg_catalog.jsonb_typeof(v_item) <> 'object' OR
                           NOT (v_item ?& ARRAY['Name','Version','Publisher','InstallDate','Architecture']) OR
                           v_item - ARRAY['Name','Version','Publisher','InstallDate','Architecture'] <> '{}'::jsonb OR
                           pg_catalog.jsonb_typeof(v_item->'Name') <> 'string' OR pg_catalog.length(v_item->>'Name') NOT BETWEEN 1 AND 512 OR
                           pg_catalog.jsonb_typeof(v_item->'Architecture') <> 'string' OR v_item->>'Architecture' NOT IN ('x86','x64') OR
                           EXISTS (SELECT 1 FROM pg_catalog.jsonb_each(v_item) property
                                   WHERE property.key IN ('Version','Publisher','InstallDate') AND
                                         NOT (property.value = 'null'::jsonb OR
                                             (pg_catalog.jsonb_typeof(property.value) = 'string' AND pg_catalog.length(property.value #>> '{}') <= 512))) THEN
                            RAISE EXCEPTION USING ERRCODE = '22023';
                        END IF;
                    END LOOP;
                ELSIF v_collector->>'Collector' = 'bitlocker' THEN
                    IF v_collector->>'Source' <> 'root\cimv2\Security\MicrosoftVolumeEncryption:Win32_EncryptableVolume' OR
                       NOT (v_data ?& ARRAY['SchemaVersion','Volumes','IsTruncated','ErrorCode']) OR
                       v_data - ARRAY['SchemaVersion','Volumes','IsTruncated','ErrorCode'] <> '{}'::jsonb OR
                       pg_catalog.jsonb_typeof(v_data->'SchemaVersion') <> 'number' OR
                       v_data->>'SchemaVersion' <> '1' OR
                       pg_catalog.jsonb_typeof(v_data->'Volumes') <> 'array' OR
                       pg_catalog.jsonb_array_length(v_data->'Volumes') > 128 OR
                       (v_collector->>'ItemCount')::integer <> pg_catalog.jsonb_array_length(v_data->'Volumes') OR
                       pg_catalog.jsonb_typeof(v_data->'IsTruncated') <> 'boolean' OR
                       (v_collector->>'Quality')::integer = 2 THEN
                        RAISE EXCEPTION USING ERRCODE = '22023';
                    END IF;
                    IF (v_collector->>'Quality')::integer = 0 THEN
                        IF v_data->'ErrorCode' <> 'null'::jsonb THEN RAISE EXCEPTION USING ERRCODE = '22023'; END IF;
                    ELSE
                        IF pg_catalog.jsonb_array_length(v_data->'Volumes') <> 0 OR v_data->'IsTruncated' <> 'false'::jsonb OR
                           pg_catalog.jsonb_typeof(v_data->'ErrorCode') <> 'string' OR
                           ((v_collector->>'Quality')::integer = 3 AND v_data->>'ErrorCode' <> 'access_denied') OR
                           ((v_collector->>'Quality')::integer = 1 AND v_data->>'ErrorCode' NOT IN ('query_timeout','query_unavailable','native_query_busy','invalid_output')) THEN
                            RAISE EXCEPTION USING ERRCODE = '22023';
                        END IF;
                    END IF;
                    FOR v_row IN SELECT value FROM pg_catalog.jsonb_array_elements(v_data->'Volumes') LOOP
                        IF pg_catalog.jsonb_typeof(v_row) <> 'object' OR
                           NOT (v_row ?& ARRAY['DeviceId','PersistentVolumeId','DriveLetter','VolumeType','ProtectionStatus','ConversionStatus','EncryptionMethod','IsVolumeInitializedForProtection']) OR
                           v_row - ARRAY['DeviceId','PersistentVolumeId','DriveLetter','VolumeType','ProtectionStatus','ConversionStatus','EncryptionMethod','IsVolumeInitializedForProtection'] <> '{}'::jsonb OR
                           pg_catalog.jsonb_typeof(v_row->'DeviceId') <> 'string' OR
                           pg_catalog.length(pg_catalog.btrim(v_row->>'DeviceId')) = 0 OR
                           pg_catalog.length(v_row->>'DeviceId') > 512 OR (v_row->>'DeviceId') ~ '[[:cntrl:]]' OR
                           NOT (v_row->'PersistentVolumeId' = 'null'::jsonb OR
                               (pg_catalog.jsonb_typeof(v_row->'PersistentVolumeId') = 'string' AND
                                pg_catalog.length(v_row->>'PersistentVolumeId') <= 512 AND (v_row->>'PersistentVolumeId') !~ '[[:cntrl:]]')) OR
                           NOT (v_row->'DriveLetter' = 'null'::jsonb OR
                               (pg_catalog.jsonb_typeof(v_row->'DriveLetter') = 'string' AND (v_row->>'DriveLetter') ~ '^[A-Z]:$')) OR
                           NOT (v_row->'IsVolumeInitializedForProtection' = 'null'::jsonb OR pg_catalog.jsonb_typeof(v_row->'IsVolumeInitializedForProtection') = 'boolean') OR
                           EXISTS (SELECT 1 FROM pg_catalog.jsonb_each(v_row) property
                               WHERE property.key IN ('VolumeType','ProtectionStatus','ConversionStatus','EncryptionMethod') AND
                               NOT (property.value = 'null'::jsonb OR
                                   (pg_catalog.jsonb_typeof(property.value) = 'number' AND (property.value #>> '{}') ~ '^[0-9]+$' AND
                                    (property.value #>> '{}')::numeric <= 4294967295))) THEN
                            RAISE EXCEPTION USING ERRCODE = '22023';
                        END IF;
                    END LOOP;
                    IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(v_data->'Volumes') row
                        GROUP BY pg_catalog.lower(row->>'DeviceId') HAVING count(*) > 1) THEN
                        RAISE EXCEPTION USING ERRCODE = '22023';
                    END IF;
                ELSIF v_collector->>'Collector' = 'hardware' THEN
                    IF NOT (v_data ?& ARRAY['SchemaVersion','Sections']) OR
                       v_data - ARRAY['SchemaVersion','Sections'] <> '{}'::jsonb OR
                       pg_catalog.jsonb_typeof(v_data->'SchemaVersion') <> 'number' OR
                       (v_data->>'SchemaVersion')::integer <> 1 OR
                       pg_catalog.jsonb_typeof(v_data->'Sections') <> 'array' OR
                       pg_catalog.jsonb_array_length(v_data->'Sections') > 9 THEN
                        RAISE EXCEPTION USING ERRCODE = '22023';
                    END IF;
                    FOR v_section IN SELECT value FROM pg_catalog.jsonb_array_elements(v_data->'Sections') LOOP
                        IF pg_catalog.jsonb_typeof(v_section) <> 'object' OR
                           NOT (v_section ?& ARRAY['Kind','Source','Quality','ObservedAt','Rows','IsTruncated','ErrorCode']) OR
                           v_section - ARRAY['Kind','Source','Quality','ObservedAt','Rows','IsTruncated','ErrorCode'] <> '{}'::jsonb OR
                           pg_catalog.jsonb_typeof(v_section->'Kind') <> 'number' OR
                           (v_section->>'Kind')::integer NOT BETWEEN 0 AND 8 OR
                           pg_catalog.jsonb_typeof(v_section->'Quality') <> 'number' OR
                           (v_section->>'Quality')::integer NOT BETWEEN 0 AND 3 OR
                           pg_catalog.jsonb_typeof(v_section->'ObservedAt') <> 'string' OR
                           (v_section->>'ObservedAt')::timestamptz IS NULL OR
                           pg_catalog.jsonb_typeof(v_section->'Rows') <> 'array' OR
                           pg_catalog.jsonb_array_length(v_section->'Rows') > 128 OR
                           pg_catalog.jsonb_typeof(v_section->'IsTruncated') <> 'boolean' OR
                           NOT (v_section->'ErrorCode' = 'null'::jsonb OR
                               v_section->>'ErrorCode' IN ('access_denied','query_timeout','query_unavailable')) THEN
                            RAISE EXCEPTION USING ERRCODE = '22023';
                        END IF;
                        CASE (v_section->>'Kind')::integer
                            WHEN 0 THEN v_expected_source := 'Win32_ComputerSystem'; v_allowed_keys := ARRAY['Manufacturer','Model','TotalPhysicalMemory'];
                            WHEN 1 THEN v_expected_source := 'Win32_ComputerSystemProduct'; v_allowed_keys := ARRAY['UUID'];
                            WHEN 2 THEN v_expected_source := 'Win32_BIOS'; v_allowed_keys := ARRAY['Manufacturer','SerialNumber','SMBIOSBIOSVersion','ReleaseDate'];
                            WHEN 3 THEN v_expected_source := 'Win32_OperatingSystem'; v_allowed_keys := ARRAY['Caption','Version','BuildNumber','InstallDate','LastBootUpTime'];
                            WHEN 4 THEN v_expected_source := 'Win32_Processor'; v_allowed_keys := ARRAY['Name','Manufacturer','NumberOfCores','NumberOfLogicalProcessors'];
                            WHEN 5 THEN v_expected_source := 'Win32_PhysicalMemory'; v_allowed_keys := ARRAY['BankLabel','DeviceLocator','Capacity','Speed'];
                            WHEN 6 THEN v_expected_source := 'Win32_VideoController'; v_allowed_keys := ARRAY['Name','AdapterRAM'];
                            WHEN 7 THEN v_expected_source := 'Win32_DiskDrive'; v_allowed_keys := ARRAY['Model','SerialNumber','Size','MediaType'];
                            WHEN 8 THEN v_expected_source := 'Win32_Battery'; v_allowed_keys := ARRAY['Name','EstimatedChargeRemaining','DesignCapacity','FullChargeCapacity'];
                        END CASE;
                        IF v_section->>'Source' <> v_expected_source OR
                           ((v_section->>'Quality')::integer <> 0 AND pg_catalog.jsonb_array_length(v_section->'Rows') <> 0) THEN
                            RAISE EXCEPTION USING ERRCODE = '22023';
                        END IF;
                        FOR v_row IN SELECT value FROM pg_catalog.jsonb_array_elements(v_section->'Rows') LOOP
                            IF pg_catalog.jsonb_typeof(v_row) <> 'object' OR
                               NOT (v_row ?& v_allowed_keys) OR v_row - v_allowed_keys <> '{}'::jsonb OR EXISTS (
                                   SELECT 1 FROM pg_catalog.jsonb_each(v_row) property
                                   WHERE NOT (property.value = 'null'::jsonb OR
                                       pg_catalog.jsonb_typeof(property.value) = 'boolean' OR
                                       (pg_catalog.jsonb_typeof(property.value) = 'string' AND pg_catalog.length(property.value #>> '{}') <= 512) OR
                                       (pg_catalog.jsonb_typeof(property.value) = 'number' AND
                                        (property.value #>> '{}') ~ '^[0-9]+$' AND
                                        (property.value #>> '{}')::numeric <= 18446744073709551615))) THEN
                                RAISE EXCEPTION USING ERRCODE = '22023';
                            END IF;
                        END LOOP;
                    END LOOP;
                END IF;
            END LOOP;
        END IF;
    EXCEPTION WHEN SQLSTATE '22007' OR SQLSTATE '22008' OR SQLSTATE '22021' OR
                          SQLSTATE '22P02' OR SQLSTATE '22023' OR SQLSTATE '22003' THEN
        RETURN QUERY SELECT 'PermanentRejected', 'ProtocolRejected', NULL::uuid, NULL::integer,
            NULL::integer, NULL::uuid, NULL::bigint, NULL::bigint, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END;

    v_now_ticks := (EXTRACT(epoch FROM v_now) * 10000000)::bigint + 621355968000000000;
    IF observed_utc_ticks < 0 OR observed_utc_ticks > 3155378975999999999 OR
       observed_utc_ticks > v_now_ticks + 3000000000 OR
       (v_kind = 1 AND observed_utc_ticks < v_now_ticks - 25920000000000) THEN
        RETURN QUERY SELECT 'PermanentRejected', 'ProtocolRejected', NULL::uuid, NULL::integer,
            NULL::integer, NULL::uuid, NULL::bigint, NULL::bigint, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END IF;

    IF sequence <= v_high_sequence - 128 THEN
        RETURN QUERY SELECT 'PermanentRejected', 'ProtocolRejected', NULL::uuid, NULL::integer,
            NULL::integer, NULL::uuid, NULL::bigint, NULL::bigint, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END IF;

    v_receipt_id := pg_catalog.gen_random_uuid();
    INSERT INTO agent_private.receipts(
        environment_id, registration_id, registration_epoch, sequence, receipt_id, device_id,
        binding_id, hash_version, protocol_version, device_guid, request_id, observed_utc_ticks,
        received_at, payload_hash, envelope_hash, kind, schema_version)
    VALUES (
        v_environment_id, v_registration_id, registration_epoch, sequence, v_receipt_id, v_device_id,
        v_binding_id, 2, protocol_version, device_guid, request_id, observed_utc_ticks,
        v_now, payload_hash, envelope_hash, v_kind, v_schema);
    UPDATE agent_private.replay_state replay
       SET high_sequence = GREATEST(replay.high_sequence, sequence)
     WHERE replay.environment_id = v_environment_id
       AND replay.registration_id = v_registration_id
       AND replay.registration_epoch = registration_epoch;

    IF v_kind = 0 THEN
        IF observed_utc_ticks >= v_now_ticks - 3000000000 THEN
            UPDATE agent_private.devices device
               SET last_seen_at = v_now,
                   last_heartbeat_receipt_id = v_receipt_id
             WHERE device.environment_id = v_environment_id
               AND device.device_id = v_device_id;
        END IF;
    ELSE
        INSERT INTO agent_private.snapshot_history(
            environment_id, registration_id, registration_epoch, sequence, receipt_id, normalized_payload)
        VALUES (v_environment_id, v_registration_id, registration_epoch, sequence, v_receipt_id, v_payload->'body');
        INSERT INTO agent_private.inventory_projection(
            environment_id, device_id, registration_id, registration_epoch, sequence, receipt_id, normalized_payload)
        VALUES (v_environment_id, v_device_id, v_registration_id, registration_epoch, sequence, v_receipt_id, v_payload->'body')
        ON CONFLICT ON CONSTRAINT inventory_projection_pkey DO UPDATE
            SET registration_id = EXCLUDED.registration_id,
                registration_epoch = EXCLUDED.registration_epoch,
                sequence = EXCLUDED.sequence,
                receipt_id = EXCLUDED.receipt_id,
                normalized_payload = EXCLUDED.normalized_payload
            WHERE (EXCLUDED.registration_epoch, EXCLUDED.sequence) >
                  (agent_private.inventory_projection.registration_epoch, agent_private.inventory_projection.sequence);
    END IF;

    RETURN QUERY SELECT 'Accepted', 'None', v_receipt_id, 1, protocol_version,
        device_guid, registration_epoch, sequence, request_id, observed_utc_ticks,
        payload_hash, envelope_hash;
END;
$function$;

ALTER FUNCTION agent_private.ingest_attested_envelope(bytea,integer,uuid,bigint,bigint,uuid,bigint,bytea,text,text)
    OWNER TO :"agent_definer_role";
REVOKE ALL ON FUNCTION agent_private.ingest_attested_envelope(bytea,integer,uuid,bigint,bigint,uuid,bigint,bytea,text,text)
    FROM PUBLIC;

-- Optional extension guard. The conditional query is prepared only when the extension exists.
CREATE OR REPLACE FUNCTION agent_private.platform_grant_role_is_unbound(p_role name)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, agent_private, pg_temp
AS $function$
DECLARE v_unbound boolean;
BEGIN
    IF p_role IS NULL OR NOT (COALESCE((SELECT
    helper.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER::name) AND
    helper.proowner=namespace.nspowner AND helper.prosecdef AND helper.prokind='f' AND
    NOT helper.proretset AND helper.prorettype='boolean'::pg_catalog.regtype AND
    helper.proargnames=ARRAY['p_role']::text[] AND
    helper.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
    NOT EXISTS(
      SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
      WHERE acl.privilege_type<>'EXECUTE' OR grantee.oid IS NULL OR
        (acl.grantee<>helper.proowner AND acl.is_grantable) OR
        grantee.rolcanlogin OR grantee.rolsuper OR grantee.rolbypassrls OR grantee.rolcreatedb OR
        grantee.rolcreaterole OR grantee.rolinherit OR grantee.rolreplication OR
        EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=grantee.oid OR member.roleid=grantee.oid) OR
        acl.grantee NOT IN(
          SELECT helper.proowner UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
          WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                            pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)')))) AND
    NOT EXISTS(
      SELECT 1 FROM(
        SELECT helper.proowner AS oid UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
        WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                          pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)'))) expected
      WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
                       WHERE acl.grantee=expected.oid AND acl.privilege_type='EXECUTE'))
    FROM pg_catalog.pg_proc helper JOIN pg_catalog.pg_namespace namespace ON namespace.oid=helper.pronamespace
    WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.platform_grant_role_is_unbound(name)')),false)) THEN
        RETURN false;
    END IF;
    IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc function
        JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner
        WHERE owner.rolname=p_role AND function.oid IN(
            pg_catalog.to_regprocedure('agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamp with time zone,bytea,bytea)'),
            pg_catalog.to_regprocedure('agent_private.audit_platform_grant_privileges(uuid,name,name)'))) THEN
        RETURN false;
    END IF;
    IF pg_catalog.to_regclass('agent_private.platform_grant_database_bindings') IS NULL THEN
        RETURN true;
    END IF;
    EXECUTE 'SELECT NOT EXISTS (SELECT 1 FROM agent_private.platform_grant_database_bindings WHERE login_role = $1)'
        INTO v_unbound USING p_role;
    RETURN v_unbound;
END;
$function$;
ALTER FUNCTION agent_private.platform_grant_role_is_unbound(name) OWNER TO :"agent_definer_role";
REVOKE ALL ON FUNCTION agent_private.platform_grant_role_is_unbound(name) FROM PUBLIC;

CREATE OR REPLACE FUNCTION agent_private.audit_ingest_privileges(expected_definer name)
RETURNS TABLE (
    login_exists boolean,
    attributes_too_broad boolean,
    has_role_membership boolean,
    binding_valid boolean,
    has_direct_object_privilege boolean,
    function_execute_granted boolean,
    function_owner_matches boolean,
    definer_attributes_too_broad boolean,
    definer_has_membership boolean,
    function_security_definer boolean,
    function_search_path_valid boolean,
    schema_create_granted boolean,
    login_owns_database_or_schema boolean,
    unexpected_function_execute boolean,
    table_security_valid boolean)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, agent_private, pg_temp
AS $function$
    SELECT
        role.oid IS NOT NULL,
        COALESCE(role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR
                 role.rolinherit OR role.rolreplication, true),
        EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members membership
                WHERE membership.member = role.oid OR membership.roleid = role.oid),
        EXISTS (
            SELECT 1 FROM agent_private.agent_database_bindings binding
            WHERE binding.login_role = SESSION_USER::name
              AND binding.purpose = 'Ingest')
          AND agent_private.platform_grant_role_is_unbound(SESSION_USER::name)
          AND agent_private.platform_grant_role_is_unbound(expected_definer)
          AND (COALESCE((SELECT
    helper.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=expected_definer) AND
    helper.proowner=namespace.nspowner AND helper.prosecdef AND helper.prokind='f' AND
    NOT helper.proretset AND helper.prorettype='boolean'::pg_catalog.regtype AND
    helper.proargnames=ARRAY['p_role']::text[] AND
    helper.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
    NOT EXISTS(
      SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
      WHERE acl.privilege_type<>'EXECUTE' OR grantee.oid IS NULL OR
        (acl.grantee<>helper.proowner AND acl.is_grantable) OR
        grantee.rolcanlogin OR grantee.rolsuper OR grantee.rolbypassrls OR grantee.rolcreatedb OR
        grantee.rolcreaterole OR grantee.rolinherit OR grantee.rolreplication OR
        EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=grantee.oid OR member.roleid=grantee.oid) OR
        acl.grantee NOT IN(
          SELECT helper.proowner UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
          WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                            pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)')))) AND
    NOT EXISTS(
      SELECT 1 FROM(
        SELECT helper.proowner AS oid UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
        WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                          pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)'))) expected
      WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
                       WHERE acl.grantee=expected.oid AND acl.privilege_type='EXECUTE'))
    FROM pg_catalog.pg_proc helper JOIN pg_catalog.pg_namespace namespace ON namespace.oid=helper.pronamespace
    WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.platform_grant_role_is_unbound(name)')),false)),
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class object
            JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object.relnamespace
            WHERE namespace.nspname = 'agent_private'
              AND object.relkind IN ('r','p','S','v','m')
              AND (pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'SELECT')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'INSERT')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'UPDATE')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'DELETE')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'TRUNCATE')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'REFERENCES')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'TRIGGER'))),
        pg_catalog.has_function_privilege(
            SESSION_USER,
            'agent_private.ingest_attested_envelope(bytea,integer,uuid,bigint,bigint,uuid,bigint,bytea,text,text)'::pg_catalog.regprocedure,
            'EXECUTE'),
        function_owner.rolname = expected_definer,
        COALESCE(definer.rolcanlogin OR definer.rolsuper OR definer.rolbypassrls OR definer.rolcreatedb OR
                 definer.rolcreaterole OR definer.rolinherit OR definer.rolreplication, true),
        EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members membership
                WHERE membership.member = definer.oid OR membership.roleid = definer.oid),
        function_owner.prosecdef,
        function_owner.proconfig = ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[],
        pg_catalog.has_schema_privilege(SESSION_USER, 'agent_private', 'CREATE'),
        schema_owner.rolname = role.rolname OR database_owner.rolname = role.rolname,
        EXISTS (
            SELECT 1 FROM pg_catalog.pg_proc callable
            WHERE callable.pronamespace = function_owner.pronamespace
              AND callable.oid NOT IN (
                  'agent_private.ingest_attested_envelope(bytea,integer,uuid,bigint,bigint,uuid,bigint,bytea,text,text)'::pg_catalog.regprocedure,
                  'agent_private.audit_ingest_privileges(name)'::pg_catalog.regprocedure)
              AND pg_catalog.has_function_privilege(SESSION_USER, callable.oid, 'EXECUTE')),
        (SELECT pg_catalog.count(*) = 8 AND pg_catalog.bool_and(
                    object.relowner = definer.oid AND object.relrowsecurity AND object.relforcerowsecurity AND
                    EXISTS (SELECT 1 FROM pg_catalog.pg_policy policy
                            WHERE policy.polrelid = object.oid AND policy.polname = 'definer_all' AND
                                  policy.polcmd = '*' AND policy.polpermissive AND
                                  policy.polroles = ARRAY[definer.oid]::oid[] AND
                                  pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) = 'true' AND
                                  pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid) = 'true'))
         FROM pg_catalog.pg_class object
         WHERE object.relnamespace = function_owner.pronamespace AND object.relkind = 'r' AND
               object.relname = ANY (ARRAY['agent_database_bindings','devices','registrations','certificate_bindings',
                                           'replay_state','receipts','snapshot_history','inventory_projection']))
    FROM (SELECT SESSION_USER::name AS login_role) session
    LEFT JOIN pg_catalog.pg_roles role ON role.rolname = session.login_role
    LEFT JOIN pg_catalog.pg_roles definer ON definer.rolname = expected_definer
    CROSS JOIN LATERAL (
        SELECT owner.rolname
        FROM pg_catalog.pg_namespace namespace
        JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
        WHERE namespace.nspname = 'agent_private'
    ) schema_owner
    CROSS JOIN LATERAL (
        SELECT owner.rolname
        FROM pg_catalog.pg_database database
        JOIN pg_catalog.pg_roles owner ON owner.oid = database.datdba
        WHERE database.datname = pg_catalog.current_database()
    ) database_owner
    CROSS JOIN LATERAL (
        SELECT owner.rolname, function.prosecdef, function.proconfig, function.pronamespace
        FROM pg_catalog.pg_proc function
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = function.pronamespace
        JOIN pg_catalog.pg_roles owner ON owner.oid = function.proowner
        WHERE namespace.nspname = 'agent_private'
          AND function.oid =
              'agent_private.ingest_attested_envelope(bytea,integer,uuid,bigint,bigint,uuid,bigint,bytea,text,text)'::pg_catalog.regprocedure
    ) function_owner;
$function$;

ALTER FUNCTION agent_private.audit_ingest_privileges(name) OWNER TO :"agent_definer_role";
REVOKE ALL ON FUNCTION agent_private.audit_ingest_privileges(name) FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA agent_private FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA agent_private FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA agent_private FROM PUBLIC;
