\set ON_ERROR_STOP on

BEGIN;

ALTER TABLE agent_private.devices
    ADD COLUMN IF NOT EXISTS next_registration_epoch bigint NOT NULL DEFAULT 1 CHECK (next_registration_epoch > 0);

CREATE TABLE agent_private.enrollment_database_bindings (
    login_role name PRIMARY KEY,
    environment_id uuid NOT NULL,
    purpose text NOT NULL CHECK (purpose IN ('Enroll','Issue')),
    UNIQUE (environment_id, purpose)
);

CREATE TABLE agent_private.enrollment_grants (
    environment_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    token_sha256 bytea NOT NULL UNIQUE CHECK (pg_catalog.octet_length(token_sha256) = 32),
    state text NOT NULL CHECK (state IN ('Available','Consumed','Revoked')),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,
    revoked_at timestamptz NULL,
    consumed_request_id uuid NULL,
    PRIMARY KEY (environment_id, grant_id),
    UNIQUE (environment_id, grant_id, device_id),
    FOREIGN KEY (environment_id, device_id) REFERENCES agent_private.devices(environment_id, device_id),
    CHECK (expires_at > created_at),
    CHECK ((state = 'Available' AND consumed_at IS NULL AND revoked_at IS NULL AND consumed_request_id IS NULL) OR
           (state = 'Consumed' AND consumed_at IS NOT NULL AND revoked_at IS NULL AND consumed_request_id IS NOT NULL) OR
           (state = 'Revoked' AND consumed_at IS NULL AND revoked_at IS NOT NULL AND consumed_request_id IS NULL))
);
CREATE UNIQUE INDEX enrollment_one_available_grant_per_device
    ON agent_private.enrollment_grants(environment_id, device_id) WHERE state = 'Available';

CREATE TABLE agent_private.enrollment_requests (
    environment_id uuid NOT NULL,
    request_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    device_guid uuid NOT NULL,
    csr_der bytea NOT NULL CHECK (pg_catalog.octet_length(csr_der) BETWEEN 1 AND 16384),
    csr_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(csr_sha256) = 32),
    spki_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(spki_sha256) = 32),
    profile_version integer NOT NULL CHECK (profile_version = 1),
    registration_id uuid NOT NULL,
    registration_epoch bigint NOT NULL CHECK (registration_epoch > 0),
    issuance_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('PendingIssuance','ExternalPending','Issued','OutcomeUnknown','PermanentFailed')),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    lease_token uuid NULL,
    lease_owner uuid NULL,
    lease_until timestamptz NULL,
    next_attempt_at timestamptz NULL,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    terminal_code text NULL CHECK (terminal_code IS NULL OR terminal_code IN ('IssuerOutcomeUnknown','IssuerPermanentFailure')),
    PRIMARY KEY (environment_id, request_id),
    UNIQUE (request_id),
    UNIQUE (issuance_id),
    UNIQUE (environment_id, grant_id),
    UNIQUE (environment_id, registration_id),
    UNIQUE (environment_id, device_id, registration_epoch),
    FOREIGN KEY (environment_id, grant_id, device_id)
        REFERENCES agent_private.enrollment_grants(environment_id, grant_id, device_id),
    FOREIGN KEY (environment_id, device_id) REFERENCES agent_private.devices(environment_id, device_id),
    CHECK ((state = 'ExternalPending' AND
            ((lease_token IS NOT NULL AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) OR
             (lease_token IS NULL AND lease_owner IS NULL AND lease_until IS NULL))) OR
           (state <> 'ExternalPending' AND lease_token IS NULL AND lease_owner IS NULL AND lease_until IS NULL))
);
CREATE UNIQUE INDEX enrollment_one_live_request_per_device
    ON agent_private.enrollment_requests(environment_id, device_id)
    WHERE state IN ('PendingIssuance','ExternalPending','Issued','OutcomeUnknown');
CREATE UNIQUE INDEX enrollment_one_live_request_per_device_guid
    ON agent_private.enrollment_requests(environment_id, device_guid)
    WHERE state IN ('PendingIssuance','ExternalPending','Issued','OutcomeUnknown');

CREATE TABLE agent_private.enrollment_results (
    environment_id uuid NOT NULL,
    request_id uuid NOT NULL,
    registration_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    leaf_der bytea NOT NULL CHECK (pg_catalog.octet_length(leaf_der) BETWEEN 1 AND 32768),
    intermediate_der bytea[] NOT NULL CHECK (pg_catalog.cardinality(intermediate_der) <= 8),
    leaf_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(leaf_sha256) = 32),
    leaf_spki_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(leaf_spki_sha256) = 32),
    serial_bytes bytea NOT NULL CHECK (pg_catalog.octet_length(serial_bytes) BETWEEN 1 AND 32),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (environment_id, request_id),
    UNIQUE (environment_id, registration_id),
    UNIQUE (environment_id, binding_id),
    FOREIGN KEY (environment_id, request_id) REFERENCES agent_private.enrollment_requests(environment_id, request_id),
    FOREIGN KEY (environment_id, registration_id) REFERENCES agent_private.registrations(environment_id, registration_id),
    FOREIGN KEY (environment_id, binding_id, registration_id)
        REFERENCES agent_private.certificate_bindings(environment_id, binding_id, registration_id),
    CHECK (not_before < not_after)
);

ALTER TABLE agent_private.enrollment_database_bindings OWNER TO :"agent_table_owner_role";
ALTER TABLE agent_private.enrollment_grants OWNER TO :"agent_table_owner_role";
ALTER TABLE agent_private.enrollment_requests OWNER TO :"agent_table_owner_role";
ALTER TABLE agent_private.enrollment_results OWNER TO :"agent_table_owner_role";

ALTER TABLE agent_private.enrollment_database_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.enrollment_database_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_private.enrollment_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.enrollment_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_private.enrollment_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.enrollment_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_private.enrollment_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.enrollment_results FORCE ROW LEVEL SECURITY;

CREATE POLICY definer_all ON agent_private.enrollment_database_bindings TO :"agent_table_owner_role" USING (true) WITH CHECK (true);
CREATE POLICY definer_all ON agent_private.enrollment_grants TO :"agent_table_owner_role" USING (true) WITH CHECK (true);
CREATE POLICY definer_all ON agent_private.enrollment_requests TO :"agent_table_owner_role" USING (true) WITH CHECK (true);
CREATE POLICY definer_all ON agent_private.enrollment_results TO :"agent_table_owner_role" USING (true) WITH CHECK (true);
CREATE POLICY enrollment_definer_access ON agent_private.enrollment_database_bindings TO :"agent_enrollment_definer_role" USING (true) WITH CHECK (true);
CREATE POLICY enrollment_definer_access ON agent_private.enrollment_grants TO :"agent_enrollment_definer_role" USING (true) WITH CHECK (true);
CREATE POLICY enrollment_definer_access ON agent_private.enrollment_requests TO :"agent_enrollment_definer_role" USING (true) WITH CHECK (true);
CREATE POLICY enrollment_definer_access ON agent_private.enrollment_results TO :"agent_enrollment_definer_role" USING (true) WITH CHECK (true);
CREATE POLICY enrollment_definer_access ON agent_private.devices TO :"agent_enrollment_definer_role" USING (true) WITH CHECK (true);
CREATE POLICY enrollment_definer_access ON agent_private.registrations TO :"agent_enrollment_definer_role" USING (true) WITH CHECK (true);
CREATE POLICY enrollment_definer_access ON agent_private.certificate_bindings TO :"agent_enrollment_definer_role" USING (true) WITH CHECK (true);

GRANT USAGE ON SCHEMA agent_private TO :"agent_enrollment_definer_role";
GRANT SELECT ON agent_private.enrollment_database_bindings TO :"agent_enrollment_definer_role";
GRANT SELECT, UPDATE ON agent_private.enrollment_grants TO :"agent_enrollment_definer_role";
GRANT SELECT, INSERT, UPDATE ON agent_private.enrollment_requests TO :"agent_enrollment_definer_role";
GRANT SELECT, INSERT ON agent_private.enrollment_results TO :"agent_enrollment_definer_role";
GRANT SELECT ON agent_private.devices, agent_private.registrations, agent_private.certificate_bindings TO :"agent_enrollment_definer_role";
GRANT UPDATE (next_registration_epoch) ON agent_private.devices TO :"agent_enrollment_definer_role";
GRANT INSERT ON agent_private.registrations, agent_private.certificate_bindings TO :"agent_enrollment_definer_role";

CREATE OR REPLACE FUNCTION agent_private.submit_or_recover_enrollment(
    p_raw_token bytea, p_request_id uuid, p_device_guid uuid, p_csr_der bytea,
    p_csr_sha256 bytea, p_spki_sha256 bytea, p_profile_version integer)
RETURNS TABLE(outcome text, diagnostic_code text, request_id uuid, issuance_id uuid,
    registration_id uuid, registration_epoch bigint, binding_id uuid, leaf_der bytea,
    intermediate_der bytea[], leaf_sha256 bytea, leaf_spki_sha256 bytea,
    serial_bytes bytea, not_before timestamptz, not_after timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_private, pg_temp
AS $function$
#variable_conflict use_variable
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_token_hash bytea;
    v_environment_id uuid;
    v_grant agent_private.enrollment_grants%ROWTYPE;
    v_request agent_private.enrollment_requests%ROWTYPE;
    v_result agent_private.enrollment_results%ROWTYPE;
    v_epoch bigint;
    v_max_epoch bigint;
    v_registration_id uuid;
    v_issuance_id uuid;
BEGIN
    IF p_raw_token IS NULL OR pg_catalog.octet_length(p_raw_token) <> 32 OR
       p_request_id IS NULL OR p_request_id = '00000000-0000-0000-0000-000000000000'::uuid OR
       p_device_guid IS NULL OR p_device_guid = '00000000-0000-0000-0000-000000000000'::uuid OR
       p_csr_der IS NULL OR pg_catalog.octet_length(p_csr_der) NOT BETWEEN 1 AND 16384 OR
       p_csr_sha256 IS NULL OR pg_catalog.octet_length(p_csr_sha256) <> 32 OR
       p_spki_sha256 IS NULL OR pg_catalog.octet_length(p_spki_sha256) <> 32 OR
       p_profile_version IS NULL OR p_profile_version <> 1 THEN
        RETURN QUERY SELECT 'PermanentRejected','ProtocolRejected',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,
            NULL::uuid,NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz;
        RETURN;
    END IF;
    IF pg_catalog.sha256(p_csr_der) <> p_csr_sha256 THEN
        RETURN QUERY SELECT 'IdentityConflict','AuthenticationFailed',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,
            NULL::uuid,NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz;
        RETURN;
    END IF;
    v_token_hash := pg_catalog.sha256(p_raw_token);
    SELECT enrollment_grant.environment_id INTO v_environment_id
      FROM agent_private.enrollment_grants enrollment_grant
      JOIN agent_private.enrollment_database_bindings binding ON binding.environment_id=enrollment_grant.environment_id
     WHERE enrollment_grant.token_sha256=v_token_hash AND binding.login_role=SESSION_USER::name AND binding.purpose='Enroll';
    IF v_environment_id IS NULL THEN
        RETURN QUERY SELECT 'PermanentRejected','AuthenticationFailed',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,
            NULL::uuid,NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz;
        RETURN;
    END IF;
    SELECT * INTO v_grant FROM agent_private.enrollment_grants enrollment_grant
     WHERE enrollment_grant.environment_id=v_environment_id AND enrollment_grant.token_sha256=v_token_hash FOR UPDATE;
    IF v_grant.state='Consumed' THEN
        SELECT * INTO v_request FROM agent_private.enrollment_requests request
         WHERE request.environment_id=v_environment_id AND request.grant_id=v_grant.grant_id FOR UPDATE;
        IF NOT FOUND OR v_grant.consumed_request_id<>p_request_id OR v_request.request_id<>p_request_id OR
           v_request.device_id<>v_grant.device_id OR v_request.device_guid<>p_device_guid OR
           v_request.csr_der<>p_csr_der OR v_request.csr_sha256<>p_csr_sha256 OR
           v_request.spki_sha256<>p_spki_sha256 OR v_request.profile_version<>p_profile_version THEN
            RETURN QUERY SELECT 'IdentityConflict','AuthenticationFailed',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,
                NULL::uuid,NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz;
            RETURN;
        END IF;
        IF v_request.state='Issued' THEN
            SELECT * INTO STRICT v_result FROM agent_private.enrollment_results result
             WHERE result.environment_id=v_environment_id AND result.request_id=v_request.request_id;
            RETURN QUERY SELECT 'Issued','None',v_request.request_id,v_request.issuance_id,v_request.registration_id,v_request.registration_epoch,
                v_result.binding_id,v_result.leaf_der,v_result.intermediate_der,v_result.leaf_sha256,v_result.leaf_spki_sha256,
                v_result.serial_bytes,v_result.not_before,v_result.not_after;
        ELSIF v_request.state='OutcomeUnknown' THEN
            RETURN QUERY SELECT 'RecoveryRequired','IssuerOutcomeUnknown',v_request.request_id,v_request.issuance_id,
                v_request.registration_id,v_request.registration_epoch,NULL::uuid,NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,
                NULL::bytea,NULL::timestamptz,NULL::timestamptz;
        ELSIF v_request.state='PermanentFailed' THEN
            RETURN QUERY SELECT 'PermanentRejected','IssuerPermanentFailure',v_request.request_id,v_request.issuance_id,
                v_request.registration_id,v_request.registration_epoch,NULL::uuid,NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,
                NULL::bytea,NULL::timestamptz,NULL::timestamptz;
        ELSE
            RETURN QUERY SELECT 'Pending','None',v_request.request_id,v_request.issuance_id,v_request.registration_id,
                v_request.registration_epoch,NULL::uuid,NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz;
        END IF;
        RETURN;
    END IF;
    IF v_grant.state<>'Available' OR v_grant.expires_at<=v_now THEN
        RETURN QUERY SELECT 'PermanentRejected','GrantUnavailable',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,
            NULL::uuid,NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz;
        RETURN;
    END IF;
    SELECT device.next_registration_epoch INTO v_epoch FROM agent_private.devices device
     WHERE device.environment_id=v_environment_id AND device.device_id=v_grant.device_id AND device.state='Active' FOR UPDATE;
    IF v_epoch IS NULL OR EXISTS (SELECT 1 FROM agent_private.registrations registration
        WHERE registration.environment_id=v_environment_id AND registration.device_id=v_grant.device_id AND registration.state='Active') OR
       EXISTS (SELECT 1 FROM agent_private.enrollment_requests request WHERE request.environment_id=v_environment_id AND
        request.device_id=v_grant.device_id AND request.state IN ('PendingIssuance','ExternalPending','Issued','OutcomeUnknown')) THEN
        RETURN QUERY SELECT 'PermanentRejected','DeviceUnavailable',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,
            NULL::uuid,NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz;
        RETURN;
    END IF;
    SELECT COALESCE(pg_catalog.max(registration.registration_epoch),0) INTO v_max_epoch
      FROM agent_private.registrations registration
     WHERE registration.environment_id=v_environment_id AND registration.device_id=v_grant.device_id;
    IF v_epoch=9223372036854775807 OR v_max_epoch=9223372036854775807 THEN
        RETURN QUERY SELECT 'PermanentRejected','DeviceUnavailable',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,
            NULL::uuid,NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz;
        RETURN;
    END IF;
    v_epoch:=GREATEST(v_epoch,v_max_epoch+1);
    v_registration_id:=pg_catalog.gen_random_uuid(); v_issuance_id:=pg_catalog.gen_random_uuid();
    UPDATE agent_private.devices AS target SET next_registration_epoch=v_epoch+1
     WHERE target.environment_id=v_environment_id AND target.device_id=v_grant.device_id;
    INSERT INTO agent_private.enrollment_requests(environment_id,request_id,grant_id,device_id,device_guid,csr_der,csr_sha256,
        spki_sha256,profile_version,registration_id,registration_epoch,issuance_id,state)
    VALUES(v_environment_id,p_request_id,v_grant.grant_id,v_grant.device_id,p_device_guid,p_csr_der,p_csr_sha256,
        p_spki_sha256,p_profile_version,v_registration_id,v_epoch,v_issuance_id,'PendingIssuance');
    UPDATE agent_private.enrollment_grants AS target SET state='Consumed',consumed_at=v_now,consumed_request_id=p_request_id
     WHERE target.environment_id=v_environment_id AND target.grant_id=v_grant.grant_id;
    RETURN QUERY SELECT 'Pending','None',p_request_id,v_issuance_id,v_registration_id,v_epoch,NULL::uuid,NULL::bytea,
        NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz;
END;
$function$;

CREATE OR REPLACE FUNCTION agent_private.claim_enrollment_issuance(p_environment_id uuid,p_worker_id uuid)
RETURNS TABLE(outcome text,diagnostic_code text,request_id uuid,issuance_id uuid,lease_token uuid,device_id uuid,
    device_guid uuid,registration_id uuid,registration_epoch bigint,csr_der bytea,csr_sha256 bytea,spki_sha256 bytea,profile_version integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_private, pg_temp AS $function$
DECLARE v_request agent_private.enrollment_requests%ROWTYPE; v_lease uuid; v_now timestamptz:=pg_catalog.clock_timestamp();
BEGIN
    IF p_environment_id IS NULL OR p_worker_id IS NULL OR p_worker_id='00000000-0000-0000-0000-000000000000'::uuid OR NOT EXISTS(
        SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE binding.login_role=SESSION_USER::name AND
        binding.environment_id=p_environment_id AND binding.purpose='Issue') THEN
        RETURN QUERY SELECT 'Unauthorized','AuthenticationFailed',NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid,
            NULL::uuid,NULL::bigint,NULL::bytea,NULL::bytea,NULL::bytea,NULL::integer; RETURN;
    END IF;
    SELECT * INTO v_request FROM agent_private.enrollment_requests request WHERE request.environment_id=p_environment_id AND
      ((request.state='PendingIssuance') OR (request.state='ExternalPending' AND
       (request.lease_until IS NULL OR request.lease_until<=v_now) AND
       (request.next_attempt_at IS NULL OR request.next_attempt_at<=v_now)))
      ORDER BY request.created_at,request.request_id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN QUERY SELECT 'None','None',NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid,
        NULL::uuid,NULL::bigint,NULL::bytea,NULL::bytea,NULL::bytea,NULL::integer; RETURN; END IF;
    v_lease:=pg_catalog.gen_random_uuid();
    UPDATE agent_private.enrollment_requests AS target SET state='ExternalPending',lease_token=v_lease,lease_owner=p_worker_id,
      lease_until=v_now+interval '5 minutes',next_attempt_at=NULL,updated_at=v_now,
      attempt_count=CASE WHEN attempt_count=2147483647 THEN attempt_count ELSE attempt_count+1 END
     WHERE target.environment_id=v_request.environment_id AND target.request_id=v_request.request_id;
    RETURN QUERY SELECT 'Claimed','None',v_request.request_id,v_request.issuance_id,v_lease,v_request.device_id,
      v_request.device_guid,v_request.registration_id,v_request.registration_epoch,v_request.csr_der,v_request.csr_sha256,
      v_request.spki_sha256,v_request.profile_version;
END;
$function$;

CREATE OR REPLACE FUNCTION agent_private.complete_enrollment_issuance(
    p_issuance_id uuid,p_lease_token uuid,p_environment_id uuid,p_device_id uuid,p_registration_id uuid,
    p_device_guid uuid,p_registration_epoch bigint,p_profile_version integer,p_leaf_der bytea,
    p_intermediate_der bytea[],p_leaf_sha256 bytea,p_leaf_spki_sha256 bytea,p_serial_bytes bytea,
    p_not_before timestamptz,p_not_after timestamptz)
RETURNS TABLE(outcome text,diagnostic_code text,request_id uuid,issuance_id uuid,registration_id uuid,
    registration_epoch bigint,binding_id uuid,leaf_der bytea,intermediate_der bytea[],leaf_sha256 bytea,
    leaf_spki_sha256 bytea,serial_bytes bytea,not_before timestamptz,not_after timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_private, pg_temp AS $function$
#variable_conflict use_variable
DECLARE v_request agent_private.enrollment_requests%ROWTYPE; v_result agent_private.enrollment_results%ROWTYPE;
    v_binding_id uuid; v_now timestamptz:=pg_catalog.clock_timestamp();
BEGIN
    IF p_issuance_id IS NULL OR p_issuance_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_lease_token IS NULL OR p_lease_token='00000000-0000-0000-0000-000000000000'::uuid OR
       p_environment_id IS NULL OR p_environment_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_device_id IS NULL OR p_device_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_registration_id IS NULL OR p_registration_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_device_guid IS NULL OR p_device_guid='00000000-0000-0000-0000-000000000000'::uuid OR
       p_registration_epoch IS NULL OR p_registration_epoch<=0 OR
       p_profile_version IS NULL OR p_profile_version<>1 OR
       p_leaf_der IS NULL OR pg_catalog.octet_length(p_leaf_der) NOT BETWEEN 1 AND 32768 OR
       p_intermediate_der IS NULL OR pg_catalog.cardinality(p_intermediate_der)>8 OR
       EXISTS(SELECT 1 FROM pg_catalog.unnest(p_intermediate_der) certificate WHERE certificate IS NULL OR
              pg_catalog.octet_length(certificate) NOT BETWEEN 1 AND 32768) OR
       (SELECT COALESCE(pg_catalog.sum(pg_catalog.octet_length(certificate)),0) FROM pg_catalog.unnest(p_intermediate_der) certificate)>131072 OR
       p_leaf_sha256 IS NULL OR pg_catalog.octet_length(p_leaf_sha256)<>32 OR pg_catalog.sha256(p_leaf_der)<>p_leaf_sha256 OR
       p_leaf_spki_sha256 IS NULL OR pg_catalog.octet_length(p_leaf_spki_sha256)<>32 OR
       p_serial_bytes IS NULL OR pg_catalog.octet_length(p_serial_bytes) NOT BETWEEN 1 AND 32 OR
       p_not_before IS NULL OR p_not_after IS NULL OR p_not_before>=p_not_after THEN
        RETURN QUERY SELECT 'PermanentRejected','ProtocolRejected',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,NULL::uuid,
          NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz; RETURN;
    END IF;
    SELECT * INTO v_request FROM agent_private.enrollment_requests request
     WHERE request.issuance_id=p_issuance_id AND request.environment_id=p_environment_id;
    IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding
      WHERE binding.login_role=SESSION_USER::name AND binding.environment_id=p_environment_id AND binding.purpose='Issue') THEN
        RETURN QUERY SELECT 'Unauthorized','AuthenticationFailed',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,NULL::uuid,
          NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz; RETURN;
    END IF;
    SELECT * INTO v_request FROM agent_private.enrollment_requests request
     WHERE request.environment_id=p_environment_id AND request.issuance_id=p_issuance_id FOR UPDATE;
    IF v_request.device_id<>p_device_id OR v_request.registration_id<>p_registration_id OR
       v_request.device_guid<>p_device_guid OR v_request.registration_epoch<>p_registration_epoch OR
       v_request.profile_version<>p_profile_version OR v_request.spki_sha256<>p_leaf_spki_sha256 THEN
        RETURN QUERY SELECT 'IdentityConflict','AuthenticationFailed',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,NULL::uuid,
          NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz; RETURN;
    END IF;
    IF v_request.state='Issued' THEN
        SELECT * INTO STRICT v_result FROM agent_private.enrollment_results result
         WHERE result.environment_id=p_environment_id AND result.request_id=v_request.request_id;
        IF v_result.registration_id=p_registration_id AND v_result.leaf_der=p_leaf_der AND
           v_result.intermediate_der=p_intermediate_der AND v_result.leaf_sha256=p_leaf_sha256 AND
           v_result.leaf_spki_sha256=p_leaf_spki_sha256 AND v_result.serial_bytes=p_serial_bytes AND
           v_result.not_before=p_not_before AND v_result.not_after=p_not_after THEN
            RETURN QUERY SELECT 'AlreadyIssued','None',v_request.request_id,v_request.issuance_id,v_request.registration_id,
              v_request.registration_epoch,v_result.binding_id,v_result.leaf_der,v_result.intermediate_der,v_result.leaf_sha256,
              v_result.leaf_spki_sha256,v_result.serial_bytes,v_result.not_before,v_result.not_after;
        ELSE
            RETURN QUERY SELECT 'IdentityConflict','AuthenticationFailed',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,NULL::uuid,
              NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz;
        END IF; RETURN;
    END IF;
    IF v_request.state<>'ExternalPending' OR v_request.lease_token IS DISTINCT FROM p_lease_token OR
       v_request.lease_until IS NULL OR v_request.lease_until<=v_now THEN
        RETURN QUERY SELECT 'RecoveryRequired','LeaseUnavailable',v_request.request_id,v_request.issuance_id,
          v_request.registration_id,v_request.registration_epoch,NULL::uuid,NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,
          NULL::bytea,NULL::timestamptz,NULL::timestamptz; RETURN;
    END IF;
    PERFORM 1 FROM agent_private.devices device WHERE device.environment_id=p_environment_id AND
      device.device_id=p_device_id AND device.state='Active' FOR UPDATE;
    IF NOT FOUND OR EXISTS(SELECT 1 FROM agent_private.registrations registration WHERE
      registration.environment_id=p_environment_id AND registration.device_id=p_device_id AND registration.state='Active') THEN
        RETURN QUERY SELECT 'IdentityConflict','DeviceUnavailable',NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,NULL::uuid,
          NULL::bytea,NULL::bytea[],NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz; RETURN;
    END IF;
    v_binding_id:=pg_catalog.gen_random_uuid();
    INSERT INTO agent_private.registrations(environment_id,registration_id,device_id,registration_epoch,device_guid,state)
      VALUES(p_environment_id,p_registration_id,p_device_id,p_registration_epoch,p_device_guid,'Active');
    INSERT INTO agent_private.certificate_bindings(environment_id,binding_id,registration_id,leaf_der_sha256,state,not_before,not_after)
      VALUES(p_environment_id,v_binding_id,p_registration_id,p_leaf_sha256,'Active',p_not_before,p_not_after);
    INSERT INTO agent_private.enrollment_results(environment_id,request_id,registration_id,binding_id,leaf_der,intermediate_der,
      leaf_sha256,leaf_spki_sha256,serial_bytes,not_before,not_after)
      VALUES(p_environment_id,v_request.request_id,p_registration_id,v_binding_id,p_leaf_der,p_intermediate_der,
      p_leaf_sha256,p_leaf_spki_sha256,p_serial_bytes,p_not_before,p_not_after);
    UPDATE agent_private.enrollment_requests AS target SET state='Issued',updated_at=v_now,lease_token=NULL,lease_owner=NULL,lease_until=NULL,
      next_attempt_at=NULL,terminal_code=NULL WHERE target.environment_id=p_environment_id AND target.request_id=v_request.request_id;
    RETURN QUERY SELECT 'Issued','None',v_request.request_id,v_request.issuance_id,p_registration_id,p_registration_epoch,
      v_binding_id,p_leaf_der,p_intermediate_der,p_leaf_sha256,p_leaf_spki_sha256,p_serial_bytes,p_not_before,p_not_after;
END;
$function$;

CREATE OR REPLACE FUNCTION agent_private.defer_enrollment_issuance(p_issuance_id uuid,p_lease_token uuid,p_retry_after_seconds integer)
RETURNS TABLE(outcome text,diagnostic_code text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_private, pg_temp AS $function$
DECLARE v_environment_id uuid; v_now timestamptz:=pg_catalog.clock_timestamp();
BEGIN
 SELECT request.environment_id INTO v_environment_id FROM agent_private.enrollment_requests request WHERE request.issuance_id=p_issuance_id;
 IF v_environment_id IS NULL OR NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE
   binding.login_role=SESSION_USER::name AND binding.environment_id=v_environment_id AND binding.purpose='Issue') THEN
   RETURN QUERY SELECT 'Unauthorized','AuthenticationFailed'; RETURN; END IF;
 IF p_retry_after_seconds IS NULL OR p_retry_after_seconds<1 THEN RETURN QUERY SELECT 'PermanentRejected','ProtocolRejected'; RETURN; END IF;
 UPDATE agent_private.enrollment_requests AS target SET lease_token=NULL,lease_owner=NULL,lease_until=NULL,
   next_attempt_at=v_now+pg_catalog.make_interval(secs=>LEAST(p_retry_after_seconds,3600)),updated_at=v_now
  WHERE target.issuance_id=p_issuance_id AND target.state='ExternalPending' AND target.lease_token=p_lease_token AND target.lease_until>v_now;
 RETURN QUERY SELECT CASE WHEN FOUND THEN 'Deferred' ELSE 'RecoveryRequired' END,
   CASE WHEN FOUND THEN 'None' ELSE 'LeaseUnavailable' END;
END;
$function$;

CREATE OR REPLACE FUNCTION agent_private.mark_enrollment_issuance_unknown(p_issuance_id uuid,p_lease_token uuid)
RETURNS TABLE(outcome text,diagnostic_code text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_private, pg_temp AS $function$
DECLARE v_environment_id uuid; v_now timestamptz:=pg_catalog.clock_timestamp();
BEGIN
 SELECT request.environment_id INTO v_environment_id FROM agent_private.enrollment_requests request WHERE request.issuance_id=p_issuance_id;
 IF v_environment_id IS NULL OR NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE
   binding.login_role=SESSION_USER::name AND binding.environment_id=v_environment_id AND binding.purpose='Issue') THEN
   RETURN QUERY SELECT 'Unauthorized','AuthenticationFailed'; RETURN; END IF;
 UPDATE agent_private.enrollment_requests AS target SET state='OutcomeUnknown',terminal_code='IssuerOutcomeUnknown',updated_at=v_now,
   lease_token=NULL,lease_owner=NULL,lease_until=NULL,next_attempt_at=NULL
  WHERE target.issuance_id=p_issuance_id AND target.state='ExternalPending' AND target.lease_token=p_lease_token AND target.lease_until>v_now;
 RETURN QUERY SELECT CASE WHEN FOUND THEN 'OutcomeUnknown' ELSE 'RecoveryRequired' END,
   CASE WHEN FOUND THEN 'IssuerOutcomeUnknown' ELSE 'LeaseUnavailable' END;
END;
$function$;

CREATE OR REPLACE FUNCTION agent_private.fail_enrollment_issuance_definitively(p_issuance_id uuid,p_lease_token uuid)
RETURNS TABLE(outcome text,diagnostic_code text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_private, pg_temp AS $function$
DECLARE v_environment_id uuid; v_now timestamptz:=pg_catalog.clock_timestamp();
BEGIN
 SELECT request.environment_id INTO v_environment_id FROM agent_private.enrollment_requests request WHERE request.issuance_id=p_issuance_id;
 IF v_environment_id IS NULL OR NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE
   binding.login_role=SESSION_USER::name AND binding.environment_id=v_environment_id AND binding.purpose='Issue') THEN
   RETURN QUERY SELECT 'Unauthorized','AuthenticationFailed'; RETURN; END IF;
 UPDATE agent_private.enrollment_requests AS target SET state='PermanentFailed',terminal_code='IssuerPermanentFailure',updated_at=v_now,
   lease_token=NULL,lease_owner=NULL,lease_until=NULL,next_attempt_at=NULL
  WHERE target.issuance_id=p_issuance_id AND target.state='ExternalPending' AND target.lease_token=p_lease_token AND target.lease_until>v_now;
 RETURN QUERY SELECT CASE WHEN FOUND THEN 'PermanentFailed' ELSE 'RecoveryRequired' END,
   CASE WHEN FOUND THEN 'IssuerPermanentFailure' ELSE 'LeaseUnavailable' END;
END;
$function$;

GRANT EXECUTE ON FUNCTION agent_private.platform_grant_role_is_unbound(name) TO :"agent_enrollment_definer_role";

CREATE OR REPLACE FUNCTION agent_private.audit_enrollment_privileges(
    p_expected_table_owner name,p_expected_function_owner name,p_expected_purpose text)
RETURNS TABLE(is_valid boolean,diagnostic_code text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, agent_private, pg_temp AS $function$
WITH login AS (SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=SESSION_USER),
function_owner AS (SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_function_owner),
table_owner AS (SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_table_owner),
schema_info AS (SELECT namespace.oid,namespace.nspowner FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname='agent_private'),
expected_table_acl(relname,privilege_type,is_grantable) AS (VALUES
 ('enrollment_database_bindings','SELECT',false),('enrollment_grants','SELECT',false),('enrollment_grants','UPDATE',false),
 ('enrollment_requests','SELECT',false),('enrollment_requests','INSERT',false),('enrollment_requests','UPDATE',false),
 ('enrollment_results','SELECT',false),('enrollment_results','INSERT',false),('devices','SELECT',false),
 ('registrations','SELECT',false),('registrations','INSERT',false),('certificate_bindings','SELECT',false),('certificate_bindings','INSERT',false)),
actual_table_acl AS (
 SELECT object.relname,acl.privilege_type,acl.is_grantable FROM pg_catalog.pg_class object,schema_info,function_owner,
 LATERAL pg_catalog.aclexplode(COALESCE(object.relacl,pg_catalog.acldefault('r',object.relowner))) acl
 WHERE object.relnamespace=schema_info.oid AND acl.grantee=function_owner.oid),
expected_column_acl(relname,attname,privilege_type,is_grantable) AS (VALUES ('devices','next_registration_epoch','UPDATE',false)),
actual_column_acl AS (
 SELECT object.relname,attribute.attname,acl.privilege_type,acl.is_grantable FROM pg_catalog.pg_class object
 JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,
 schema_info,function_owner,LATERAL pg_catalog.aclexplode(attribute.attacl) acl
 WHERE object.relnamespace=schema_info.oid AND acl.grantee=function_owner.oid),
expected_execute(proname) AS (
 SELECT entry.proname FROM (VALUES
  ('Enroll','submit_or_recover_enrollment'),('Enroll','audit_enrollment_privileges'),
  ('Issue','claim_enrollment_issuance'),('Issue','complete_enrollment_issuance'),('Issue','defer_enrollment_issuance'),
  ('Issue','mark_enrollment_issuance_unknown'),('Issue','fail_enrollment_issuance_definitively'),
  ('Issue','audit_enrollment_privileges')) entry(purpose,proname) WHERE entry.purpose=p_expected_purpose),
actual_execute AS (
 SELECT function.proname FROM pg_catalog.pg_proc function,schema_info
 WHERE function.pronamespace=schema_info.oid AND pg_catalog.has_function_privilege(SESSION_USER,function.oid,'EXECUTE')),
checks AS (
 SELECT
   (SELECT pg_catalog.count(*)=1 FROM login) AND
   NOT EXISTS(SELECT 1 FROM login WHERE rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,login WHERE membership.member=login.oid OR membership.roleid=login.oid) AND
   (SELECT pg_catalog.count(*)=1 FROM agent_private.enrollment_database_bindings binding
     WHERE binding.login_role=SESSION_USER::name AND binding.purpose=p_expected_purpose) AND
   p_expected_purpose IN ('Enroll','Issue') AND
   agent_private.platform_grant_role_is_unbound(SESSION_USER::name) AND
   agent_private.platform_grant_role_is_unbound(p_expected_function_owner) AND
   agent_private.platform_grant_role_is_unbound(p_expected_table_owner) AND
   (COALESCE((SELECT
    helper.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=p_expected_table_owner) AND
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
    WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.platform_grant_role_is_unbound(name)')),false)) AND
   NOT pg_catalog.has_schema_privilege(SESSION_USER,'agent_private','CREATE') AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND
     object.relkind IN ('r','p','v','m') AND (pg_catalog.has_table_privilege(SESSION_USER,object.oid,'SELECT') OR
     pg_catalog.has_table_privilege(SESSION_USER,object.oid,'INSERT') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'UPDATE') OR
     pg_catalog.has_table_privilege(SESSION_USER,object.oid,'DELETE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRUNCATE') OR
     pg_catalog.has_table_privilege(SESSION_USER,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRIGGER'))) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND
     (pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'SELECT') OR
      pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'UPDATE'))) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,login WHERE database.datdba=login.oid) AND
   NOT EXISTS(SELECT 1 FROM schema_info,login WHERE schema_info.nspowner=login.oid) AND
   NOT EXISTS(SELECT 1 FROM function_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,function_owner WHERE membership.member=function_owner.oid OR membership.roleid=function_owner.oid) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,function_owner WHERE database.datdba=function_owner.oid) AND
   NOT EXISTS(SELECT 1 FROM schema_info,function_owner WHERE schema_info.nspowner=function_owner.oid) AND
   NOT pg_catalog.has_schema_privilege(p_expected_function_owner,'agent_private','CREATE') AND
   NOT EXISTS(SELECT 1 FROM table_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,table_owner WHERE membership.member=table_owner.oid OR membership.roleid=table_owner.oid) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,table_owner WHERE database.datdba=table_owner.oid) AND
   (SELECT pg_catalog.count(*)=1 FROM schema_info,table_owner WHERE schema_info.nspowner=table_owner.oid) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,login,
      LATERAL pg_catalog.aclexplode(function.proacl) acl WHERE function.pronamespace=schema_info.oid AND
      acl.grantee=login.oid AND acl.privilege_type='EXECUTE' AND acl.is_grantable) AND
   NOT EXISTS((SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl) UNION ALL
              (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl)) AND
   NOT EXISTS((SELECT * FROM expected_column_acl EXCEPT SELECT * FROM actual_column_acl) UNION ALL
              (SELECT * FROM actual_column_acl EXCEPT SELECT * FROM expected_column_acl)) AND
   NOT EXISTS((SELECT * FROM expected_execute EXCEPT SELECT * FROM actual_execute) UNION ALL
              (SELECT * FROM actual_execute EXCEPT SELECT * FROM expected_execute)) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,
      LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl
      WHERE function.pronamespace=schema_info.oid AND acl.grantee=0 AND acl.privilege_type='EXECUTE') AND
   (SELECT pg_catalog.count(*)=7 AND pg_catalog.bool_and(function.proowner=function_owner.oid AND function.prosecdef AND
      function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[])
    FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proname=ANY(ARRAY[
      'submit_or_recover_enrollment','claim_enrollment_issuance','complete_enrollment_issuance','defer_enrollment_issuance',
      'mark_enrollment_issuance_unknown','fail_enrollment_issuance_definitively','audit_enrollment_privileges'])) AND
   (SELECT pg_catalog.count(*)=7 AND pg_catalog.bool_and(object.relowner=table_owner.oid AND object.relrowsecurity AND object.relforcerowsecurity)
    FROM pg_catalog.pg_class object,schema_info,pg_catalog.pg_roles table_owner WHERE table_owner.rolname=p_expected_table_owner AND
      object.relnamespace=schema_info.oid AND object.relkind='r' AND object.relname=ANY(ARRAY[
      'devices','registrations','certificate_bindings','enrollment_database_bindings','enrollment_grants','enrollment_requests','enrollment_results'])) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner,table_owner WHERE object.relnamespace=schema_info.oid AND
      object.relname=ANY(ARRAY['devices','registrations','certificate_bindings','enrollment_database_bindings','enrollment_grants','enrollment_requests','enrollment_results']) AND
      (NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy WHERE policy.polrelid=object.oid AND policy.polname='enrollment_definer_access' AND
        policy.polroles=ARRAY[function_owner.oid]::oid[] AND policy.polcmd='*' AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND
        pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)='true') OR
       NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy WHERE policy.polrelid=object.oid AND policy.polname='definer_all' AND
        policy.polroles=ARRAY[table_owner.oid]::oid[] AND policy.polcmd='*' AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND
        pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)='true'))) AS valid
)
SELECT checks.valid,CASE WHEN checks.valid THEN 'None' ELSE 'PrivilegeAuditFailed' END FROM checks;
$function$;

ALTER FUNCTION agent_private.submit_or_recover_enrollment(bytea,uuid,uuid,bytea,bytea,bytea,integer) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.claim_enrollment_issuance(uuid,uuid) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.complete_enrollment_issuance(uuid,uuid,uuid,uuid,uuid,uuid,bigint,integer,bytea,bytea[],bytea,bytea,bytea,timestamptz,timestamptz) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.defer_enrollment_issuance(uuid,uuid,integer) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.mark_enrollment_issuance_unknown(uuid,uuid) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.fail_enrollment_issuance_definitively(uuid,uuid) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.audit_enrollment_privileges(name,name,text) OWNER TO :"agent_enrollment_definer_role";
REVOKE ALL ON FUNCTION agent_private.submit_or_recover_enrollment(bytea,uuid,uuid,bytea,bytea,bytea,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.claim_enrollment_issuance(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.complete_enrollment_issuance(uuid,uuid,uuid,uuid,uuid,uuid,bigint,integer,bytea,bytea[],bytea,bytea,bytea,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.defer_enrollment_issuance(uuid,uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.mark_enrollment_issuance_unknown(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.fail_enrollment_issuance_definitively(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.audit_enrollment_privileges(name,name,text) FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA agent_private FROM :"agent_enrollment_definer_role";
GRANT SELECT ON agent_private.enrollment_database_bindings TO :"agent_enrollment_definer_role";
GRANT SELECT, UPDATE ON agent_private.enrollment_grants TO :"agent_enrollment_definer_role";
GRANT SELECT, INSERT, UPDATE ON agent_private.enrollment_requests TO :"agent_enrollment_definer_role";
GRANT SELECT, INSERT ON agent_private.enrollment_results TO :"agent_enrollment_definer_role";
GRANT SELECT ON agent_private.devices, agent_private.registrations, agent_private.certificate_bindings TO :"agent_enrollment_definer_role";
GRANT UPDATE (next_registration_epoch) ON agent_private.devices TO :"agent_enrollment_definer_role";
GRANT INSERT ON agent_private.registrations, agent_private.certificate_bindings TO :"agent_enrollment_definer_role";
REVOKE ALL ON ALL TABLES IN SCHEMA agent_private FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA agent_private FROM PUBLIC;

COMMIT;
