-- Staged profile4 journal projections; apply only inside the reviewed upgrade transaction.
-- CREATE OR REPLACE preserves validator identity, ownership, ACLs and trigger dependencies.

CREATE OR REPLACE FUNCTION enrollment_execution.validate_journal() RETURNS trigger
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $function$
DECLARE
    operation_uuid uuid := coalesce(NEW.operation_id,OLD.operation_id);
    permit enrollment_execution.mint_permits%ROWTYPE;
    operation record;
    result enrollment_execution.issue_results%ROWTYPE;
    ack enrollment_execution.delivery_acks%ROWTYPE;
    envelope enrollment_execution.sealed_envelopes%ROWTYPE;
BEGIN
    SELECT * INTO STRICT permit FROM enrollment_execution.mint_permits WHERE operation_id=operation_uuid;
    SELECT "QueuedAt","AuthorizationNotAfter","RecipientKeyFingerprint","EnvironmentId","DirectoryObjectId","ServerDeviceId","MappingCreatedAt","RequesterId" INTO STRICT operation FROM public."EnrollmentGrantOperations" WHERE "Id"=operation_uuid;
    SELECT * INTO result FROM enrollment_execution.issue_results WHERE operation_id=operation_uuid;
    SELECT * INTO ack FROM enrollment_execution.delivery_acks WHERE operation_id=operation_uuid;
    SELECT * INTO envelope FROM enrollment_execution.sealed_envelopes WHERE operation_id=operation_uuid;
    IF permit.issued_at<operation."QueuedAt" OR permit.not_after>operation."AuthorizationNotAfter"
        OR permit.recipient_fingerprint<>operation."RecipientKeyFingerprint" THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Invalid enrollment permit binding.';
    END IF;
    IF envelope.operation_id IS NOT NULL AND pg_catalog.sha256(envelope.ciphertext)<>permit.ciphertext_sha256 THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Invalid enrollment envelope binding.';
    END IF;
    IF result.operation_id IS NOT NULL AND (result.recorded_at<permit.issued_at
        OR (result.diagnostic='MintPermitExpired' AND result.recorded_at<permit.not_after)) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Invalid enrollment result time.';
    END IF;
    IF result.outcome='Issued' AND (result.environment_id<>operation."EnvironmentId"
        OR result.directory_object_id<>operation."DirectoryObjectId" OR result.device_id<>operation."ServerDeviceId"
        OR result.mapping_created_at<>operation."MappingCreatedAt" OR result.mint_permit_not_after<>permit.not_after
        OR result.grant_created_at<permit.issued_at OR result.token_sha256<>permit.token_sha256
        OR result.authorization_digest<>permit.authorization_digest) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Invalid enrollment receipt binding.';
    END IF;
    IF ack.operation_id IS NOT NULL AND (result.outcome IS DISTINCT FROM 'Issued'
        OR ack.requester_id<>operation."RequesterId" OR ack.ciphertext_sha256<>permit.ciphertext_sha256
        OR ack.token_sha256<>permit.token_sha256 OR ack.acknowledged_at<result.recorded_at) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Invalid enrollment acknowledgement binding.';
    END IF;
    IF (ack.operation_id IS NOT NULL OR result.outcome='Rejected') THEN
        IF envelope.operation_id IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Final enrollment disposition must erase its envelope.';
        END IF;
    ELSIF envelope.operation_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment permit requires its durable envelope.';
    END IF;
    RETURN NULL;
END
$function$;

CREATE OR REPLACE FUNCTION enrollment_execution.validate_execution_stop() RETURNS trigger
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $function$
DECLARE
    operation_uuid uuid := NEW.operation_id;
    operation record;
    stop enrollment_execution.execution_stops%ROWTYPE;
BEGIN
    -- Serialize stop/permit/result decisions even when different tables are written.
    SELECT "QueuedAt","AuthorizationNotAfter" INTO STRICT operation FROM public."EnrollmentGrantOperations"
        WHERE "Id"=operation_uuid FOR NO KEY UPDATE;
    SELECT * INTO stop FROM enrollment_execution.execution_stops WHERE operation_id=operation_uuid;
    IF stop.operation_id IS NULL THEN RETURN NULL; END IF;
    IF stop.recorded_at<operation."QueuedAt"
        OR (stop.reason='AuthorizationExpired' AND stop.recorded_at<operation."AuthorizationNotAfter") THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Invalid enrollment stop time.';
    END IF;
    IF EXISTS(SELECT 1 FROM enrollment_execution.mint_permits
        WHERE operation_id=operation_uuid AND issued_at>stop.recorded_at) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment stop predates its permit.';
    END IF;
    IF stop.reason IN ('OperationConflict','ReceiptMismatch')
        AND NOT EXISTS(SELECT 1 FROM enrollment_execution.mint_permits WHERE operation_id=operation_uuid) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Private issue fault requires an enrollment permit.';
    END IF;
    IF stop.reason IN ('AuthorizationChanged','AuthorizationExpired')
        AND EXISTS(SELECT 1 FROM enrollment_execution.mint_permits WHERE operation_id=operation_uuid) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Authorization rejection cannot replace a committed permit.';
    END IF;
    IF EXISTS(SELECT 1 FROM enrollment_execution.issue_results WHERE operation_id=operation_uuid)
        OR EXISTS(SELECT 1 FROM enrollment_execution.delivery_acks WHERE operation_id=operation_uuid) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment stop cannot replace a committed result.';
    END IF;
    RETURN NULL;
END
$function$;
