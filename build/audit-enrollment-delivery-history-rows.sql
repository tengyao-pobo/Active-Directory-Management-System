-- Unconsumed activation-time history scan. Never call from per-request audits.
-- Requires the reviewed owner visibility/locking wrapper and exact structure preflight.
-- This query alone is not a readiness or privilege attestation.
WITH status_ordered AS (
 SELECT observation.*,
   max(recorded_at) FILTER(WHERE state='Unknown') OVER (
     PARTITION BY operation_id ORDER BY sequence ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) prior_unknown_barrier
 FROM enrollment_execution.status_observations observation
), status_sequences AS (
 SELECT operation_id,min(sequence) first_sequence,max(sequence) last_sequence,count(*) sequence_count,
   count(DISTINCT sequence) distinct_sequences,count(*) FILTER(WHERE state IN('Consumed','Revoked','Expired')) terminal_count,
   max(sequence) FILTER(WHERE state IN('Consumed','Revoked','Expired')) terminal_sequence
 FROM enrollment_execution.status_observations GROUP BY operation_id
)
SELECT
 NOT EXISTS(
   SELECT 1 FROM enrollment_execution.mint_permits permit
   LEFT JOIN public."EnrollmentGrantOperations" operation ON operation."Id"=permit.operation_id
   LEFT JOIN enrollment_execution.issue_results result ON result.operation_id=permit.operation_id
   LEFT JOIN enrollment_execution.delivery_acks ack ON ack.operation_id=permit.operation_id
   LEFT JOIN enrollment_execution.sealed_envelopes envelope ON envelope.operation_id=permit.operation_id
   WHERE operation."Id" IS NULL
     OR (permit.issued_at>=operation."QueuedAt" AND permit.not_after<=operation."AuthorizationNotAfter"
       AND permit.recipient_fingerprint=operation."RecipientKeyFingerprint") IS NOT TRUE
     OR (envelope.operation_id IS NOT NULL AND pg_catalog.sha256(envelope.ciphertext) IS DISTINCT FROM permit.ciphertext_sha256)
     OR (result.operation_id IS NOT NULL AND (result.recorded_at>=permit.issued_at
       AND (result.diagnostic<>'MintPermitExpired' OR result.recorded_at>=permit.not_after)) IS NOT TRUE)
     OR (result.outcome='Issued' AND (result.environment_id=operation."EnvironmentId"
       AND result.directory_object_id=operation."DirectoryObjectId" AND result.device_id=operation."ServerDeviceId"
       AND result.mapping_created_at=operation."MappingCreatedAt" AND result.mint_permit_not_after=permit.not_after
       AND result.grant_created_at>=permit.issued_at AND result.token_sha256=permit.token_sha256
       AND result.authorization_digest=permit.authorization_digest) IS NOT TRUE)
     OR (ack.operation_id IS NOT NULL AND (result.outcome='Issued' AND ack.requester_id=operation."RequesterId"
       AND ack.ciphertext_sha256=permit.ciphertext_sha256 AND ack.token_sha256=permit.token_sha256
       AND ack.acknowledged_at>=result.recorded_at) IS NOT TRUE)
     OR CASE WHEN ack.operation_id IS NOT NULL OR result.outcome='Rejected'
       THEN envelope.operation_id IS NOT NULL ELSE envelope.operation_id IS NULL END
 )
 AND NOT EXISTS(SELECT 1 FROM enrollment_execution.sealed_envelopes envelope
   LEFT JOIN enrollment_execution.mint_permits permit ON permit.operation_id=envelope.operation_id WHERE permit.operation_id IS NULL)
 AND NOT EXISTS(SELECT 1 FROM enrollment_execution.issue_results result
   LEFT JOIN enrollment_execution.mint_permits permit ON permit.operation_id=result.operation_id WHERE permit.operation_id IS NULL)
 AND NOT EXISTS(SELECT 1 FROM enrollment_execution.delivery_acks ack
   LEFT JOIN enrollment_execution.issue_results result ON result.operation_id=ack.operation_id WHERE result.operation_id IS NULL)
 AND NOT EXISTS(
   SELECT 1 FROM enrollment_execution.execution_stops stop
   LEFT JOIN public."EnrollmentGrantOperations" operation ON operation."Id"=stop.operation_id
   LEFT JOIN enrollment_execution.mint_permits permit ON permit.operation_id=stop.operation_id
   LEFT JOIN enrollment_execution.issue_results result ON result.operation_id=stop.operation_id
   LEFT JOIN enrollment_execution.delivery_acks ack ON ack.operation_id=stop.operation_id
   WHERE operation."Id" IS NULL OR (stop.recorded_at>=operation."QueuedAt"
     AND (stop.reason<>'AuthorizationExpired' OR stop.recorded_at>=operation."AuthorizationNotAfter")) IS NOT TRUE
     OR (permit.operation_id IS NOT NULL AND permit.issued_at>stop.recorded_at)
     OR (stop.reason IN('OperationConflict','ReceiptMismatch') AND permit.operation_id IS NULL)
     OR (stop.reason IN('AuthorizationChanged','AuthorizationExpired') AND permit.operation_id IS NOT NULL)
     OR result.operation_id IS NOT NULL OR ack.operation_id IS NOT NULL
 )
 AND NOT EXISTS(SELECT 1 FROM status_sequences WHERE first_sequence<>1 OR last_sequence<>sequence_count
   OR distinct_sequences<>sequence_count OR terminal_count>1 OR (terminal_count=1 AND terminal_sequence<>last_sequence))
 AND NOT EXISTS(
   SELECT 1 FROM status_ordered observation
   LEFT JOIN enrollment_execution.issue_results result ON result.operation_id=observation.operation_id
   LEFT JOIN public."EnrollmentGrantOperations" operation ON operation."Id"=observation.operation_id
   WHERE (result.outcome='Issued' AND result.environment_id=observation.environment_id
       AND operation."EnvironmentId"=observation.environment_id) IS NOT TRUE
     OR (observation.state<>'Unknown' AND (observation.private_observed_at>=result.grant_created_at) IS NOT TRUE)
     OR (observation.state='Available' AND (observation.private_observed_at<result.grant_expires_at
       AND observation.private_observed_at>observation.recorded_at-interval '15 seconds'
       AND (observation.prior_unknown_barrier IS NULL OR observation.private_observed_at>=observation.prior_unknown_barrier)
       AND observation.available_until=least(observation.private_observed_at+interval '15 seconds',
         observation.recorded_at+interval '15 seconds',result.grant_expires_at)) IS NOT TRUE)
     OR (observation.state='Expired' AND (observation.private_observed_at>=result.grant_expires_at) IS NOT TRUE)
     OR (observation.state IN('Consumed','Revoked') AND (observation.private_state_changed_at>=result.grant_created_at
       AND (observation.state<>'Consumed' OR observation.private_state_changed_at<result.grant_expires_at)) IS NOT TRUE)
 ) AS is_valid;
