using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

/// <summary>Durable execution work scheduling and append-only claim history.</summary>
[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912110000_EnrollmentGrantExecutionQueue")]
public sealed class EnrollmentGrantExecutionQueue : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE TABLE enrollment_execution.work_queue (
            environment_id uuid NOT NULL,
            operation_id uuid NOT NULL,
            state text NOT NULL CHECK (state IN ('Ready','Claimed','Deferred','Completed')),
            attempt integer NOT NULL CHECK (attempt>=0),
            next_attempt_at timestamptz NOT NULL CHECK (isfinite(next_attempt_at)),
            active_claim_token uuid,
            last_transition_token uuid,
            last_defer_reason text,
            completed_at timestamptz,
            seeded_at timestamptz NOT NULL CHECK (isfinite(seeded_at)),
            PRIMARY KEY(environment_id,operation_id),
            FOREIGN KEY(operation_id)
                REFERENCES public."EnrollmentGrantOperations"("Id") ON DELETE RESTRICT,
            CONSTRAINT work_queue_closed_shape CHECK (
                (state='Ready' AND attempt=0 AND active_claim_token IS NULL
                    AND last_transition_token IS NULL AND last_defer_reason IS NULL AND completed_at IS NULL)
                OR (state='Claimed' AND attempt>=1 AND active_claim_token IS NOT NULL
                    AND last_transition_token IS NULL AND last_defer_reason IS NULL AND completed_at IS NULL)
                OR (state='Deferred' AND attempt>=1 AND active_claim_token IS NOT NULL
                    AND last_transition_token=active_claim_token
                    AND last_defer_reason IN ('Retryable','OutcomeUnknown') AND completed_at IS NULL)
                OR (state='Completed' AND attempt>=1 AND active_claim_token IS NOT NULL
                    AND last_transition_token=active_claim_token AND last_defer_reason IS NULL
                    AND completed_at IS NOT NULL AND isfinite(completed_at)))
        );

        CREATE TABLE enrollment_execution.claim_leases (
            claim_token uuid PRIMARY KEY CHECK (claim_token<>'00000000-0000-0000-0000-000000000000'::uuid),
            environment_id uuid NOT NULL,
            operation_id uuid NOT NULL,
            attempt integer NOT NULL CHECK (attempt>=1),
            claimed_at timestamptz NOT NULL,
            lease_until timestamptz NOT NULL,
            UNIQUE(claim_token,environment_id,operation_id,attempt),
            FOREIGN KEY(environment_id,operation_id)
                REFERENCES enrollment_execution.work_queue(environment_id,operation_id) ON DELETE RESTRICT,
            CONSTRAINT claim_lease_time CHECK (isfinite(claimed_at) AND isfinite(lease_until)
                AND lease_until=claimed_at+interval '120 seconds')
        );
        ALTER TABLE enrollment_execution.work_queue ADD CONSTRAINT work_queue_active_claim
            FOREIGN KEY(active_claim_token,environment_id,operation_id,attempt)
            REFERENCES enrollment_execution.claim_leases(claim_token,environment_id,operation_id,attempt)
            DEFERRABLE INITIALLY DEFERRED;

        CREATE FUNCTION enrollment_execution.guard_work_queue() RETURNS trigger
            LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            old_lease_until timestamptz;
        BEGIN
            IF TG_OP='DELETE' THEN
                RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution work history is immutable.';
            END IF;
            IF TG_OP='INSERT' THEN
                IF NEW.state<>'Ready' THEN
                    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Invalid initial execution work state.';
                END IF;
                RETURN NEW;
            END IF;
            IF ROW(NEW.environment_id,NEW.operation_id,NEW.seeded_at)
                IS DISTINCT FROM ROW(OLD.environment_id,OLD.operation_id,OLD.seeded_at)
                OR NOT ((OLD.state='Ready' AND NEW.state='Claimed')
                    OR (OLD.state='Claimed' AND NEW.state IN ('Claimed','Deferred','Completed'))
                    OR (OLD.state='Deferred' AND NEW.state='Claimed')) THEN
                RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Invalid enrollment execution work transition.';
            END IF;
            IF OLD.state='Claimed' AND NEW.state='Claimed' THEN
                SELECT lease.lease_until INTO old_lease_until
                FROM enrollment_execution.claim_leases AS lease
                WHERE lease.claim_token=OLD.active_claim_token
                  AND lease.environment_id=OLD.environment_id
                  AND lease.operation_id=OLD.operation_id
                  AND lease.attempt=OLD.attempt;
                IF NEW.active_claim_token IS NOT DISTINCT FROM OLD.active_claim_token
                    OR old_lease_until IS NULL OR clock_timestamp()<old_lease_until THEN
                    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='An active execution claim cannot be replaced.';
                END IF;
            END IF;
            RETURN NEW;
        END
        $function$;

        CREATE FUNCTION enrollment_execution.validate_work_queue() RETURNS trigger
            LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
        DECLARE
            environment_uuid uuid;
            operation_uuid uuid;
            work enrollment_execution.work_queue%ROWTYPE;
            operation public."EnrollmentGrantOperations"%ROWTYPE;
            outbox public."Outbox"%ROWTYPE;
        BEGIN
            IF TG_TABLE_NAME='work_queue' THEN
                environment_uuid:=NEW.environment_id;
                operation_uuid:=NEW.operation_id;
            ELSE
                IF NEW."EventType"<>'EnrollmentGrantExecutionRequested' THEN RETURN NULL; END IF;
                environment_uuid:=NEW."EnvironmentId";
                operation_uuid:=NEW."Id";
            END IF;
            SELECT * INTO work FROM enrollment_execution.work_queue
                WHERE environment_id=environment_uuid AND operation_id=operation_uuid;
            IF work.operation_id IS NULL THEN
                IF TG_TABLE_NAME='Outbox' AND NEW."EventType"='EnrollmentGrantExecutionRequested'
                    AND NEW."DeliveredAt" IS NOT NULL THEN
                    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Unclaimed enrollment work cannot be delivered.';
                END IF;
                RETURN NULL;
            END IF;
            SELECT * INTO STRICT operation FROM public."EnrollmentGrantOperations"
                WHERE "EnvironmentId"=environment_uuid AND "Id"=operation_uuid;
            SELECT * INTO STRICT outbox FROM public."Outbox"
                WHERE "EnvironmentId"=environment_uuid AND "Id"=operation_uuid;
            IF outbox."EventType"<>'EnrollmentGrantExecutionRequested'
                OR outbox."Version"<>1 OR outbox."CreatedAt"<>operation."QueuedAt"
                OR outbox."Payload"<>jsonb_build_object('version',1,'environmentId',environment_uuid,'operationId',operation_uuid)
                OR (work.state='Completed' AND outbox."DeliveredAt" IS DISTINCT FROM work.completed_at)
                OR (work.state<>'Completed' AND outbox."DeliveredAt" IS NOT NULL) THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Invalid enrollment execution queue anchor.';
            END IF;
            RETURN NULL;
        END
        $function$;

        CREATE TRIGGER work_queue_guard BEFORE INSERT OR UPDATE OR DELETE ON enrollment_execution.work_queue
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.guard_work_queue();
        CREATE TRIGGER claim_leases_immutable BEFORE UPDATE OR DELETE ON enrollment_execution.claim_leases
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation();
        CREATE CONSTRAINT TRIGGER work_queue_consistent AFTER INSERT OR UPDATE ON enrollment_execution.work_queue
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_work_queue();
        CREATE FUNCTION enrollment_execution.claim_next_work(p_environment uuid,p_token uuid)
        RETURNS TABLE(contract_version smallint,outcome text,queried_at timestamptz,environment_id uuid,
            operation_id uuid,claim_token uuid,attempt integer,claimed_at timestamptz,lease_until timestamptz)
        LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            prior enrollment_execution.claim_leases%ROWTYPE;
            work enrollment_execution.work_queue%ROWTYPE;
            now_at timestamptz;
            next_attempt integer;
            candidate uuid;
        BEGIN
            IF current_setting('transaction_isolation')<>'serializable' THEN
                RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Execution queue requires a serializable transaction.';
            END IF;
            IF p_environment IS NULL OR p_environment='00000000-0000-0000-0000-000000000000'::uuid
                OR p_token IS NULL OR p_token='00000000-0000-0000-0000-000000000000'::uuid THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid execution claim.';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_token::text,1162235478));
            SELECT lease.* INTO prior FROM enrollment_execution.claim_leases AS lease WHERE lease.claim_token=p_token;
            IF prior.claim_token IS NOT NULL THEN
                now_at:=clock_timestamp();
                IF prior.environment_id<>p_environment THEN
                    RETURN QUERY SELECT 1::smallint,'TokenConflict'::text,now_at,NULL::uuid,NULL::uuid,NULL::uuid,NULL::integer,NULL::timestamptz,NULL::timestamptz;
                    RETURN;
                END IF;
                SELECT queue.* INTO STRICT work FROM enrollment_execution.work_queue AS queue
                    WHERE queue.environment_id=prior.environment_id AND queue.operation_id=prior.operation_id FOR UPDATE;
                now_at:=clock_timestamp();
                IF work.state='Deferred' AND work.last_transition_token=p_token THEN
                    RETURN QUERY SELECT 1::smallint,'AlreadyDeferred'::text,now_at,NULL::uuid,NULL::uuid,NULL::uuid,NULL::integer,NULL::timestamptz,NULL::timestamptz;
                ELSIF work.state='Completed' AND work.last_transition_token=p_token THEN
                    RETURN QUERY SELECT 1::smallint,'AlreadyCompleted'::text,now_at,NULL::uuid,NULL::uuid,NULL::uuid,NULL::integer,NULL::timestamptz,NULL::timestamptz;
                ELSIF work.state='Claimed' AND work.active_claim_token=p_token AND now_at<prior.lease_until THEN
                    RETURN QUERY SELECT 1::smallint,'Existing'::text,now_at,prior.environment_id,prior.operation_id,
                        prior.claim_token,prior.attempt,prior.claimed_at,prior.lease_until;
                ELSE
                    RETURN QUERY SELECT 1::smallint,'StaleClaim'::text,now_at,NULL::uuid,NULL::uuid,NULL::uuid,NULL::integer,NULL::timestamptz,NULL::timestamptz;
                END IF;
                RETURN;
            END IF;

            SELECT queue.* INTO work FROM enrollment_execution.work_queue queue
            LEFT JOIN enrollment_execution.claim_leases lease
              ON lease.environment_id=queue.environment_id AND lease.operation_id=queue.operation_id
             AND lease.attempt=queue.attempt AND lease.claim_token=queue.active_claim_token
            WHERE queue.environment_id=p_environment AND
              ((queue.state='Ready') OR (queue.state='Deferred' AND queue.next_attempt_at<=clock_timestamp())
               OR (queue.state='Claimed' AND lease.lease_until<=clock_timestamp()))
            ORDER BY queue.next_attempt_at,queue.operation_id LIMIT 1 FOR UPDATE OF queue SKIP LOCKED;
            IF work.operation_id IS NULL THEN
                SELECT outbox."Id" INTO candidate FROM public."Outbox" outbox
                JOIN public."EnrollmentGrantOperations" operation
                  ON operation."EnvironmentId"=outbox."EnvironmentId" AND operation."Id"=outbox."Id"
                WHERE outbox."EnvironmentId"=p_environment AND outbox."EventType"='EnrollmentGrantExecutionRequested'
                  AND outbox."Version"=1 AND outbox."DeliveredAt" IS NULL
                  AND outbox."CreatedAt"=operation."QueuedAt"
                  AND outbox."Payload"=jsonb_build_object('version',1,'environmentId',p_environment,'operationId',outbox."Id")
                  AND NOT EXISTS(SELECT 1 FROM enrollment_execution.work_queue existing
                      WHERE existing.environment_id=p_environment AND existing.operation_id=outbox."Id")
                ORDER BY outbox."CreatedAt",outbox."Id" LIMIT 1;
                IF candidate IS NOT NULL THEN
                    now_at:=clock_timestamp();
                    INSERT INTO enrollment_execution.work_queue(environment_id,operation_id,state,attempt,next_attempt_at,
                        active_claim_token,last_transition_token,last_defer_reason,completed_at,seeded_at)
                    VALUES(p_environment,candidate,'Ready',0,now_at,NULL,NULL,NULL,NULL,now_at)
                    ON CONFLICT ON CONSTRAINT work_queue_pkey DO NOTHING;
                    SELECT queue.* INTO work FROM enrollment_execution.work_queue AS queue
                        WHERE queue.environment_id=p_environment AND queue.operation_id=candidate FOR UPDATE;
                END IF;
            END IF;
            now_at:=clock_timestamp();
            IF work.operation_id IS NULL OR work.state='Completed' THEN
                RETURN QUERY SELECT 1::smallint,'NoWork'::text,now_at,NULL::uuid,NULL::uuid,NULL::uuid,NULL::integer,NULL::timestamptz,NULL::timestamptz;
                RETURN;
            END IF;
            next_attempt:=CASE WHEN work.attempt=2147483647 THEN 2147483647 ELSE work.attempt+1 END;
            INSERT INTO enrollment_execution.claim_leases(claim_token,environment_id,operation_id,attempt,claimed_at,lease_until)
                VALUES(p_token,p_environment,work.operation_id,next_attempt,now_at,now_at+interval '120 seconds');
            UPDATE enrollment_execution.work_queue AS queue SET state='Claimed',attempt=next_attempt,active_claim_token=p_token,
                last_transition_token=NULL,last_defer_reason=NULL,completed_at=NULL
                WHERE queue.environment_id=p_environment AND queue.operation_id=work.operation_id;
            RETURN QUERY SELECT 1::smallint,'Claimed'::text,now_at,p_environment,work.operation_id,p_token,next_attempt,
                now_at,now_at+interval '120 seconds';
        END
        $function$;

        CREATE FUNCTION enrollment_execution.defer_work_claim(p_environment uuid,p_operation uuid,p_token uuid,p_reason text)
        RETURNS TABLE(contract_version smallint,outcome text,queried_at timestamptz,next_attempt_at timestamptz)
        LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE prior enrollment_execution.claim_leases%ROWTYPE; work enrollment_execution.work_queue%ROWTYPE;
            now_at timestamptz; retry_at timestamptz; delay_seconds integer;
        BEGIN
            IF current_setting('transaction_isolation')<>'serializable' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Execution queue requires a serializable transaction.'; END IF;
            IF p_environment IS NULL OR p_environment='00000000-0000-0000-0000-000000000000'::uuid
                OR p_operation IS NULL OR p_operation='00000000-0000-0000-0000-000000000000'::uuid
                OR p_token IS NULL OR p_token='00000000-0000-0000-0000-000000000000'::uuid
                OR p_reason IS NULL OR p_reason NOT IN ('Retryable','OutcomeUnknown') THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid execution defer request.';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_token::text,1162235478));
            SELECT lease.* INTO prior FROM enrollment_execution.claim_leases AS lease WHERE lease.claim_token=p_token;
            now_at:=clock_timestamp();
            IF prior.claim_token IS NULL THEN RETURN QUERY SELECT 1::smallint,'NotFound'::text,now_at,NULL::timestamptz; RETURN; END IF;
            IF (prior.environment_id,prior.operation_id)<>(p_environment,p_operation) THEN RETURN QUERY SELECT 1::smallint,'TokenConflict'::text,now_at,NULL::timestamptz; RETURN; END IF;
            SELECT queue.* INTO STRICT work FROM enrollment_execution.work_queue AS queue
                WHERE queue.environment_id=p_environment AND queue.operation_id=p_operation FOR UPDATE;
            now_at:=clock_timestamp();
            IF work.state='Deferred' AND work.last_transition_token=p_token THEN
                RETURN QUERY SELECT 1::smallint,'AlreadyDeferred'::text,now_at,work.next_attempt_at; RETURN;
            ELSIF work.state='Completed' AND work.last_transition_token=p_token THEN
                RETURN QUERY SELECT 1::smallint,'AlreadyCompleted'::text,now_at,NULL::timestamptz; RETURN;
            ELSIF work.state<>'Claimed' OR work.active_claim_token<>p_token OR now_at>=prior.lease_until THEN
                RETURN QUERY SELECT 1::smallint,'StaleClaim'::text,now_at,NULL::timestamptz; RETURN;
            END IF;
            IF EXISTS(SELECT 1 FROM enrollment_execution.issue_results AS result WHERE result.operation_id=p_operation)
                OR EXISTS(SELECT 1 FROM enrollment_execution.execution_stops AS stop WHERE stop.operation_id=p_operation) THEN
                UPDATE public."Outbox" AS outbox SET "DeliveredAt"=now_at
                    WHERE outbox."EnvironmentId"=p_environment AND outbox."Id"=p_operation
                      AND outbox."EventType"='EnrollmentGrantExecutionRequested' AND outbox."Version"=1
                      AND outbox."DeliveredAt" IS NULL;
                IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Execution outbox anchor is unavailable.'; END IF;
                UPDATE enrollment_execution.work_queue AS queue SET state='Completed',next_attempt_at=now_at,
                    last_transition_token=p_token,last_defer_reason=NULL,completed_at=now_at
                    WHERE queue.environment_id=p_environment AND queue.operation_id=p_operation;
                RETURN QUERY SELECT 1::smallint,'Completed'::text,now_at,NULL::timestamptz; RETURN;
            END IF;
            delay_seconds:=least(300,5*(1<<least(prior.attempt-1,6)));
            retry_at:=now_at+make_interval(secs=>delay_seconds);
            UPDATE enrollment_execution.work_queue SET state='Deferred',next_attempt_at=retry_at,
                last_transition_token=p_token,last_defer_reason=p_reason,completed_at=NULL
                WHERE environment_id=p_environment AND operation_id=p_operation;
            RETURN QUERY SELECT 1::smallint,'Deferred'::text,now_at,retry_at;
        END
        $function$;

        CREATE FUNCTION enrollment_execution.complete_work_claim(p_environment uuid,p_operation uuid,p_token uuid)
        RETURNS TABLE(contract_version smallint,outcome text,queried_at timestamptz,next_attempt_at timestamptz)
        LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE prior enrollment_execution.claim_leases%ROWTYPE; work enrollment_execution.work_queue%ROWTYPE; now_at timestamptz;
        BEGIN
            IF current_setting('transaction_isolation')<>'serializable' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Execution queue requires a serializable transaction.'; END IF;
            IF p_environment IS NULL OR p_environment='00000000-0000-0000-0000-000000000000'::uuid
                OR p_operation IS NULL OR p_operation='00000000-0000-0000-0000-000000000000'::uuid
                OR p_token IS NULL OR p_token='00000000-0000-0000-0000-000000000000'::uuid THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid execution completion request.';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_token::text,1162235478));
            SELECT lease.* INTO prior FROM enrollment_execution.claim_leases AS lease WHERE lease.claim_token=p_token;
            now_at:=clock_timestamp();
            IF prior.claim_token IS NULL THEN RETURN QUERY SELECT 1::smallint,'NotFound'::text,now_at,NULL::timestamptz; RETURN; END IF;
            IF (prior.environment_id,prior.operation_id)<>(p_environment,p_operation) THEN RETURN QUERY SELECT 1::smallint,'TokenConflict'::text,now_at,NULL::timestamptz; RETURN; END IF;
            SELECT queue.* INTO STRICT work FROM enrollment_execution.work_queue AS queue
                WHERE queue.environment_id=p_environment AND queue.operation_id=p_operation FOR UPDATE;
            now_at:=clock_timestamp();
            IF work.state='Completed' AND work.last_transition_token=p_token THEN
                RETURN QUERY SELECT 1::smallint,'AlreadyCompleted'::text,now_at,NULL::timestamptz; RETURN;
            ELSIF work.state='Deferred' AND work.last_transition_token=p_token THEN
                RETURN QUERY SELECT 1::smallint,'StaleClaim'::text,now_at,NULL::timestamptz; RETURN;
            ELSIF work.state<>'Claimed' OR work.active_claim_token<>p_token OR now_at>=prior.lease_until THEN
                RETURN QUERY SELECT 1::smallint,'StaleClaim'::text,now_at,NULL::timestamptz; RETURN;
            END IF;
            IF NOT EXISTS(SELECT 1 FROM enrollment_execution.issue_results AS result WHERE result.operation_id=p_operation)
                AND NOT EXISTS(SELECT 1 FROM enrollment_execution.execution_stops AS stop WHERE stop.operation_id=p_operation) THEN
                RETURN QUERY SELECT 1::smallint,'NotTerminal'::text,now_at,NULL::timestamptz; RETURN;
            END IF;
            UPDATE public."Outbox" SET "DeliveredAt"=now_at
                WHERE "EnvironmentId"=p_environment AND "Id"=p_operation
                  AND "EventType"='EnrollmentGrantExecutionRequested' AND "Version"=1 AND "DeliveredAt" IS NULL;
            IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Execution outbox anchor is unavailable.'; END IF;
            UPDATE enrollment_execution.work_queue SET state='Completed',next_attempt_at=now_at,
                last_transition_token=p_token,last_defer_reason=NULL,completed_at=now_at
                WHERE environment_id=p_environment AND operation_id=p_operation;
            RETURN QUERY SELECT 1::smallint,'Completed'::text,now_at,NULL::timestamptz;
        END
        $function$;

        REVOKE ALL ON FUNCTION enrollment_execution.claim_next_work(uuid,uuid),
            enrollment_execution.defer_work_claim(uuid,uuid,uuid,text),
            enrollment_execution.complete_work_claim(uuid,uuid,uuid) FROM PUBLIC;

        ALTER TABLE enrollment_execution.work_queue ENABLE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.work_queue FORCE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.claim_leases ENABLE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.claim_leases FORCE ROW LEVEL SECURITY;
        REVOKE ALL ON enrollment_execution.work_queue,enrollment_execution.claim_leases FROM PUBLIC;
        REVOKE ALL ON FUNCTION enrollment_execution.guard_work_queue(),enrollment_execution.validate_work_queue() FROM PUBLIC;
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Enrollment execution claim history requires a reviewed forward migration.");
}
