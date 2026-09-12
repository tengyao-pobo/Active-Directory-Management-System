using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912090100_EnrollmentGrantExecutionStops")]
public sealed class EnrollmentGrantExecutionStops : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE TABLE enrollment_execution.execution_stops (
            operation_id uuid PRIMARY KEY REFERENCES public."EnrollmentGrantOperations"("Id") ON DELETE RESTRICT,
            reason text NOT NULL CHECK (reason IN ('AuthorizationChanged','AuthorizationExpired',
                'StoredDataInvalid','OperationConflict','ReceiptMismatch')),
            recorded_at timestamptz NOT NULL CHECK (isfinite(recorded_at))
        );
        ALTER TABLE enrollment_execution.execution_stops ENABLE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.execution_stops FORCE ROW LEVEL SECURITY;
        REVOKE ALL ON enrollment_execution.execution_stops FROM PUBLIC;

        CREATE FUNCTION enrollment_execution.lock_execution_stop_boundary() RETURNS trigger
            LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
            PERFORM 1 FROM public."EnrollmentGrantOperations" WHERE "Id"=NEW.operation_id FOR NO KEY UPDATE;
            IF TG_TABLE_NAME='mint_permits'
                AND EXISTS(SELECT 1 FROM enrollment_execution.execution_stops WHERE operation_id=NEW.operation_id) THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Stopped enrollment operation cannot mint a permit.';
            END IF;
            RETURN NEW;
        END
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.lock_execution_stop_boundary() FROM PUBLIC;
        CREATE TRIGGER mint_permits_stop_boundary BEFORE INSERT ON enrollment_execution.mint_permits
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.lock_execution_stop_boundary();
        CREATE TRIGGER execution_stops_boundary BEFORE INSERT ON enrollment_execution.execution_stops
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.lock_execution_stop_boundary();

        CREATE FUNCTION enrollment_execution.validate_execution_stop() RETURNS trigger
            LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            operation_uuid uuid := NEW.operation_id;
            operation public."EnrollmentGrantOperations"%ROWTYPE;
            stop enrollment_execution.execution_stops%ROWTYPE;
        BEGIN
            -- Serialize stop/permit/result decisions even when different tables are written.
            SELECT * INTO STRICT operation FROM public."EnrollmentGrantOperations"
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
        REVOKE ALL ON FUNCTION enrollment_execution.validate_execution_stop() FROM PUBLIC;
        CREATE TRIGGER execution_stops_immutable BEFORE UPDATE OR DELETE ON enrollment_execution.execution_stops
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation();
        CREATE CONSTRAINT TRIGGER execution_stops_consistent AFTER INSERT ON enrollment_execution.execution_stops
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_execution_stop();
        CREATE CONSTRAINT TRIGGER mint_permits_stop_consistent AFTER INSERT ON enrollment_execution.mint_permits
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_execution_stop();
        CREATE CONSTRAINT TRIGGER issue_results_stop_consistent AFTER INSERT ON enrollment_execution.issue_results
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_execution_stop();
        CREATE CONSTRAINT TRIGGER delivery_acks_stop_consistent AFTER INSERT ON enrollment_execution.delivery_acks
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_execution_stop();
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Enrollment execution stops require a reviewed forward migration.");
}
