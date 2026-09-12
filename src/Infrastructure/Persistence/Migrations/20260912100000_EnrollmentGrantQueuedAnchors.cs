using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912100000_EnrollmentGrantQueuedAnchors")]
public sealed class EnrollmentGrantQueuedAnchors : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE FUNCTION public.guard_enrollment_grant_queued_plan() RETURNS trigger
            LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
            IF TG_OP<>'INSERT' AND OLD."Action"='agent-enrollment.initial-grant.v1' AND OLD."State"=5 THEN
                RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Queued enrollment grant plans are immutable.';
            END IF;
            IF TG_OP<>'DELETE' AND NEW."Action"='agent-enrollment.initial-grant.v1' AND NEW."State"=5 AND
               (TG_OP='INSERT' OR OLD."Action"<>'agent-enrollment.initial-grant.v1' OR OLD."State"<>1 OR
                (OLD."EnvironmentId",OLD."Id",OLD."RequesterId",OLD."Action",OLD."ImmutablePlanJson",OLD."PlanHash",
                 OLD."PolicyVersion",OLD."ExpiresAt",OLD."Reason") IS DISTINCT FROM
                (NEW."EnvironmentId",NEW."Id",NEW."RequesterId",NEW."Action",NEW."ImmutablePlanJson",NEW."PlanHash",
                 NEW."PolicyVersion",NEW."ExpiresAt",NEW."Reason")) THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment grant plans can only queue from Approved.';
            END IF;
            RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
        END
        $function$;

        CREATE FUNCTION public.guard_enrollment_grant_plan_child() RETURNS trigger
            LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            parent_key record;
            parent_state integer;
            parent_action text;
        BEGIN
            FOR parent_key IN
                SELECT DISTINCT key.environment_id,key.plan_id
                FROM (VALUES
                    (CASE WHEN TG_OP<>'INSERT' THEN OLD."EnvironmentId" END,
                     CASE WHEN TG_OP<>'INSERT' THEN OLD."PlanId" END),
                    (CASE WHEN TG_OP<>'DELETE' THEN NEW."EnvironmentId" END,
                     CASE WHEN TG_OP<>'DELETE' THEN NEW."PlanId" END)
                ) AS key(environment_id,plan_id)
                WHERE key.environment_id IS NOT NULL AND key.plan_id IS NOT NULL
                ORDER BY key.environment_id,key.plan_id
            LOOP
                SELECT "State","Action" INTO parent_state,parent_action
                FROM public."Plans"
                WHERE "EnvironmentId"=parent_key.environment_id AND "Id"=parent_key.plan_id
                FOR SHARE;
                IF NOT FOUND THEN
                    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Plan parent is unavailable.';
                END IF;
                IF parent_action='agent-enrollment.initial-grant.v1' AND parent_state=5 THEN
                    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Queued enrollment grant plan children are immutable.';
                END IF;
            END LOOP;
            RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
        END
        $function$;

        CREATE FUNCTION public.guard_enrollment_grant_operation_parent() RETURNS trigger
            LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            parent_state integer;
            parent_action text;
        BEGIN
            SELECT "State","Action" INTO parent_state,parent_action
            FROM public."Plans"
            WHERE "EnvironmentId"=NEW."EnvironmentId" AND "Id"=NEW."PlanId"
            FOR SHARE;
            IF NOT FOUND OR parent_action<>'agent-enrollment.initial-grant.v1' OR parent_state<>5 THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment grant operation requires a queued plan.';
            END IF;
            RETURN NEW;
        END
        $function$;

        CREATE FUNCTION public.guard_enrollment_grant_outbox_anchor() RETURNS trigger
            LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
            IF (TG_OP<>'INSERT' AND OLD."EventType"='EnrollmentGrantExecutionRequested') OR
               (TG_OP<>'DELETE' AND NEW."EventType"='EnrollmentGrantExecutionRequested') THEN
                IF TG_OP='DELETE' THEN
                    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Enrollment grant outbox anchors are immutable.';
                END IF;
                IF TG_OP='UPDATE' AND (OLD."EnvironmentId",OLD."Id",OLD."EventType",OLD."Version",OLD."Payload",OLD."CreatedAt")
                    IS DISTINCT FROM (NEW."EnvironmentId",NEW."Id",NEW."EventType",NEW."Version",NEW."Payload",NEW."CreatedAt") THEN
                    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Enrollment grant outbox anchor identity is immutable.';
                END IF;
            END IF;
            RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
        END
        $function$;

        CREATE FUNCTION public.validate_enrollment_grant_queue_anchor() RETURNS trigger
            LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            environment_uuid uuid;
            plan_uuid uuid;
            operation_row public."EnrollmentGrantOperations"%ROWTYPE;
            plan_state integer;
            plan_action text;
            operation_count integer;
            outbox_count integer;
        BEGIN
            IF TG_TABLE_NAME='Plans' THEN
                environment_uuid:=coalesce(NEW."EnvironmentId",OLD."EnvironmentId");
                plan_uuid:=coalesce(NEW."Id",OLD."Id");
            ELSIF TG_TABLE_NAME='EnrollmentGrantOperations' THEN
                environment_uuid:=coalesce(NEW."EnvironmentId",OLD."EnvironmentId");
                plan_uuid:=coalesce(NEW."PlanId",OLD."PlanId");
            ELSE
                IF coalesce(NEW."EventType",OLD."EventType")<>'EnrollmentGrantExecutionRequested' THEN RETURN NULL; END IF;
                environment_uuid:=coalesce(NEW."EnvironmentId",OLD."EnvironmentId");
                SELECT * INTO operation_row FROM public."EnrollmentGrantOperations"
                WHERE "EnvironmentId"=environment_uuid AND "Id"=coalesce(NEW."Id",OLD."Id");
                IF NOT FOUND THEN
                    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment grant outbox requires its operation.';
                END IF;
                plan_uuid:=operation_row."PlanId";
            END IF;

            SELECT "State","Action" INTO plan_state,plan_action FROM public."Plans"
            WHERE "EnvironmentId"=environment_uuid AND "Id"=plan_uuid;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment grant anchor plan is unavailable.';
            END IF;
            SELECT count(*)::integer INTO operation_count FROM public."EnrollmentGrantOperations"
            WHERE "EnvironmentId"=environment_uuid AND "PlanId"=plan_uuid;
            IF plan_action='agent-enrollment.initial-grant.v1' AND plan_state=5 THEN
                IF operation_count<>1 THEN
                    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Queued enrollment grant plan requires one operation.';
                END IF;
                SELECT * INTO STRICT operation_row FROM public."EnrollmentGrantOperations"
                WHERE "EnvironmentId"=environment_uuid AND "PlanId"=plan_uuid;
                SELECT count(*)::integer INTO outbox_count FROM public."Outbox"
                WHERE "EnvironmentId"=environment_uuid AND "Id"=operation_row."Id"
                  AND "EventType"='EnrollmentGrantExecutionRequested' AND "Version"=1
                  AND "CreatedAt"=operation_row."QueuedAt"
                  AND "Payload"=jsonb_build_object('version',1,'environmentId',environment_uuid,'operationId',operation_row."Id");
                IF outbox_count<>1 THEN
                    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Queued enrollment grant plan requires its exact outbox.';
                END IF;
            ELSIF operation_count<>0 THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment grant operation requires a queued plan.';
            END IF;
            RETURN NULL;
        END
        $function$;

        REVOKE ALL ON FUNCTION public.guard_enrollment_grant_queued_plan() FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.guard_enrollment_grant_plan_child() FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.guard_enrollment_grant_operation_parent() FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.guard_enrollment_grant_outbox_anchor() FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.validate_enrollment_grant_queue_anchor() FROM PUBLIC;

        CREATE TRIGGER enrollment_grant_queued_plan_immutable BEFORE INSERT OR UPDATE OR DELETE ON public."Plans"
            FOR EACH ROW EXECUTE FUNCTION public.guard_enrollment_grant_queued_plan();
        CREATE TRIGGER enrollment_grant_plan_items_anchor BEFORE INSERT OR UPDATE OR DELETE ON public."PlanItems"
            FOR EACH ROW EXECUTE FUNCTION public.guard_enrollment_grant_plan_child();
        CREATE TRIGGER enrollment_grant_approvals_anchor BEFORE INSERT OR UPDATE OR DELETE ON public."Approvals"
            FOR EACH ROW EXECUTE FUNCTION public.guard_enrollment_grant_plan_child();
        CREATE TRIGGER enrollment_grant_operation_parent BEFORE INSERT ON public."EnrollmentGrantOperations"
            FOR EACH ROW EXECUTE FUNCTION public.guard_enrollment_grant_operation_parent();
        CREATE TRIGGER enrollment_grant_outbox_anchor BEFORE INSERT OR UPDATE OR DELETE ON public."Outbox"
            FOR EACH ROW EXECUTE FUNCTION public.guard_enrollment_grant_outbox_anchor();

        CREATE CONSTRAINT TRIGGER enrollment_grant_plan_anchor_consistent AFTER INSERT OR UPDATE ON public."Plans"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.validate_enrollment_grant_queue_anchor();
        CREATE CONSTRAINT TRIGGER enrollment_grant_operation_anchor_consistent AFTER INSERT ON public."EnrollmentGrantOperations"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.validate_enrollment_grant_queue_anchor();
        CREATE CONSTRAINT TRIGGER enrollment_grant_outbox_anchor_consistent AFTER INSERT OR UPDATE OR DELETE ON public."Outbox"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.validate_enrollment_grant_queue_anchor();
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Queued enrollment grant anchors require a reviewed forward migration.");
}
