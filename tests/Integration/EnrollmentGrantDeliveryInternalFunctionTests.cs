namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static string DeliveryInternalFunctionProbe()
    {
        var signatures = new[]
        {
            "guard_status_observation()",
            "record_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)",
            "read_status_refresh_receipt(uuid,uuid)", "lock_delivery_context(uuid,uuid,uuid,text)",
            "get_sealed_delivery(uuid,uuid,uuid,text)", "ack_sealed_delivery(uuid,uuid,uuid,text,bytea,bytea)",
            "delivery_worker_scope(uuid,text)", "read_grant_status_receipt(uuid,uuid)",
            "append_grant_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)",
            "read_grant_delivery(uuid,uuid,uuid,text)", "acknowledge_grant_delivery(uuid,uuid,uuid,text,bytea,bytea)",
            "reject_delivery_update()", "audit_delivery_privileges(uuid)", "scope_uuid(text)",
            "has_computer_permission(uuid,uuid,uuid,uuid,text)", "reject_history_mutation()", "validate_journal()", "validate_execution_stop()",
            "lock_execution_stop_boundary()"
        };
        var mutations = new List<(string Label, string Sql)>();
        mutations.Add(("existing queue attestation retained", "ALTER FUNCTION enrollment_execution.guard_work_queue() STRICT;"));
        foreach (var signature in signatures)
            foreach (var alteration in new[] { "RESET ALL", "SUPPORT pg_catalog.textlike_support", "LEAKPROOF" })
                mutations.Add((signature.Split('(')[0] + " " + alteration,
                    "ALTER FUNCTION enrollment_execution." + signature + " " + alteration + ";"));
        foreach (var signature in new[] { signatures[1], signatures[2], signatures[4], signatures[5] })
            mutations.Add((signature.Split('(')[0] + " output ABI", AlterDeliveryOutputType(signature, "contract_version smallint")));
        mutations.Add(("lock context output ABI", AlterDeliveryOutputType(signatures[3], "authorized boolean")));
        mutations.Add(("unexpected overload", "CREATE FUNCTION enrollment_execution.scope_uuid(integer) RETURNS uuid LANGUAGE sql AS 'SELECT NULL::uuid';"));
        mutations.Add(("argument default", """
            DO $argument_default$
            DECLARE definition text; original text;
            BEGIN
              SELECT pg_catalog.pg_get_functiondef(p.oid),p.prosrc INTO STRICT definition,original
                FROM pg_catalog.pg_proc p WHERE p.oid='enrollment_execution.scope_uuid(text)'::regprocedure;
              IF pg_catalog.strpos(definition,'p_value text)')=0 THEN RAISE EXCEPTION 'Missing input argument.'; END IF;
              EXECUTE pg_catalog.replace(definition,'p_value text)','p_value text DEFAULT NULL::text)');
              IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='enrollment_execution.scope_uuid(text)'::regprocedure AND p.prosrc=original)
                THEN RAISE EXCEPTION 'Argument-default probe changed the body.'; END IF;
            END $argument_default$;
            """));
        var sql = "";
        foreach (var role in new[] { "status_runtime_role", "delivery_runtime_role" })
            foreach (var mutation in mutations)
            {
                sql += "SAVEPOINT internal_function_case;\n" + mutation.Sql + "\n";
                sql += $"SET LOCAL SESSION AUTHORIZATION :\"{role}\";\n";
                sql += $$"""
                    DO $internal_function_probe$
                    DECLARE row_count integer; rejected boolean;
                    BEGIN
                      SELECT count(*),bool_and(result.is_valid IS FALSE AND result.diagnostic_code='ProfileDrift' AND result.profile_version=4)
                        INTO row_count,rejected FROM enrollment_execution.audit_delivery_privileges(
                          current_setting('app.catalog_expected_environment_id')::uuid) result;
                      IF row_count<>1 OR rejected IS DISTINCT FROM true THEN
                        RAISE EXCEPTION 'Internal function contract accepted: {{mutation.Label}}';
                      END IF;
                    END $internal_function_probe$;

                    """;
                sql += "RESET SESSION AUTHORIZATION;\nROLLBACK TO SAVEPOINT internal_function_case;\nRELEASE SAVEPOINT internal_function_case;\n";
            }
        return sql;
    }
}
