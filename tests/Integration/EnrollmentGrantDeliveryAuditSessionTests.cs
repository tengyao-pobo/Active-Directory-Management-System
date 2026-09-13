namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static string DeliveryAuditSessionProbe()
    {
        // Server-side identity simulation in the rollback-only installed candidate.
        // Physical LOGIN and the application pool's external audit remain separate tests.
        const string runtimeProbe = """
            DO $runtime_audit_probe$
            DECLARE audit_row record; test_environment uuid;
            BEGIN
              IF SESSION_USER::text<>current_setting('app.delivery_test_login') OR CURRENT_USER<>SESSION_USER THEN
                RAISE EXCEPTION 'Delivery test did not enter the intended session identity.';
              END IF;
              SELECT * INTO STRICT audit_row FROM enrollment_execution.audit_delivery_privileges(
                current_setting('app.delivery_test_environment')::uuid);
              IF audit_row.is_valid IS DISTINCT FROM true OR audit_row.diagnostic_code IS DISTINCT FROM 'None'
                OR audit_row.profile_version IS DISTINCT FROM 4::smallint THEN
                RAISE EXCEPTION 'Bound delivery session was rejected.';
              END IF;
              FOREACH test_environment IN ARRAY ARRAY[current_setting('app.delivery_test_other_environment')::uuid,
                NULL::uuid,'00000000-0000-0000-0000-000000000000'::uuid,gen_random_uuid()]
              LOOP
                SELECT * INTO STRICT audit_row FROM enrollment_execution.audit_delivery_privileges(test_environment);
                IF audit_row.is_valid IS DISTINCT FROM false OR audit_row.diagnostic_code IS DISTINCT FROM 'ProfileDrift'
                  OR audit_row.profile_version IS DISTINCT FROM 4::smallint THEN
                  RAISE EXCEPTION 'Delivery session accepted an unbound environment.';
                END IF;
              END LOOP;
            END $runtime_audit_probe$;
            RESET SESSION AUTHORIZATION;

            """;
        var sql = """
            SELECT pg_catalog.set_config('app.delivery_test_environment',:'expected_environment_id',true),
              pg_catalog.set_config('app.delivery_test_other_environment',:'other_environment_id',true);
            DO $owner_audit_probe$
            DECLARE audit_row record; test_environment uuid;
            BEGIN
              FOREACH test_environment IN ARRAY ARRAY[current_setting('app.delivery_test_environment')::uuid,
                current_setting('app.delivery_test_other_environment')::uuid]
              LOOP
                SELECT * INTO STRICT audit_row FROM enrollment_execution.audit_delivery_privileges(test_environment);
                IF audit_row.is_valid IS DISTINCT FROM true OR audit_row.diagnostic_code IS DISTINCT FROM 'None'
                  OR audit_row.profile_version IS DISTINCT FROM 4::smallint THEN
                  RAISE EXCEPTION 'Owner could not inspect a valid environment profile.';
                END IF;
              END LOOP;
            END $owner_audit_probe$;

            """;
        foreach (var role in new[] { "status_runtime_role", "delivery_runtime_role" })
            sql += $"SELECT pg_catalog.set_config('app.delivery_test_login',:'{role}',true);\nSET LOCAL SESSION AUTHORIZATION :\"{role}\";\n" + runtimeProbe;
        return sql + """
            SET LOCAL SESSION AUTHORIZATION :"delivery_definer_role";
            DO $definer_audit_probe$
            DECLARE audit_row record;
            BEGIN
              SELECT * INTO STRICT audit_row FROM enrollment_execution.audit_delivery_privileges(
                current_setting('app.delivery_test_environment')::uuid);
              IF audit_row.is_valid IS DISTINCT FROM false OR audit_row.diagnostic_code IS DISTINCT FROM 'ProfileDrift'
                OR audit_row.profile_version IS DISTINCT FROM 4::smallint THEN
                RAISE EXCEPTION 'Delivery definer was accepted as a runtime session.';
              END IF;
            END $definer_audit_probe$;
            RESET SESSION AUTHORIZATION;
            """;
    }
}
