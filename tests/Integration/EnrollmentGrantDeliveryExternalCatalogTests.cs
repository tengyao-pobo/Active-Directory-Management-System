using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task DeliveryExternalCatalogMissingIdentityReturnsOneBoolean()
    {
        var connectionString = Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!;
        var owner = new NpgsqlConnectionStringBuilder(connectionString).Username!;
        var query = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-catalog.sql"));
        foreach (var parameter in new[] { "runtime_role", "delivery_definer_role", "expected_table_owner_role", "expected_environment_id", "expected_purpose" })
            query = query.Replace(":'" + parameter + "'", "@" + parameter, StringComparison.Ordinal);
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(query, connection);
        command.Parameters.AddWithValue("runtime_role", owner);
        command.Parameters.AddWithValue("delivery_definer_role", "catalog_missing_" + Guid.NewGuid().ToString("N"));
        command.Parameters.AddWithValue("expected_table_owner_role", owner);
        command.Parameters.AddWithValue("expected_environment_id", Guid.NewGuid());
        command.Parameters.AddWithValue("expected_purpose", "EnrollmentGrantDelivery");
        await using var reader = await command.ExecuteReaderAsync();
        Assert.Equal(1, reader.FieldCount);
        Assert.Equal("is_valid", reader.GetName(0));
        Assert.Equal(typeof(bool), reader.GetFieldType(0));
        Assert.True(await reader.ReadAsync());
        Assert.False(await reader.IsDBNullAsync(0));
        Assert.False(reader.GetBoolean(0));
        Assert.False(await reader.ReadAsync());
        Assert.False(await reader.NextResultAsync());
    }

    private static async Task<string> DeliveryExternalCatalogProbeAsync(CancellationToken cancellationToken)
    {
        var query = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-catalog.sql"), cancellationToken)).Trim().TrimEnd(';');
        foreach (var parameter in new[] { "runtime_role", "delivery_definer_role", "expected_table_owner_role", "expected_environment_id", "expected_purpose" })
        {
            Assert.Equal(1, query.Split(":'" + parameter + "'", StringSplitOptions.None).Length - 1);
            query = query.Replace(":'" + parameter + "'", "current_setting('app.catalog_" + parameter + "')", StringComparison.Ordinal);
        }
        var sql = """
            SELECT pg_catalog.set_config('app.catalog_delivery_definer_role',:'delivery_definer_role',true),
              pg_catalog.set_config('app.catalog_expected_table_owner_role',:'expected_table_owner_role',true),
              pg_catalog.set_config('app.catalog_expected_environment_id',:'expected_environment_id',true);

            """;
        foreach (var (role, purpose) in new[] { ("status_runtime_role", "EnrollmentGrantStatusRefresh"), ("delivery_runtime_role", "EnrollmentGrantDelivery") })
        {
            sql += $"SELECT pg_catalog.set_config('app.catalog_runtime_role',:'{role}',true), pg_catalog.set_config('app.catalog_expected_purpose','{purpose}',true);\n";
            sql += $"SET LOCAL SESSION AUTHORIZATION :\"{role}\";\n" + Verify(query, true, "canonical " + purpose);
            foreach (var parameter in new[] { "runtime_role", "delivery_definer_role", "expected_table_owner_role" })
                sql += Verify(query.Replace("current_setting('app.catalog_" + parameter + "')", "'catalog_missing_role'", StringComparison.Ordinal), false, "missing " + parameter);
            sql += Verify(query.Replace("current_setting('app.catalog_expected_environment_id')", "NULL::text", StringComparison.Ordinal), false, "null environment");
            sql += Verify(query.Replace("current_setting('app.catalog_expected_environment_id')", "'00000000-0000-0000-0000-000000000000'", StringComparison.Ordinal), false, "zero environment");
            sql += Verify(query.Replace("current_setting('app.catalog_expected_purpose')", "'Unsupported'", StringComparison.Ordinal), false, "unknown purpose");
            var opposite = purpose == "EnrollmentGrantDelivery" ? "EnrollmentGrantStatusRefresh" : "EnrollmentGrantDelivery";
            sql += Verify(query.Replace("current_setting('app.catalog_expected_purpose')", "'" + opposite + "'", StringComparison.Ordinal), false, "purpose crossover");
            sql += "RESET SESSION AUTHORIZATION;\n";
            foreach (var setting in new[] { "session_replication_role=replica", "lo_compat_privileges=on" })
            {
                sql += "SAVEPOINT external_catalog_setting;\nSET LOCAL " + setting + ";\n";
                sql += $"SET LOCAL SESSION AUTHORIZATION :\"{role}\";\n" + Verify(query, false, setting);
                sql += """
                    DO $internal_setting_probe$
                    DECLARE row_count integer; rejected boolean;
                    BEGIN
                      SELECT count(*),bool_and(result.is_valid IS FALSE AND result.diagnostic_code='ProfileDrift' AND result.profile_version=4)
                        INTO row_count,rejected FROM enrollment_execution.audit_delivery_privileges(
                          current_setting('app.catalog_expected_environment_id')::uuid) result;
                      IF row_count<>1 OR rejected IS DISTINCT FROM true THEN
                        RAISE EXCEPTION 'Internal audit accepted unsafe session settings.';
                      END IF;
                    END $internal_setting_probe$;

                    """;
                sql += "RESET SESSION AUTHORIZATION;\nROLLBACK TO SAVEPOINT external_catalog_setting;\nRELEASE SAVEPOINT external_catalog_setting;\n";
            }
            var wrapper = purpose == "EnrollmentGrantDelivery" ? "read_grant_delivery(uuid,uuid,uuid,text)" : "read_grant_status_receipt(uuid,uuid)";
            var mutations = new List<(string Label, string Sql)>
            {
                ("role inherit", $"ALTER ROLE :\"{role}\" INHERIT;"),
                ("role createdb", $"ALTER ROLE :\"{role}\" CREATEDB;"),
                ("role membership", $"GRANT :\"delivery_definer_role\" TO :\"{role}\";"),
                ("definer login", "ALTER ROLE :\"delivery_definer_role\" LOGIN;"),
                ("definer database create", "GRANT CREATE ON DATABASE :\"DBNAME\" TO :\"delivery_definer_role\";"),
                ("runtime ownership", $"CREATE SCHEMA catalog_runtime_owned AUTHORIZATION :\"{role}\";"),
                ("definer ownership", "CREATE SCHEMA catalog_definer_owned AUTHORIZATION :\"delivery_definer_role\";"),
                ("extra function", $"GRANT EXECUTE ON FUNCTION enrollment_execution.delivery_worker_scope(uuid,text) TO :\"{role}\";"),
                ("missing wrapper grant", $"REVOKE EXECUTE ON FUNCTION enrollment_execution.{wrapper} FROM :\"{role}\";"),
                ("grant option", $"GRANT EXECUTE ON FUNCTION enrollment_execution.audit_delivery_privileges(uuid) TO :\"{role}\" WITH GRANT OPTION;"),
                ("public entry", "GRANT EXECUTE ON FUNCTION enrollment_execution.audit_delivery_privileges(uuid) TO PUBLIC;"),
                ("extra schema usage", $"GRANT USAGE ON SCHEMA public TO :\"{role}\";"),
                ("extra database privilege", $"GRANT TEMP ON DATABASE :\"DBNAME\" TO :\"{role}\";"),
                ("column access", $"GRANT SELECT(\"Id\") ON public.\"Environments\" TO :\"{role}\";"),
                ("maintain access", $"GRANT MAINTAIN ON public.\"Environments\" TO :\"{role}\";"),
                ("type access", $"CREATE DOMAIN public.catalog_extra_type AS text; GRANT USAGE ON DOMAIN public.catalog_extra_type TO :\"{role}\";"),
                ("large object access", "DO $large_object$ DECLARE object_id oid:=pg_catalog.lo_create(0); BEGIN EXECUTE pg_catalog.format('GRANT SELECT ON LARGE OBJECT %s TO %I',object_id,current_setting('app.catalog_runtime_role')); END $large_object$;"),
                ("public large object read", "DO $large_object$ DECLARE object_id oid:=pg_catalog.lo_create(0); BEGIN EXECUTE pg_catalog.format('GRANT SELECT ON LARGE OBJECT %s TO PUBLIC',object_id); END $large_object$;"),
                ("public large object write", "DO $large_object$ DECLARE object_id oid:=pg_catalog.lo_create(0); BEGIN EXECUTE pg_catalog.format('GRANT UPDATE ON LARGE OBJECT %s TO PUBLIC',object_id); END $large_object$;"),
                ("public trigger bypass parameter", "GRANT SET ON PARAMETER session_replication_role TO PUBLIC;"),
                ("public alter system parameter", "GRANT ALTER SYSTEM ON PARAMETER log_statement TO PUBLIC;"),
                ("sequence access", $"CREATE SEQUENCE public.catalog_extra_sequence; GRANT USAGE ON SEQUENCE public.catalog_extra_sequence TO :\"{role}\";"),
                ("public definer function", "CREATE FUNCTION public.catalog_extra_definer() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';"),
                ("marker body", "CREATE OR REPLACE FUNCTION enrollment_execution.execution_store_profile() RETURNS smallint LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS 'SELECT 3::smallint';"),
                ("marker public", "GRANT EXECUTE ON FUNCTION enrollment_execution.execution_store_profile() TO PUBLIC;"),
                ("marker owner ACL absent", "REVOKE EXECUTE ON FUNCTION enrollment_execution.execution_store_profile() FROM :\"expected_table_owner_role\";"),
                ("missing schema", "DROP SCHEMA enrollment_execution CASCADE;"),
                ("missing API attestor", "DROP FUNCTION public.api_database_session() CASCADE;"),
                ("API attestor config", "ALTER FUNCTION public.api_database_session() RESET ALL;"),
                ("API public ACL absent", "REVOKE EXECUTE ON FUNCTION public.api_database_session() FROM PUBLIC;"),
                ("API owner ACL absent", "REVOKE EXECUTE ON FUNCTION public.api_database_session() FROM :\"expected_table_owner_role\";")
            };
            foreach (var signature in new[]
            {
                "audit_execution_privileges(uuid)", "audit_delivery_privileges(uuid)", "execution_store_profile()", "delivery_worker_scope(uuid,text)",
                "read_grant_status_receipt(uuid,uuid)",
                "append_grant_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)",
                "read_grant_delivery(uuid,uuid,uuid,text)", "acknowledge_grant_delivery(uuid,uuid,uuid,text,bytea,bytea)"
            }) mutations.Add(("missing " + signature.Split('(')[0], "DROP FUNCTION enrollment_execution." + signature + " CASCADE;"));
            foreach (var audit in new[] { "audit_execution_privileges(uuid)", "audit_delivery_privileges(uuid)" })
            {
                foreach (var alteration in new[] { "RESET ALL", "SECURITY INVOKER", "STRICT", "SET search_path TO public", "SUPPORT pg_catalog.textlike_support" })
                    mutations.Add((audit.Split('(')[0] + " " + alteration, "ALTER FUNCTION enrollment_execution." + audit + " " + alteration + ";"));
                mutations.Add((audit.Split('(')[0] + " owner", "ALTER FUNCTION enrollment_execution." + audit + " OWNER TO :\"delivery_definer_role\";"));
                mutations.Add((audit.Split('(')[0] + " output ABI", AlterOutputType(audit, "profile_version smallint")));
            }
            foreach (var entry in new[] { "read_grant_status_receipt(uuid,uuid)",
                "append_grant_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)",
                "read_grant_delivery(uuid,uuid,uuid,text)", "acknowledge_grant_delivery(uuid,uuid,uuid,text,bytea,bytea)" })
                mutations.Add((entry.Split('(')[0] + " output ABI", AlterOutputType(entry, "contract_version smallint")));
            foreach (var mutation in mutations)
            {
                sql += "SAVEPOINT external_catalog_case;\n" + mutation.Sql + "\n";
                sql += $"SET LOCAL SESSION AUTHORIZATION :\"{role}\";\n" + Verify(query, false, mutation.Label);
                sql += "RESET SESSION AUTHORIZATION;\nROLLBACK TO SAVEPOINT external_catalog_case;\nRELEASE SAVEPOINT external_catalog_case;\n";
            }
        }
        return sql;

        static string AlterOutputType(string signature, string field) => $$"""
            DO $alter_output_contract$
            DECLARE original record; grant_row record; grants jsonb; definition text;
            BEGIN
              SELECT p.* INTO STRICT original FROM pg_catalog.pg_proc p
                WHERE p.oid='enrollment_execution.{{signature}}'::regprocedure;
              definition:=pg_catalog.pg_get_functiondef(original.oid);
              IF pg_catalog.strpos(definition,'{{field}}')=0 THEN
                RAISE EXCEPTION 'Expected output field was not found.';
              END IF;
              SELECT COALESCE(jsonb_agg(jsonb_build_object('role',pg_catalog.pg_get_userbyid(acl.grantee),
                'grantable',acl.is_grantable)),'[]'::jsonb) INTO grants
                FROM pg_catalog.aclexplode(original.proacl) acl WHERE acl.grantee<>original.proowner;
              EXECUTE 'DROP FUNCTION enrollment_execution.{{signature}} CASCADE';
              EXECUTE pg_catalog.replace(definition,'{{field}}','{{field.Replace("smallint", "integer", StringComparison.Ordinal)}}');
              EXECUTE pg_catalog.format('ALTER FUNCTION enrollment_execution.{{signature}} OWNER TO %I',pg_catalog.pg_get_userbyid(original.proowner));
              EXECUTE 'REVOKE ALL ON FUNCTION enrollment_execution.{{signature}} FROM PUBLIC';
              FOR grant_row IN SELECT * FROM jsonb_to_recordset(grants) AS grant_data(role text,grantable boolean)
              LOOP
                EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION enrollment_execution.{{signature}} TO %I%s',
                  grant_row.role,CASE WHEN grant_row.grantable THEN ' WITH GRANT OPTION' ELSE '' END);
              END LOOP;
              IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
                WHERE p.oid='enrollment_execution.{{signature}}'::regprocedure AND p.prosrc=original.prosrc) THEN
                RAISE EXCEPTION 'Output-contract probe changed the function body.';
              END IF;
            END $alter_output_contract$;

            """;

        static string Verify(string candidate, bool expected, string label) => $$"""
            DO $external_catalog_probe$
            DECLARE row_count integer; verdict boolean;
            BEGIN
              SELECT count(*),bool_and(result.is_valid) INTO row_count,verdict FROM ({{candidate}}) result;
              IF row_count<>1 OR verdict IS DISTINCT FROM {{(expected ? "true" : "false")}} THEN
                RAISE EXCEPTION 'External catalog failed: {{label}}';
              END IF;
            END $external_catalog_probe$;

            """;
    }
}
