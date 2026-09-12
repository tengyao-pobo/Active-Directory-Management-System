namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task DeliveryGeneratedDefinerCatalogMatchesSource()
    {
        const string begin = "    -- BEGIN generated delivery definer catalog";
        const string end = "    -- END generated delivery definer catalog";
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-definer.sql"));
        var query = source[source.IndexOf("WITH ", StringComparison.Ordinal)..].Trim().TrimEnd(';')
            .Replace(":'expected_table_owner_role'", "pg_catalog.pg_get_userbyid(table_owner)", StringComparison.Ordinal)
            .Replace(":'delivery_definer_role'", "pg_catalog.pg_get_userbyid(delivery_definer)", StringComparison.Ordinal);
        var expected = begin + "\n    -- Source: audit-enrollment-delivery-definer.sql\n    ok := ok AND (\n" + query + "\n    );\n" + end;
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        Assert.Equal(1, profile.Split(begin, StringSplitOptions.None).Length - 1);
        Assert.Equal(1, profile.Split(end, StringSplitOptions.None).Length - 1);
        var start = profile.IndexOf(begin, StringComparison.Ordinal);
        var finish = profile.IndexOf(end, StringComparison.Ordinal) + end.Length;
        Assert.Equal(expected.Replace("\r\n", "\n"), profile[start..finish].Replace("\r\n", "\n"));
    }

    private static async Task<string> DeliveryDefinerCatalogProbeAsync(CancellationToken cancellationToken)
    {
        var query = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-definer.sql"), cancellationToken)).Trim().TrimEnd(';');
        foreach (var parameter in new[] { "delivery_definer_role", "expected_table_owner_role" })
        {
            Assert.Equal(1, query.Split(":'" + parameter + "'", StringSplitOptions.None).Length - 1);
            query = query.Replace(":'" + parameter + "'", "current_setting('app.catalog_" + parameter + "')", StringComparison.Ordinal);
        }
        var sql = Verify(query, true, "canonical");
        foreach (var parameter in new[] { "delivery_definer_role", "expected_table_owner_role" })
            sql += Verify(query.Replace("current_setting('app.catalog_" + parameter + "')", "'catalog_missing_role'", StringComparison.Ordinal), false, "missing " + parameter);
        foreach (var mutation in new (string Label, string Sql)[]
        {
            ("missing column", "REVOKE SELECT(\"ServerDeviceId\") ON public.\"EnrollmentGrantOperations\" FROM :\"delivery_definer_role\";"),
            ("missing stop read", "REVOKE SELECT ON enrollment_execution.execution_stops FROM :\"delivery_definer_role\";"),
            ("missing policy callee", "REVOKE EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid) FROM :\"delivery_definer_role\";"),
            ("missing owned ACL", "REVOKE EXECUTE ON FUNCTION enrollment_execution.read_grant_delivery(uuid,uuid,uuid,text) FROM :\"delivery_definer_role\";"),
            ("missing schema usage", "REVOKE USAGE ON SCHEMA enrollment_execution FROM :\"delivery_definer_role\";"),
            ("extra table privilege", "GRANT SELECT ON public.\"EnrollmentGrantOperations\" TO :\"delivery_definer_role\";"),
            ("extra column privilege", "GRANT UPDATE(\"Version\") ON public.\"Environments\" TO :\"delivery_definer_role\";"),
            ("redundant column privilege", "GRANT SELECT(\"Id\") ON public.\"Roles\" TO :\"delivery_definer_role\";"),
            ("extra function ACL", "GRANT EXECUTE ON FUNCTION public.api_database_session() TO :\"delivery_definer_role\";"),
            ("grant option", "GRANT SELECT ON enrollment_execution.execution_stops TO :\"delivery_definer_role\" WITH GRANT OPTION;"),
            ("system direct ACL", "GRANT SELECT ON pg_catalog.pg_class TO :\"delivery_definer_role\";"),
            ("other database ACL", "GRANT CONNECT ON DATABASE postgres TO :\"delivery_definer_role\";"),
            ("type ACL", "CREATE DOMAIN public.definer_extra_type AS text; GRANT USAGE ON DOMAIN public.definer_extra_type TO :\"delivery_definer_role\";"),
            ("owned schema", "CREATE SCHEMA definer_owned_extra AUTHORIZATION :\"delivery_definer_role\";"),
            ("owned extra function", "CREATE FUNCTION public.definer_owned_extra() RETURNS integer LANGUAGE sql AS 'SELECT 1'; ALTER FUNCTION public.definer_owned_extra() OWNER TO :\"delivery_definer_role\";"),
            ("public extra table access", "GRANT SELECT ON public.\"Outbox\" TO PUBLIC;"),
            ("public allowed table access", "GRANT SELECT ON enrollment_execution.execution_stops TO PUBLIC;"),
            ("public selected wrapper", "GRANT EXECUTE ON FUNCTION enrollment_execution.read_grant_delivery(uuid,uuid,uuid,text) TO PUBLIC;"),
            ("public delivery schema usage", "GRANT USAGE ON SCHEMA enrollment_execution TO PUBLIC;"),
            ("public schema usage", "CREATE SCHEMA definer_public_extra; GRANT USAGE ON SCHEMA definer_public_extra TO PUBLIC;"),
            ("public extra function access", "CREATE FUNCTION public.definer_extra_call() RETURNS integer LANGUAGE sql AS 'SELECT 1';"),
            ("public large object", "DO $large$ DECLARE object_id oid:=pg_catalog.lo_create(0); BEGIN EXECUTE pg_catalog.format('GRANT SELECT ON LARGE OBJECT %s TO PUBLIC',object_id); END $large$;"),
            ("public parameter", "GRANT SET ON PARAMETER session_replication_role TO PUBLIC;"),
            ("future ACL", "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO :\"delivery_definer_role\";"),
            ("login", "ALTER ROLE :\"delivery_definer_role\" LOGIN;"),
            ("inherit", "ALTER ROLE :\"delivery_definer_role\" INHERIT;"),
            ("membership", "GRANT :\"delivery_definer_role\" TO :\"status_runtime_role\";")
        })
        {
            sql += "SAVEPOINT definer_catalog_case;\n" + mutation.Sql + "\n" + Verify(query, false, mutation.Label);
            foreach (var role in new[] { "status_runtime_role", "delivery_runtime_role" })
            {
                sql += $"SET LOCAL SESSION AUTHORIZATION :\"{role}\";\n";
                sql += $$"""
                    DO $composed_definer_probe$
                    DECLARE row_count integer; rejected boolean;
                    BEGIN
                      SELECT count(*),bool_and(result.is_valid IS FALSE AND result.diagnostic_code='ProfileDrift' AND result.profile_version=4)
                        INTO row_count,rejected FROM enrollment_execution.audit_delivery_privileges(
                          current_setting('app.catalog_expected_environment_id')::uuid) result;
                      IF row_count<>1 OR rejected IS DISTINCT FROM true THEN
                        RAISE EXCEPTION 'Composed definer catalog accepted: {{mutation.Label}}';
                      END IF;
                    END $composed_definer_probe$;

                    """;
                sql += "RESET SESSION AUTHORIZATION;\n";
            }
            sql += "ROLLBACK TO SAVEPOINT definer_catalog_case;\nRELEASE SAVEPOINT definer_catalog_case;\n";
        }
        return sql;

        static string Verify(string candidate, bool expected, string label) => $$"""
            DO $definer_catalog_probe$
            DECLARE row_count integer; verdict boolean;
            BEGIN
              SELECT count(*),bool_and(result.is_valid) INTO row_count,verdict FROM ({{candidate}}) result;
              IF row_count<>1 OR verdict IS DISTINCT FROM {{(expected ? "true" : "false")}} THEN
                RAISE EXCEPTION 'Definer catalog failed: {{label}}';
              END IF;
            END $definer_catalog_probe$;

            """;
    }
}
