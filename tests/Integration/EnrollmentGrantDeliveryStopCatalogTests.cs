using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    public static IEnumerable<object[]> DeliveryStopCatalogCases => new[]
    {
        "none", "missing", "owner", "not-null", "default", "collation", "extra-column", "reason-check",
        "foreign-action", "foreign-deferred", "foreign-unvalidated", "bare-primary", "included-primary", "extra-index",
        "incoming-foreign-key", "replica-identity", "rls", "force-rls", "boundary-disabled", "immutable-disabled",
        "consistent-missing", "consistent-ordinary", "consistent-immediate", "consistent-condition", "consistent-event",
        "peer-missing", "validator-missing", "peer-disabled", "peer-renamed", "peer-extra", "extra-boundary", "ri-disabled", "ri-always"
    }.Select(fault => new object[] { fault });

    [Theory]
    [MemberData(nameof(DeliveryStopCatalogCases))]
    public async Task DeliveryStopCatalogRejectsStructuralDrift(string fault)
    {
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }
        await Execute("SET LOCAL search_path=pg_catalog,pg_temp");
        var query = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-stops.sql")))
            .Replace(":'expected_table_owner_role'", "current_user::text", StringComparison.Ordinal);
        async Task<bool> Valid(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            var result = reader.GetBoolean(0);
            Assert.False(await reader.ReadAsync());
            return result;
        }
        Assert.True(await Valid(query));
        Assert.False(await Valid(query.Replace("current_user::text", "'stop_catalog_missing_owner'", StringComparison.Ordinal)));
        await Execute(DeliveryStopMutationSql(fault, QuoteIdentifier(_fixture.PlanLockOwner)));
        Assert.Equal(fault == "none", await Valid(query));
        await transaction.RollbackAsync();
    }

    internal static string DeliveryStopMutationSql(string fault, string alternateOwner)
    {
        const string table = "enrollment_execution.execution_stops";
        return fault switch
        {
            "none" => "SELECT 1",
            "missing" => $"DROP TABLE {table} CASCADE",
            "owner" => $"ALTER TABLE {table} OWNER TO {alternateOwner}",
            "not-null" => $"ALTER TABLE {table} ALTER COLUMN recorded_at DROP NOT NULL",
            "default" => $"ALTER TABLE {table} ALTER COLUMN reason SET DEFAULT 'StoredDataInvalid'",
            "collation" => $"ALTER TABLE {table} ALTER COLUMN reason TYPE text COLLATE \"C\"",
            "extra-column" => $"ALTER TABLE {table} ADD COLUMN extra text",
            "reason-check" => $"ALTER TABLE {table} DROP CONSTRAINT execution_stops_reason_check",
            "foreign-action" => ReplaceForeignKey("ON DELETE CASCADE"),
            "foreign-deferred" => ReplaceForeignKey("ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED"),
            "foreign-unvalidated" => ReplaceForeignKey("ON DELETE RESTRICT NOT VALID"),
            "bare-primary" => $"ALTER TABLE {table} DROP CONSTRAINT execution_stops_pkey; CREATE UNIQUE INDEX execution_stops_pkey ON {table}(operation_id)",
            "included-primary" => $"ALTER TABLE {table} DROP CONSTRAINT execution_stops_pkey; ALTER TABLE {table} ADD CONSTRAINT execution_stops_pkey PRIMARY KEY(operation_id) INCLUDE(reason)",
            "extra-index" => $"CREATE INDEX stop_extra_index ON {table}(reason)",
            "incoming-foreign-key" => $"CREATE TABLE enrollment_execution.stop_incoming(id uuid REFERENCES {table}(operation_id))",
            "replica-identity" => $"ALTER TABLE {table} REPLICA IDENTITY FULL",
            "rls" => $"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY",
            "force-rls" => $"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY",
            "boundary-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER execution_stops_boundary",
            "immutable-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER execution_stops_immutable",
            "consistent-missing" => $"DROP TRIGGER execution_stops_consistent ON {table}",
            "consistent-ordinary" => ReplaceConsistent("", "", "INSERT", ""),
            "consistent-immediate" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY IMMEDIATE", "INSERT", ""),
            "consistent-condition" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY DEFERRED", "INSERT", "WHEN (NEW.reason<>'StoredDataInvalid')"),
            "consistent-event" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY DEFERRED", "INSERT OR UPDATE", ""),
            "peer-missing" => "ALTER TABLE enrollment_execution.delivery_acks RENAME TO renamed_delivery_acks",
            "validator-missing" => "ALTER FUNCTION enrollment_execution.validate_execution_stop() RENAME TO renamed_validate_execution_stop",
            "peer-disabled" => "ALTER TABLE enrollment_execution.delivery_acks DISABLE TRIGGER delivery_acks_stop_consistent",
            "peer-renamed" => "ALTER TRIGGER issue_results_stop_consistent ON enrollment_execution.issue_results RENAME TO renamed_stop_consistent",
            "peer-extra" => "CREATE CONSTRAINT TRIGGER extra_stop_consistent AFTER INSERT ON enrollment_execution.mint_permits DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_execution_stop()",
            "extra-boundary" => "CREATE TRIGGER extra_stop_boundary BEFORE INSERT ON enrollment_execution.delivery_acks FOR EACH ROW EXECUTE FUNCTION enrollment_execution.lock_execution_stop_boundary()",
            "ri-disabled" => ChangeForeignTrigger("DISABLE"),
            "ri-always" => ChangeForeignTrigger("ENABLE ALWAYS"),
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        };

        static string ReplaceForeignKey(string suffix) => $"ALTER TABLE {table} DROP CONSTRAINT execution_stops_operation_id_fkey; ALTER TABLE {table} ADD CONSTRAINT execution_stops_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES public.\"EnrollmentGrantOperations\"(\"Id\") {suffix}";
        static string ReplaceConsistent(string kind, string timing, string events, string condition) =>
            $"DROP TRIGGER execution_stops_consistent ON {table}; CREATE {kind} TRIGGER execution_stops_consistent AFTER {events} ON {table} {timing} FOR EACH ROW {condition} EXECUTE FUNCTION enrollment_execution.validate_execution_stop()";
        static string ChangeForeignTrigger(string action) => $$"""
            DO $stop_ri_drift$ DECLARE target record; BEGIN
              SELECT trigger.tgname INTO STRICT target FROM pg_catalog.pg_trigger trigger
              JOIN pg_catalog.pg_constraint constraint_row ON constraint_row.oid=trigger.tgconstraint
              WHERE constraint_row.conrelid='enrollment_execution.execution_stops'::regclass
                AND constraint_row.conname='execution_stops_operation_id_fkey' AND trigger.tgtype=9;
              EXECUTE pg_catalog.format('ALTER TABLE public."EnrollmentGrantOperations" {{action}} TRIGGER %I',target.tgname);
            END $stop_ri_drift$;
            """;
    }
}

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task DeliveryGeneratedStopStructureCatalogMatchesSource()
    {
        const string begin = "    -- BEGIN generated delivery stop structure catalog";
        const string end = "    -- END generated delivery stop structure catalog";
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-stops.sql"));
        var query = source[source.IndexOf("WITH ", StringComparison.Ordinal)..].Trim().TrimEnd(';')
            .Replace(":'expected_table_owner_role'", "pg_catalog.pg_get_userbyid(table_owner)", StringComparison.Ordinal);
        var expected = begin + "\n    -- Source: audit-enrollment-delivery-stops.sql\n    ok := ok AND (\n" + query + "\n    );\n" + end;
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        Assert.Equal(1, profile.Split(begin, StringSplitOptions.None).Length - 1);
        Assert.Equal(1, profile.Split(end, StringSplitOptions.None).Length - 1);
        var start = profile.IndexOf(begin, StringComparison.Ordinal);
        var finish = profile.IndexOf(end, StringComparison.Ordinal) + end.Length;
        Assert.Equal(expected.Replace("\r\n", "\n"), profile[start..finish].Replace("\r\n", "\n"));
    }

    private static string DeliveryStopCatalogProbe()
    {
        var sql = "";
        foreach (var fault in EnrollmentGrantPlanTests.DeliveryStopCatalogCases.Select(row => (string)row[0]).Where(fault => fault != "none"))
        {
            sql += "SAVEPOINT stop_catalog_case;\n" + EnrollmentGrantPlanTests.DeliveryStopMutationSql(fault, ":\"execution_runtime_role\"") + ";\n";
            foreach (var role in new[] { "status_runtime_role", "delivery_runtime_role" })
            {
                sql += $"SET LOCAL SESSION AUTHORIZATION :\"{role}\";\n";
                sql += $$"""
                    DO $composed_stop_probe$
                    DECLARE row_count integer; rejected boolean;
                    BEGIN
                      SELECT count(*),bool_and(result.is_valid IS FALSE AND result.diagnostic_code='ProfileDrift' AND result.profile_version=4)
                        INTO row_count,rejected FROM enrollment_execution.audit_delivery_privileges(
                          current_setting('app.catalog_expected_environment_id')::uuid) result;
                      IF row_count<>1 OR rejected IS DISTINCT FROM true THEN
                        RAISE EXCEPTION 'Composed stop catalog accepted: {{fault}}';
                      END IF;
                    END $composed_stop_probe$;

                    """;
                sql += "RESET SESSION AUTHORIZATION;\n";
            }
            sql += "ROLLBACK TO SAVEPOINT stop_catalog_case;\nRELEASE SAVEPOINT stop_catalog_case;\n";
        }
        return sql;
    }
}
