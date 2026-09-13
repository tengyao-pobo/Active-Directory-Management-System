using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    public static IEnumerable<object[]> DeliveryStatusCatalogCases => new[]
    {
        "none", "missing", "owner", "not-null", "default",
        "collation", "extra-column", "check", "foreign-action", "foreign-deferred",
        "foreign-unvalidated", "bare-unique", "extra-index", "included-index", "partial-index",
        "nulls-index", "incoming-foreign-key", "replica-identity", "rls", "force-rls",
        "guard-disabled", "guard-always", "guard-event", "guard-condition", "extra-trigger",
        "ri-disabled", "ri-always", "immutable-disabled"
    }.Select(fault => new object[] { fault });

    [Theory]
    [MemberData(nameof(DeliveryStatusCatalogCases))]
    public async Task DeliveryStatusCatalogRejectsStructuralDrift(string fault)
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
        var query = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-status.sql")))
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
        Assert.False(await Valid(query.Replace("current_user::text", "'status_catalog_missing_owner'", StringComparison.Ordinal)));
        await Execute(DeliveryStatusMutationSql(fault, QuoteIdentifier(_fixture.PlanLockOwner)));
        Assert.Equal(fault == "none", await Valid(query));
        await transaction.RollbackAsync();

    }

    internal static string DeliveryStatusMutationSql(string fault, string alternateOwner)
    {
        const string table = "enrollment_execution.status_observations";
        return fault switch
        {
            "none" => "SELECT 1",
            "missing" => $"DROP TABLE {table} CASCADE",
            "owner" => $"ALTER TABLE {table} OWNER TO " + alternateOwner,
            "not-null" => $"ALTER TABLE {table} ALTER COLUMN sequence DROP NOT NULL",
            "default" => $"ALTER TABLE {table} ALTER COLUMN diagnostic SET DEFAULT 'None'",
            "collation" => $"ALTER TABLE {table} ALTER COLUMN diagnostic TYPE text COLLATE \"C\"",
            "extra-column" => $"ALTER TABLE {table} ADD COLUMN extra text",
            "check" => $"ALTER TABLE {table} DROP CONSTRAINT status_observation_shape",
            "foreign-action" => ReplaceForeignKey("ON DELETE CASCADE"),
            "foreign-deferred" => ReplaceForeignKey("ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED"),
            "foreign-unvalidated" => ReplaceForeignKey("ON DELETE RESTRICT NOT VALID"),
            "bare-unique" => ReplaceIndex("(operation_id,sequence)"),
            "extra-index" => $"CREATE INDEX status_extra_index ON {table}(sequence)",
            "included-index" => ReplaceIndex("(operation_id,sequence) INCLUDE(state)", attachConstraint: true),
            "partial-index" => ReplaceIndex("(operation_id,sequence) WHERE sequence>0"),
            "nulls-index" => ReplaceIndex("(operation_id,sequence) NULLS NOT DISTINCT", attachConstraint: true),
            "incoming-foreign-key" => $"CREATE TABLE enrollment_execution.status_incoming (id uuid REFERENCES {table}(observation_id))",
            "replica-identity" => $"ALTER TABLE {table} REPLICA IDENTITY FULL",
            "rls" => $"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY",
            "force-rls" => $"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY",
            "immutable-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER status_observations_immutable",
            "guard-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER status_observations_guard",
            "guard-always" => $"ALTER TABLE {table} ENABLE ALWAYS TRIGGER status_observations_guard",
            "guard-event" => ReplaceGuard("BEFORE INSERT OR UPDATE", ""),
            "guard-condition" => ReplaceGuard("BEFORE INSERT", "WHEN (NEW.sequence>0)"),
            "extra-trigger" => $"CREATE TRIGGER status_extra_guard BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION enrollment_execution.guard_status_observation()",
            "ri-disabled" => ChangeForeignTrigger("DISABLE"),
            "ri-always" => ChangeForeignTrigger("ENABLE ALWAYS"),
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        };

        static string ReplaceForeignKey(string suffix) => $"ALTER TABLE {table} DROP CONSTRAINT status_observations_operation_id_fkey; ALTER TABLE {table} ADD CONSTRAINT status_observations_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES enrollment_execution.issue_results(operation_id) {suffix}";
        static string ReplaceIndex(string suffix, bool attachConstraint = false) => $"ALTER TABLE {table} DROP CONSTRAINT status_observations_operation_id_sequence_key; CREATE UNIQUE INDEX status_observations_operation_id_sequence_key ON {table} {suffix}"
            + (attachConstraint ? $"; ALTER TABLE {table} ADD CONSTRAINT status_observations_operation_id_sequence_key UNIQUE USING INDEX status_observations_operation_id_sequence_key" : "");
        static string ReplaceGuard(string events, string condition) => $"DROP TRIGGER status_observations_guard ON {table}; CREATE TRIGGER status_observations_guard {events} ON {table} FOR EACH ROW {condition} EXECUTE FUNCTION enrollment_execution.guard_status_observation()";
        static string ChangeForeignTrigger(string action) => $$"""
            DO $ri_drift$ DECLARE target record; BEGIN
              SELECT trigger.tgname INTO STRICT target FROM pg_catalog.pg_trigger trigger
              JOIN pg_catalog.pg_constraint constraint_row ON constraint_row.oid=trigger.tgconstraint
              WHERE constraint_row.conrelid='enrollment_execution.status_observations'::regclass
                AND constraint_row.conname='status_observations_operation_id_fkey' AND trigger.tgtype=9;
              EXECUTE pg_catalog.format('ALTER TABLE enrollment_execution.issue_results {{action}} TRIGGER %I',target.tgname);
            END $ri_drift$;
            """;
    }
}

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task DeliveryGeneratedStatusStructureCatalogMatchesSource()
    {
        const string begin = "    -- BEGIN generated delivery status structure catalog";
        const string end = "    -- END generated delivery status structure catalog";
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-status.sql"));
        var query = source[source.IndexOf("WITH ", StringComparison.Ordinal)..].Trim().TrimEnd(';')
            .Replace(":'expected_table_owner_role'", "pg_catalog.pg_get_userbyid(table_owner)", StringComparison.Ordinal);
        var expected = begin + "\n    -- Source: audit-enrollment-delivery-status.sql\n    ok := ok AND (\n" + query + "\n    );\n" + end;
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        Assert.Equal(1, profile.Split(begin, StringSplitOptions.None).Length - 1);
        Assert.Equal(1, profile.Split(end, StringSplitOptions.None).Length - 1);
        var start = profile.IndexOf(begin, StringComparison.Ordinal);
        var finish = profile.IndexOf(end, StringComparison.Ordinal) + end.Length;
        Assert.Equal(expected.Replace("\r\n", "\n"), profile[start..finish].Replace("\r\n", "\n"));
    }

    private static string DeliveryStatusCatalogProbe()
    {
        var sql = "";
        foreach (var fault in EnrollmentGrantPlanTests.DeliveryStatusCatalogCases.Select(row => (string)row[0]).Where(fault => fault != "none"))
        {
            sql += "SAVEPOINT status_catalog_case;\n" + EnrollmentGrantPlanTests.DeliveryStatusMutationSql(fault, ":\"execution_runtime_role\"") + ";\n";
            foreach (var role in new[] { "status_runtime_role", "delivery_runtime_role" })
            {
                sql += $"SET LOCAL SESSION AUTHORIZATION :\"{role}\";\n";
                sql += $$"""
                    DO $composed_status_probe$
                    DECLARE row_count integer; rejected boolean;
                    BEGIN
                      SELECT count(*),bool_and(result.is_valid IS FALSE AND result.diagnostic_code='ProfileDrift' AND result.profile_version=4)
                        INTO row_count,rejected FROM enrollment_execution.audit_delivery_privileges(
                          current_setting('app.catalog_expected_environment_id')::uuid) result;
                      IF row_count<>1 OR rejected IS DISTINCT FROM true THEN
                        RAISE EXCEPTION 'Composed status catalog accepted: {{fault}}';
                      END IF;
                    END $composed_status_probe$;

                    """;
                sql += "RESET SESSION AUTHORIZATION;\n";
            }
            sql += "ROLLBACK TO SAVEPOINT status_catalog_case;\nRELEASE SAVEPOINT status_catalog_case;\n";
        }
        return sql;
    }
}
