using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    private static readonly string[] ResultRequiredColumns = ["outcome", "diagnostic", "recorded_at"];
    public static IEnumerable<object[]> DeliveryResultCatalogCases => new[]
    {
        "none", "missing", "owner", "default", "column-type", "collation", "extra-column", "outcome-check", "time-check",
        "shape-missing", "shape-identity-null", "shape-rejected-diagnostic", "shape-hash-null", "shape-rejected-data", "shape-duration", "shape-version", "shape-diagnostic",
        "foreign-action", "foreign-deferred", "foreign-unvalidated", "foreign-target", "bare-primary", "included-primary", "extra-index",
        "private-missing", "private-nonunique", "private-key", "private-order", "private-included", "private-predicate", "private-no-predicate", "private-null-distinct",
        "incoming-extra", "incoming-ack-missing", "incoming-status-missing", "incoming-ack-action", "incoming-status-action", "incoming-status-key",
        "replica-identity", "rls", "force-rls", "immutable-disabled", "immutable-event",
        "consistent-missing", "consistent-disabled", "consistent-ordinary", "consistent-immediate", "consistent-condition", "consistent-event",
        "stop-missing", "stop-disabled", "validator-swap", "ack-missing", "status-missing", "permit-missing",
        "validator-missing", "stop-validator-missing", "extra-local", "reserved-shadow",
        "ri-disabled", "ri-always", "ack-ri-disabled", "ack-ri-always", "status-ri-disabled", "status-ri-always"
    }.Concat(ResultRequiredColumns.Select(column => "null-" + column)).Select(fault => new object[] { fault });
    [Theory]
    [MemberData(nameof(DeliveryResultCatalogCases))]
    public async Task DeliveryResultCatalogRejectsStructuralDrift(string fault)
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
        var query = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-results.sql")))
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
        Assert.False(await Valid(query.Replace("current_user::text", "'result_catalog_missing_owner'", StringComparison.Ordinal)));
        await Execute(DeliveryResultMutationSql(fault, QuoteIdentifier(_fixture.PlanLockOwner)));
        Assert.Equal(fault == "none", await Valid(query));
        await transaction.RollbackAsync();
    }

    internal static string DeliveryResultMutationSql(string fault, string alternateOwner)
    {
        const string table = "enrollment_execution.issue_results";
        if (fault.StartsWith("null-", StringComparison.Ordinal) && ResultRequiredColumns.Contains(fault[5..]))
            return $"ALTER TABLE {table} ALTER COLUMN {fault[5..]} DROP NOT NULL";
        return fault switch
        {
            "none" => "SELECT 1",
            "missing" => $"DROP TABLE {table} CASCADE",
            "owner" => $"ALTER TABLE {table} OWNER TO {alternateOwner}",
            "default" => $"ALTER TABLE {table} ALTER COLUMN issue_contract_version SET DEFAULT 2",
            "column-type" => $"ALTER TABLE {table} ALTER COLUMN issue_contract_version TYPE integer",
            "collation" => $"ALTER TABLE {table} ALTER COLUMN diagnostic TYPE text COLLATE \"C\"",
            "extra-column" => $"ALTER TABLE {table} ADD COLUMN extra text",
            "outcome-check" => $"ALTER TABLE {table} DROP CONSTRAINT issue_results_outcome_check",
            "time-check" => $"ALTER TABLE {table} DROP CONSTRAINT issue_results_recorded_at_check",
            "shape-missing" => $"ALTER TABLE {table} DROP CONSTRAINT issue_result_closed_shape",
            "shape-identity-null" => ChangeShape("AND grant_id IS NOT NULL ", ""),
            "shape-rejected-diagnostic" => ChangeShape("'MintPermitExpired'::text", "'MintPermitExpired'::text, 'Unexpected'::text"),
            "shape-hash-null" => ChangeShape("AND token_sha256 IS NOT NULL ", ""),
            "shape-rejected-data" => ChangeShape("AND authorization_digest IS NULL", ""),
            "shape-duration" => ChangeShape("grant_expires_at = (grant_created_at + '00:10:00'::interval)", "grant_expires_at >= grant_created_at"),
            "shape-version" => ChangeShape("issue_contract_version = 2", "issue_contract_version >= 1"),
            "shape-diagnostic" => ChangeShape("diagnostic = 'None'::text", "diagnostic <> ''::text"),
            "foreign-action" => ReplaceForeignKey("ON DELETE CASCADE"),
            "foreign-deferred" => ReplaceForeignKey("ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED"),
            "foreign-unvalidated" => ReplaceForeignKey("ON DELETE RESTRICT NOT VALID"),
            "foreign-target" => $"ALTER TABLE {table} DROP CONSTRAINT issue_results_operation_id_fkey; ALTER TABLE {table} ADD CONSTRAINT issue_results_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES public.\"EnrollmentGrantOperations\"(\"Id\") ON DELETE RESTRICT",
            "bare-primary" => $"ALTER TABLE {table} DROP CONSTRAINT issue_results_pkey CASCADE; CREATE UNIQUE INDEX issue_results_pkey ON {table}(operation_id);" + Incoming("delivery_acks", "RESTRICT", false) + Incoming("status_observations", "RESTRICT", false),
            "included-primary" => $"ALTER TABLE {table} DROP CONSTRAINT issue_results_pkey CASCADE; ALTER TABLE {table} ADD CONSTRAINT issue_results_pkey PRIMARY KEY(operation_id) INCLUDE(outcome);" + Incoming("delivery_acks", "RESTRICT", false) + Incoming("status_observations", "RESTRICT", false),
            "extra-index" => $"CREATE INDEX result_extra_index ON {table}(diagnostic)",
            "private-missing" => "DROP INDEX enrollment_execution.issue_results_private_grant",
            "private-nonunique" => ReplacePrivate("", "(environment_id,grant_id) WHERE outcome='Issued'"),
            "private-key" => ReplacePrivate("UNIQUE", "(environment_id,operation_id) WHERE outcome='Issued'"),
            "private-order" => ReplacePrivate("UNIQUE", "(grant_id,environment_id) WHERE outcome='Issued'"),
            "private-included" => ReplacePrivate("UNIQUE", "(environment_id,grant_id) INCLUDE(outcome) WHERE outcome='Issued'"),
            "private-predicate" => ReplacePrivate("UNIQUE", "(environment_id,grant_id) WHERE outcome='Rejected'"),
            "private-no-predicate" => ReplacePrivate("UNIQUE", "(environment_id,grant_id)"),
            "private-null-distinct" => ReplacePrivate("UNIQUE", "(environment_id,grant_id) NULLS NOT DISTINCT WHERE outcome='Issued'"),
            "incoming-extra" => $"CREATE TABLE enrollment_execution.result_incoming(id uuid REFERENCES {table}(operation_id))",
            "incoming-ack-missing" => "ALTER TABLE enrollment_execution.delivery_acks DROP CONSTRAINT delivery_acks_operation_id_fkey",
            "incoming-status-missing" => "ALTER TABLE enrollment_execution.status_observations DROP CONSTRAINT status_observations_operation_id_fkey",
            "incoming-ack-action" => Incoming("delivery_acks", "CASCADE", true),
            "incoming-status-action" => Incoming("status_observations", "CASCADE", true),
            "incoming-status-key" => $"TRUNCATE TABLE enrollment_execution.status_observations; ALTER TABLE enrollment_execution.status_observations DROP CONSTRAINT status_observations_operation_id_fkey; ALTER TABLE enrollment_execution.status_observations ADD CONSTRAINT status_observations_operation_id_fkey FOREIGN KEY(observation_id) REFERENCES {table}(operation_id) ON DELETE RESTRICT",
            "replica-identity" => $"ALTER TABLE {table} REPLICA IDENTITY FULL",
            "rls" => $"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY",
            "force-rls" => $"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY",
            "immutable-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER issue_results_immutable",
            "immutable-event" => $"DROP TRIGGER issue_results_immutable ON {table}; CREATE TRIGGER issue_results_immutable BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation()",
            "consistent-missing" => $"DROP TRIGGER issue_results_consistent ON {table}",
            "consistent-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER issue_results_consistent",
            "consistent-ordinary" => ReplaceConsistent("", "", "INSERT", ""),
            "consistent-immediate" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY IMMEDIATE", "INSERT", ""),
            "consistent-condition" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY DEFERRED", "INSERT", "WHEN (NEW.outcome='Issued')"),
            "consistent-event" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY DEFERRED", "INSERT OR UPDATE", ""),
            "stop-missing" => $"DROP TRIGGER issue_results_stop_consistent ON {table}",
            "stop-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER issue_results_stop_consistent",
            "validator-swap" => $"DROP TRIGGER issue_results_consistent ON {table}; DROP TRIGGER issue_results_stop_consistent ON {table}; CREATE CONSTRAINT TRIGGER issue_results_consistent AFTER INSERT ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_execution_stop(); CREATE CONSTRAINT TRIGGER issue_results_stop_consistent AFTER INSERT ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_journal()",
            "ack-missing" => "ALTER TABLE enrollment_execution.delivery_acks RENAME TO renamed_delivery_acks",
            "status-missing" => "ALTER TABLE enrollment_execution.status_observations RENAME TO renamed_status_observations",
            "permit-missing" => "ALTER TABLE enrollment_execution.mint_permits RENAME TO renamed_mint_permits",
            "validator-missing" => "ALTER FUNCTION enrollment_execution.validate_journal() RENAME TO renamed_validate_journal",
            "stop-validator-missing" => "ALTER FUNCTION enrollment_execution.validate_execution_stop() RENAME TO renamed_validate_execution_stop",
            "extra-local" => $"CREATE TRIGGER result_extra BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation()",
            "reserved-shadow" => "CREATE TRIGGER issue_results_immutable BEFORE UPDATE ON enrollment_execution.delivery_acks FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation()",
            "ri-disabled" => ChangeForeignTrigger("issue_results", 5, "DISABLE"),
            "ri-always" => ChangeForeignTrigger("issue_results", 5, "ENABLE ALWAYS"),
            "ack-ri-disabled" => ChangeForeignTrigger("delivery_acks", 9, "DISABLE"),
            "ack-ri-always" => ChangeForeignTrigger("delivery_acks", 9, "ENABLE ALWAYS"),
            "status-ri-disabled" => ChangeForeignTrigger("status_observations", 9, "DISABLE"),
            "status-ri-always" => ChangeForeignTrigger("status_observations", 9, "ENABLE ALWAYS"),
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        };
        static string ChangeShape(string before, string after) => $$"""
            DO $result_shape_drift$ DECLARE definition text; changed text; BEGIN
              SELECT pg_catalog.pg_get_constraintdef(oid,true) INTO STRICT definition FROM pg_catalog.pg_constraint
                WHERE conrelid='enrollment_execution.issue_results'::regclass AND conname='issue_result_closed_shape';
              changed:=replace(definition,{{Quote(before)}},{{Quote(after)}});
              IF changed=definition THEN RAISE EXCEPTION 'Result shape mutation did not change the constraint'; END IF;
              ALTER TABLE enrollment_execution.issue_results DROP CONSTRAINT issue_result_closed_shape;
              EXECUTE 'ALTER TABLE enrollment_execution.issue_results ADD CONSTRAINT issue_result_closed_shape '||changed;
            END $result_shape_drift$;
            """;
        static string Quote(string text) => "'" + text.Replace("'", "''", StringComparison.Ordinal) + "'";
        static string ReplacePrivate(string unique, string suffix) => $"DROP INDEX enrollment_execution.issue_results_private_grant; CREATE {unique} INDEX issue_results_private_grant ON {table}{suffix}";
        static string Incoming(string peer, string action, bool drop) => (drop ? $"ALTER TABLE enrollment_execution.{peer} DROP CONSTRAINT {peer}_operation_id_fkey;" : "") + $"ALTER TABLE enrollment_execution.{peer} ADD CONSTRAINT {peer}_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES {table}(operation_id) ON DELETE {action};";
        static string ReplaceForeignKey(string suffix) => $"ALTER TABLE {table} DROP CONSTRAINT issue_results_operation_id_fkey; ALTER TABLE {table} ADD CONSTRAINT issue_results_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES enrollment_execution.mint_permits(operation_id) {suffix}";
        static string ReplaceConsistent(string kind, string timing, string events, string condition) =>
            $"DROP TRIGGER issue_results_consistent ON {table}; CREATE {kind} TRIGGER issue_results_consistent AFTER {events} ON {table} {timing} FOR EACH ROW {condition} EXECUTE FUNCTION enrollment_execution.validate_journal()";
        static string ChangeForeignTrigger(string peer, int type, string action) => $$"""
            DO $result_ri_drift$ DECLARE target record; BEGIN
              SELECT trigger.tgname INTO STRICT target FROM pg_catalog.pg_trigger trigger
              JOIN pg_catalog.pg_constraint constraint_row ON constraint_row.oid=trigger.tgconstraint
              WHERE constraint_row.conrelid='enrollment_execution.{{peer}}'::regclass
                AND constraint_row.conname='{{peer}}_operation_id_fkey' AND trigger.tgtype={{type}};
              EXECUTE pg_catalog.format('ALTER TABLE enrollment_execution.issue_results {{action}} TRIGGER %I',target.tgname);
            END $result_ri_drift$;
            """;
    }
}

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task DeliveryGeneratedResultStructureCatalogMatchesSource()
    {
        const string begin = "    -- BEGIN generated delivery result structure catalog";
        const string end = "    -- END generated delivery result structure catalog";
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-results.sql"));
        var query = source[source.IndexOf("WITH ", StringComparison.Ordinal)..].Trim().TrimEnd(';')
            .Replace(":'expected_table_owner_role'", "pg_catalog.pg_get_userbyid(table_owner)", StringComparison.Ordinal);
        var expected = begin + "\n    -- Source: audit-enrollment-delivery-results.sql\n    ok := ok AND (\n" + query + "\n    );\n" + end;
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        Assert.Equal(1, profile.Split(begin, StringSplitOptions.None).Length - 1);
        Assert.Equal(1, profile.Split(end, StringSplitOptions.None).Length - 1);
        var start = profile.IndexOf(begin, StringComparison.Ordinal);
        var finish = profile.IndexOf(end, StringComparison.Ordinal) + end.Length;
        Assert.Equal(expected.Replace("\r\n", "\n"), profile[start..finish].Replace("\r\n", "\n"));
    }

    private static string DeliveryResultCatalogProbe()
    {
        var sql = "";
        foreach (var fault in EnrollmentGrantPlanTests.DeliveryResultCatalogCases.Select(row => (string)row[0]).Where(fault => fault != "none"))
        {
            sql += "SAVEPOINT result_catalog_case;\n" + EnrollmentGrantPlanTests.DeliveryResultMutationSql(fault, ":\"execution_runtime_role\"") + ";\n";
            foreach (var role in new[] { "status_runtime_role", "delivery_runtime_role" })
            {
                sql += $"SET LOCAL SESSION AUTHORIZATION :\"{role}\";\n";
                sql += $$"""
                    DO $composed_result_probe$
                    DECLARE row_count integer; rejected boolean;
                    BEGIN
                      SELECT count(*),bool_and(result.is_valid IS FALSE AND result.diagnostic_code='ProfileDrift' AND result.profile_version=4)
                        INTO row_count,rejected FROM enrollment_execution.audit_delivery_privileges(
                          current_setting('app.catalog_expected_environment_id')::uuid) result;
                      IF row_count<>1 OR rejected IS DISTINCT FROM true THEN
                        RAISE EXCEPTION 'Composed result catalog accepted: {{fault}}';
                      END IF;
                    END $composed_result_probe$;

                    """;
                sql += "RESET SESSION AUTHORIZATION;\n";
            }
            sql += "ROLLBACK TO SAVEPOINT result_catalog_case;\nRELEASE SAVEPOINT result_catalog_case;\n";
        }
        return sql;
    }
}
