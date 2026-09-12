using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    public static IEnumerable<object[]> DeliveryAckCatalogCases => new[]
    {
        "none", "missing", "owner", "requester-null", "cipher-null", "token-null", "time-null", "default", "column-type", "extra-column",
        "requester-check", "cipher-check", "token-check", "time-check", "foreign-action", "foreign-deferred", "foreign-unvalidated", "foreign-target",
        "bare-primary", "included-primary", "extra-index", "incoming-foreign-key", "replica-identity", "rls", "force-rls",
        "immutable-disabled", "immutable-update-only", "immutable-delete-only", "consistent-missing", "consistent-disabled",
        "consistent-ordinary", "consistent-immediate", "consistent-condition", "consistent-event", "stop-missing", "stop-disabled", "validator-swap",
        "peer-missing", "validator-missing", "stop-validator-missing", "extra-local", "reserved-shadow", "ri-disabled", "ri-always"
    }.Select(fault => new object[] { fault });
    [Theory]
    [MemberData(nameof(DeliveryAckCatalogCases))]
    public async Task DeliveryAckCatalogRejectsStructuralDrift(string fault)
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
        var query = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-acks.sql")))
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
        Assert.False(await Valid(query.Replace("current_user::text", "'ack_catalog_missing_owner'", StringComparison.Ordinal)));
        await Execute(DeliveryAckMutationSql(fault, QuoteIdentifier(_fixture.PlanLockOwner)));
        Assert.Equal(fault == "none", await Valid(query));
        await transaction.RollbackAsync();
    }

    internal static string DeliveryAckMutationSql(string fault, string alternateOwner)
    {
        const string table = "enrollment_execution.delivery_acks";
        return fault switch
        {
            "none" => "SELECT 1",
            "missing" => $"DROP TABLE {table} CASCADE",
            "owner" => $"ALTER TABLE {table} OWNER TO {alternateOwner}",
            "requester-null" => $"ALTER TABLE {table} ALTER COLUMN requester_id DROP NOT NULL",
            "cipher-null" => $"ALTER TABLE {table} ALTER COLUMN ciphertext_sha256 DROP NOT NULL",
            "token-null" => $"ALTER TABLE {table} ALTER COLUMN token_sha256 DROP NOT NULL",
            "time-null" => $"ALTER TABLE {table} ALTER COLUMN acknowledged_at DROP NOT NULL",
            "default" => $"ALTER TABLE {table} ALTER COLUMN acknowledged_at SET DEFAULT now()",
            "column-type" => $"CREATE DOMAIN enrollment_execution.ack_bytes AS bytea; ALTER TABLE {table} ALTER COLUMN token_sha256 TYPE enrollment_execution.ack_bytes",
            "extra-column" => $"ALTER TABLE {table} ADD COLUMN extra text",
            "requester-check" => $"ALTER TABLE {table} DROP CONSTRAINT delivery_acks_requester_id_check",
            "cipher-check" => $"ALTER TABLE {table} DROP CONSTRAINT delivery_acks_ciphertext_sha256_check",
            "token-check" => $"ALTER TABLE {table} DROP CONSTRAINT delivery_acks_token_sha256_check",
            "time-check" => $"ALTER TABLE {table} DROP CONSTRAINT delivery_acks_acknowledged_at_check",
            "foreign-action" => ReplaceForeignKey("ON DELETE CASCADE"),
            "foreign-deferred" => ReplaceForeignKey("ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED"),
            "foreign-unvalidated" => ReplaceForeignKey("ON DELETE RESTRICT NOT VALID"),
            "foreign-target" => $"ALTER TABLE {table} DROP CONSTRAINT delivery_acks_operation_id_fkey; ALTER TABLE {table} ADD CONSTRAINT delivery_acks_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES enrollment_execution.mint_permits(operation_id) ON DELETE RESTRICT",
            "bare-primary" => $"ALTER TABLE {table} DROP CONSTRAINT delivery_acks_pkey; CREATE UNIQUE INDEX delivery_acks_pkey ON {table}(operation_id)",
            "included-primary" => $"ALTER TABLE {table} DROP CONSTRAINT delivery_acks_pkey; ALTER TABLE {table} ADD CONSTRAINT delivery_acks_pkey PRIMARY KEY(operation_id) INCLUDE(requester_id)",
            "extra-index" => $"CREATE INDEX ack_extra_index ON {table}(requester_id)",
            "incoming-foreign-key" => $"CREATE TABLE enrollment_execution.ack_incoming(id uuid REFERENCES {table}(operation_id))",
            "replica-identity" => $"ALTER TABLE {table} REPLICA IDENTITY FULL",
            "rls" => $"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY",
            "force-rls" => $"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY",
            "immutable-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER delivery_acks_immutable",
            "immutable-update-only" => ReplaceImmutable("UPDATE"),
            "immutable-delete-only" => ReplaceImmutable("DELETE"),
            "consistent-missing" => $"DROP TRIGGER delivery_acks_consistent ON {table}",
            "consistent-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER delivery_acks_consistent",
            "consistent-ordinary" => ReplaceConsistent("", "", "INSERT", ""),
            "consistent-immediate" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY IMMEDIATE", "INSERT", ""),
            "consistent-condition" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY DEFERRED", "INSERT", "WHEN (current_user<>'unused_ack_role')"),
            "consistent-event" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY DEFERRED", "INSERT OR UPDATE", ""),
            "stop-missing" => $"DROP TRIGGER delivery_acks_stop_consistent ON {table}",
            "stop-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER delivery_acks_stop_consistent",
            "validator-swap" => $"DROP TRIGGER delivery_acks_consistent ON {table}; DROP TRIGGER delivery_acks_stop_consistent ON {table}; CREATE CONSTRAINT TRIGGER delivery_acks_consistent AFTER INSERT ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_execution_stop(); CREATE CONSTRAINT TRIGGER delivery_acks_stop_consistent AFTER INSERT ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_journal()",
            "peer-missing" => "ALTER TABLE enrollment_execution.issue_results RENAME TO renamed_issue_results",
            "validator-missing" => "ALTER FUNCTION enrollment_execution.validate_journal() RENAME TO renamed_validate_journal",
            "stop-validator-missing" => "ALTER FUNCTION enrollment_execution.validate_execution_stop() RENAME TO renamed_validate_execution_stop",
            "extra-local" => $"CREATE TRIGGER ack_extra BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation()",
            "reserved-shadow" => "CREATE TRIGGER delivery_acks_immutable BEFORE UPDATE ON enrollment_execution.mint_permits FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation()",
            "ri-disabled" => ChangeForeignTrigger("DISABLE"),
            "ri-always" => ChangeForeignTrigger("ENABLE ALWAYS"),
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        };

        static string ReplaceImmutable(string events) => $"DROP TRIGGER delivery_acks_immutable ON {table}; CREATE TRIGGER delivery_acks_immutable BEFORE {events} ON {table} FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation()";
        static string ReplaceForeignKey(string suffix) => $"ALTER TABLE {table} DROP CONSTRAINT delivery_acks_operation_id_fkey; ALTER TABLE {table} ADD CONSTRAINT delivery_acks_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES enrollment_execution.issue_results(operation_id) {suffix}";
        static string ReplaceConsistent(string kind, string timing, string events, string condition) =>
            $"DROP TRIGGER delivery_acks_consistent ON {table}; CREATE {kind} TRIGGER delivery_acks_consistent AFTER {events} ON {table} {timing} FOR EACH ROW {condition} EXECUTE FUNCTION enrollment_execution.validate_journal()";
        static string ChangeForeignTrigger(string action) => $$"""
            DO $ack_ri_drift$ DECLARE target record; BEGIN
              SELECT trigger.tgname INTO STRICT target FROM pg_catalog.pg_trigger trigger
              JOIN pg_catalog.pg_constraint constraint_row ON constraint_row.oid=trigger.tgconstraint
              WHERE constraint_row.conrelid='enrollment_execution.delivery_acks'::regclass
                AND constraint_row.conname='delivery_acks_operation_id_fkey' AND trigger.tgtype=9;
              EXECUTE pg_catalog.format('ALTER TABLE enrollment_execution.issue_results {{action}} TRIGGER %I',target.tgname);
            END $ack_ri_drift$;
            """;
    }
}

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task DeliveryGeneratedAckStructureCatalogMatchesSource()
    {
        const string begin = "    -- BEGIN generated delivery ack structure catalog";
        const string end = "    -- END generated delivery ack structure catalog";
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-acks.sql"));
        var query = source[source.IndexOf("WITH ", StringComparison.Ordinal)..].Trim().TrimEnd(';')
            .Replace(":'expected_table_owner_role'", "pg_catalog.pg_get_userbyid(table_owner)", StringComparison.Ordinal);
        var expected = begin + "\n    -- Source: audit-enrollment-delivery-acks.sql\n    ok := ok AND (\n" + query + "\n    );\n" + end;
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        Assert.Equal(1, profile.Split(begin, StringSplitOptions.None).Length - 1);
        Assert.Equal(1, profile.Split(end, StringSplitOptions.None).Length - 1);
        var start = profile.IndexOf(begin, StringComparison.Ordinal);
        var finish = profile.IndexOf(end, StringComparison.Ordinal) + end.Length;
        Assert.Equal(expected.Replace("\r\n", "\n"), profile[start..finish].Replace("\r\n", "\n"));
    }

    private static string DeliveryAckCatalogProbe()
    {
        var sql = "";
        foreach (var fault in EnrollmentGrantPlanTests.DeliveryAckCatalogCases.Select(row => (string)row[0]).Where(fault => fault != "none"))
        {
            sql += "SAVEPOINT ack_catalog_case;\n" + EnrollmentGrantPlanTests.DeliveryAckMutationSql(fault, ":\"execution_runtime_role\"") + ";\n";
            foreach (var role in new[] { "status_runtime_role", "delivery_runtime_role" })
            {
                sql += $"SET LOCAL SESSION AUTHORIZATION :\"{role}\";\n";
                sql += $$"""
                    DO $composed_ack_probe$
                    DECLARE row_count integer; rejected boolean;
                    BEGIN
                      SELECT count(*),bool_and(result.is_valid IS FALSE AND result.diagnostic_code='ProfileDrift' AND result.profile_version=4)
                        INTO row_count,rejected FROM enrollment_execution.audit_delivery_privileges(
                          current_setting('app.catalog_expected_environment_id')::uuid) result;
                      IF row_count<>1 OR rejected IS DISTINCT FROM true THEN
                        RAISE EXCEPTION 'Composed ack catalog accepted: {{fault}}';
                      END IF;
                    END $composed_ack_probe$;

                    """;
                sql += "RESET SESSION AUTHORIZATION;\n";
            }
            sql += "ROLLBACK TO SAVEPOINT ack_catalog_case;\nRELEASE SAVEPOINT ack_catalog_case;\n";
        }
        return sql;
    }
}
