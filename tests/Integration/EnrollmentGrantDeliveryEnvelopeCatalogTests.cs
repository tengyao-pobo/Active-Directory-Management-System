using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    public static IEnumerable<object[]> DeliveryEnvelopeCatalogCases => new[]
    {
        "none", "missing", "owner", "not-null", "default", "column-type", "extra-column", "ciphertext-check",
        "foreign-action", "foreign-deferred", "foreign-unvalidated", "foreign-target", "bare-primary", "included-primary", "extra-index",
        "incoming-foreign-key", "replica-identity", "rls", "force-rls", "immutable-disabled", "immutable-delete",
        "consistent-missing", "consistent-ordinary", "consistent-immediate", "consistent-condition", "consistent-insert-only", "consistent-update", "consistent-disabled",
        "peer-missing", "validator-missing", "peer-disabled", "peer-renamed", "peer-extra", "ri-disabled", "ri-always"
    }.Select(fault => new object[] { fault });
    [Theory]
    [MemberData(nameof(DeliveryEnvelopeCatalogCases))]
    public async Task DeliveryEnvelopeCatalogRejectsStructuralDrift(string fault)
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
        var query = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-envelopes.sql")))
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
        Assert.False(await Valid(query.Replace("current_user::text", "'envelope_catalog_missing_owner'", StringComparison.Ordinal)));
        await Execute(DeliveryEnvelopeMutationSql(fault, QuoteIdentifier(_fixture.PlanLockOwner)));
        Assert.Equal(fault == "none", await Valid(query));
        await transaction.RollbackAsync();
    }

    internal static string DeliveryEnvelopeMutationSql(string fault, string alternateOwner)
    {
        const string table = "enrollment_execution.sealed_envelopes";
        return fault switch
        {
            "none" => "SELECT 1",
            "missing" => $"DROP TABLE {table} CASCADE",
            "owner" => $"ALTER TABLE {table} OWNER TO {alternateOwner}",
            "not-null" => $"ALTER TABLE {table} ALTER COLUMN ciphertext DROP NOT NULL",
            "default" => $"ALTER TABLE {table} ALTER COLUMN ciphertext SET DEFAULT decode(repeat('00',384),'hex')",
            "column-type" => $"CREATE DOMAIN enrollment_execution.envelope_bytes AS bytea; ALTER TABLE {table} ALTER COLUMN ciphertext TYPE enrollment_execution.envelope_bytes",
            "extra-column" => $"ALTER TABLE {table} ADD COLUMN extra text",
            "ciphertext-check" => $"ALTER TABLE {table} DROP CONSTRAINT sealed_envelopes_ciphertext_check; ALTER TABLE {table} ADD CONSTRAINT sealed_envelopes_ciphertext_check CHECK(octet_length(ciphertext)<=384)",
            "foreign-action" => ReplaceForeignKey("ON DELETE CASCADE"),
            "foreign-deferred" => ReplaceForeignKey("ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED"),
            "foreign-unvalidated" => ReplaceForeignKey("ON DELETE RESTRICT NOT VALID"),
            "foreign-target" => $"ALTER TABLE {table} DROP CONSTRAINT sealed_envelopes_operation_id_fkey; ALTER TABLE {table} ADD CONSTRAINT sealed_envelopes_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES public.\"EnrollmentGrantOperations\"(\"Id\") ON DELETE RESTRICT",
            "bare-primary" => $"ALTER TABLE {table} DROP CONSTRAINT sealed_envelopes_pkey; CREATE UNIQUE INDEX sealed_envelopes_pkey ON {table}(operation_id)",
            "included-primary" => $"ALTER TABLE {table} DROP CONSTRAINT sealed_envelopes_pkey; ALTER TABLE {table} ADD CONSTRAINT sealed_envelopes_pkey PRIMARY KEY(operation_id) INCLUDE(ciphertext)",
            "extra-index" => $"CREATE INDEX envelope_extra_index ON {table}(ciphertext)",
            "incoming-foreign-key" => $"CREATE TABLE enrollment_execution.envelope_incoming(id uuid REFERENCES {table}(operation_id))",
            "replica-identity" => $"ALTER TABLE {table} REPLICA IDENTITY FULL",
            "rls" => $"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY",
            "force-rls" => $"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY",
            "immutable-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER sealed_envelopes_immutable",
            "immutable-delete" => $"DROP TRIGGER sealed_envelopes_immutable ON {table}; CREATE TRIGGER sealed_envelopes_immutable BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation()",
            "consistent-missing" => $"DROP TRIGGER sealed_envelopes_consistent ON {table}",
            "consistent-ordinary" => ReplaceConsistent("", "", "INSERT OR DELETE", ""),
            "consistent-immediate" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY IMMEDIATE", "INSERT OR DELETE", ""),
            "consistent-condition" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY DEFERRED", "INSERT OR DELETE", "WHEN (current_user<>'unused_envelope_role')"),
            "consistent-insert-only" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY DEFERRED", "INSERT", ""),
            "consistent-update" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY DEFERRED", "INSERT OR UPDATE OR DELETE", ""),
            "consistent-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER sealed_envelopes_consistent",
            "peer-missing" => "ALTER TABLE enrollment_execution.mint_permits RENAME TO renamed_mint_permits",
            "validator-missing" => "ALTER FUNCTION enrollment_execution.validate_journal() RENAME TO renamed_validate_journal",
            "peer-disabled" => "ALTER TABLE enrollment_execution.delivery_acks DISABLE TRIGGER delivery_acks_consistent",
            "peer-renamed" => "ALTER TRIGGER issue_results_consistent ON enrollment_execution.issue_results RENAME TO renamed_journal_consistent",
            "peer-extra" => "CREATE CONSTRAINT TRIGGER extra_journal_consistent AFTER INSERT ON enrollment_execution.mint_permits DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_journal()",
            "ri-disabled" => ChangeForeignTrigger("DISABLE"),
            "ri-always" => ChangeForeignTrigger("ENABLE ALWAYS"),
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        };

        static string ReplaceForeignKey(string suffix) => $"ALTER TABLE {table} DROP CONSTRAINT sealed_envelopes_operation_id_fkey; ALTER TABLE {table} ADD CONSTRAINT sealed_envelopes_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES enrollment_execution.mint_permits(operation_id) {suffix}";
        static string ReplaceConsistent(string kind, string timing, string events, string condition) =>
            $"DROP TRIGGER sealed_envelopes_consistent ON {table}; CREATE {kind} TRIGGER sealed_envelopes_consistent AFTER {events} ON {table} {timing} FOR EACH ROW {condition} EXECUTE FUNCTION enrollment_execution.validate_journal()";
        static string ChangeForeignTrigger(string action) => $$"""
            DO $envelope_ri_drift$ DECLARE target record; BEGIN
              SELECT trigger.tgname INTO STRICT target FROM pg_catalog.pg_trigger trigger
              JOIN pg_catalog.pg_constraint constraint_row ON constraint_row.oid=trigger.tgconstraint
              WHERE constraint_row.conrelid='enrollment_execution.sealed_envelopes'::regclass
                AND constraint_row.conname='sealed_envelopes_operation_id_fkey' AND trigger.tgtype=9;
              EXECUTE pg_catalog.format('ALTER TABLE enrollment_execution.mint_permits {{action}} TRIGGER %I',target.tgname);
            END $envelope_ri_drift$;
            """;
    }
}

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task DeliveryGeneratedEnvelopeStructureCatalogMatchesSource()
    {
        const string begin = "    -- BEGIN generated delivery envelope structure catalog";
        const string end = "    -- END generated delivery envelope structure catalog";
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-envelopes.sql"));
        var query = source[source.IndexOf("WITH ", StringComparison.Ordinal)..].Trim().TrimEnd(';')
            .Replace(":'expected_table_owner_role'", "pg_catalog.pg_get_userbyid(table_owner)", StringComparison.Ordinal);
        var expected = begin + "\n    -- Source: audit-enrollment-delivery-envelopes.sql\n    ok := ok AND (\n" + query + "\n    );\n" + end;
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        Assert.Equal(1, profile.Split(begin, StringSplitOptions.None).Length - 1);
        Assert.Equal(1, profile.Split(end, StringSplitOptions.None).Length - 1);
        var start = profile.IndexOf(begin, StringComparison.Ordinal);
        var finish = profile.IndexOf(end, StringComparison.Ordinal) + end.Length;
        Assert.Equal(expected.Replace("\r\n", "\n"), profile[start..finish].Replace("\r\n", "\n"));
    }

    private static string DeliveryEnvelopeCatalogProbe()
    {
        var sql = "";
        foreach (var fault in EnrollmentGrantPlanTests.DeliveryEnvelopeCatalogCases.Select(row => (string)row[0]).Where(fault => fault != "none"))
        {
            sql += "SAVEPOINT envelope_catalog_case;\n" + EnrollmentGrantPlanTests.DeliveryEnvelopeMutationSql(fault, ":\"execution_runtime_role\"") + ";\n";
            foreach (var role in new[] { "status_runtime_role", "delivery_runtime_role" })
            {
                sql += $"SET LOCAL SESSION AUTHORIZATION :\"{role}\";\n";
                sql += $$"""
                    DO $composed_envelope_probe$
                    DECLARE row_count integer; rejected boolean;
                    BEGIN
                      SELECT count(*),bool_and(result.is_valid IS FALSE AND result.diagnostic_code='ProfileDrift' AND result.profile_version=4)
                        INTO row_count,rejected FROM enrollment_execution.audit_delivery_privileges(
                          current_setting('app.catalog_expected_environment_id')::uuid) result;
                      IF row_count<>1 OR rejected IS DISTINCT FROM true THEN
                        RAISE EXCEPTION 'Composed envelope catalog accepted: {{fault}}';
                      END IF;
                    END $composed_envelope_probe$;

                    """;
                sql += "RESET SESSION AUTHORIZATION;\n";
            }
            sql += "ROLLBACK TO SAVEPOINT envelope_catalog_case;\nRELEASE SAVEPOINT envelope_catalog_case;\n";
        }
        return sql;
    }
}
