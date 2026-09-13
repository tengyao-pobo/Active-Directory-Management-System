using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    private static readonly string[] PermitRequiredColumns = ["format_version", "issued_at", "not_after", "token_sha256", "recipient_fingerprint", "ciphertext_sha256", "authorization_digest"];
    private static readonly string[] PermitValueChecks = ["mint_permits_format_version_check", "mint_permit_time", "mint_permits_token_sha256_check", "mint_permits_recipient_fingerprint_check", "mint_permits_ciphertext_sha256_check", "mint_permits_authorization_digest_check"];
    public static IEnumerable<object[]> DeliveryPermitCatalogCases => new[]
    {
        "none", "missing", "owner", "default", "column-type", "extra-column",
        "foreign-action", "foreign-deferred", "foreign-unvalidated", "foreign-target",
        "bare-primary", "included-primary", "extra-index", "unique-missing", "unique-bare", "unique-key", "unique-included", "unique-null-distinct",
        "incoming-extra", "incoming-envelope-missing", "incoming-result-missing", "incoming-envelope-action", "incoming-result-action",
        "replica-identity", "rls", "force-rls", "immutable-disabled", "immutable-event", "boundary-disabled", "boundary-event",
        "consistent-missing", "consistent-disabled", "consistent-ordinary", "consistent-immediate", "consistent-condition", "consistent-event",
        "stop-missing", "stop-disabled", "validator-swap", "envelope-missing", "result-missing", "operation-missing",
        "validator-missing", "stop-validator-missing", "boundary-missing", "extra-local", "reserved-shadow",
        "ri-disabled", "ri-always", "envelope-ri-disabled", "envelope-ri-always", "result-ri-disabled", "result-ri-always"
    }.Concat(PermitRequiredColumns.Select(column => "null-" + column)).Concat(PermitValueChecks.Select(name => "check-" + name))
        .Select(fault => new object[] { fault });
    [Theory]
    [MemberData(nameof(DeliveryPermitCatalogCases))]
    public async Task DeliveryPermitCatalogRejectsStructuralDrift(string fault)
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
        var query = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-permits.sql")))
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
        Assert.False(await Valid(query.Replace("current_user::text", "'permit_catalog_missing_owner'", StringComparison.Ordinal)));
        await Execute(DeliveryPermitMutationSql(fault, QuoteIdentifier(_fixture.PlanLockOwner)));
        Assert.Equal(fault == "none", await Valid(query));
        await transaction.RollbackAsync();
    }

    internal static string DeliveryPermitMutationSql(string fault, string alternateOwner)
    {
        const string table = "enrollment_execution.mint_permits";
        if (fault.StartsWith("null-", StringComparison.Ordinal) && PermitRequiredColumns.Contains(fault[5..]))
            return $"ALTER TABLE {table} ALTER COLUMN {fault[5..]} DROP NOT NULL";
        if (fault.StartsWith("check-", StringComparison.Ordinal) && PermitValueChecks.Contains(fault[6..]))
            return $"ALTER TABLE {table} DROP CONSTRAINT {fault[6..]}";
        return fault switch
        {
            "none" => "SELECT 1",
            "missing" => $"DROP TABLE {table} CASCADE",
            "owner" => $"ALTER TABLE {table} OWNER TO {alternateOwner}",
            "default" => $"ALTER TABLE {table} ALTER COLUMN format_version SET DEFAULT 1",
            "column-type" => $"ALTER TABLE {table} ALTER COLUMN format_version TYPE integer",
            "extra-column" => $"ALTER TABLE {table} ADD COLUMN extra text",
            "foreign-action" => ReplaceForeignKey("ON DELETE CASCADE"),
            "foreign-deferred" => ReplaceForeignKey("ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED"),
            "foreign-unvalidated" => ReplaceForeignKey("ON DELETE RESTRICT NOT VALID"),
            "foreign-target" => $"CREATE TABLE enrollment_execution.permit_fake_parent(operation_id uuid PRIMARY KEY); INSERT INTO enrollment_execution.permit_fake_parent SELECT \"Id\" FROM public.\"EnrollmentGrantOperations\"; ALTER TABLE {table} DROP CONSTRAINT mint_permits_operation_id_fkey; ALTER TABLE {table} ADD CONSTRAINT mint_permits_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES enrollment_execution.permit_fake_parent(operation_id) ON DELETE RESTRICT",
            "bare-primary" => $"ALTER TABLE {table} DROP CONSTRAINT mint_permits_pkey CASCADE; CREATE UNIQUE INDEX mint_permits_pkey ON {table}(operation_id);" + Incoming("sealed_envelopes", "RESTRICT", false) + Incoming("issue_results", "RESTRICT", false),
            "included-primary" => $"ALTER TABLE {table} DROP CONSTRAINT mint_permits_pkey CASCADE; ALTER TABLE {table} ADD CONSTRAINT mint_permits_pkey PRIMARY KEY(operation_id) INCLUDE(token_sha256);" + Incoming("sealed_envelopes", "RESTRICT", false) + Incoming("issue_results", "RESTRICT", false),
            "extra-index" => $"CREATE INDEX permit_extra_index ON {table}(format_version)",
            "unique-missing" => $"ALTER TABLE {table} DROP CONSTRAINT mint_permits_token_sha256_key",
            "unique-bare" => $"ALTER TABLE {table} DROP CONSTRAINT mint_permits_token_sha256_key; CREATE UNIQUE INDEX mint_permits_token_sha256_key ON {table}(token_sha256)",
            "unique-key" => ReplaceUnique("UNIQUE(operation_id)"),
            "unique-included" => ReplaceUnique("UNIQUE(token_sha256) INCLUDE(format_version)"),
            "unique-null-distinct" => ReplaceUnique("UNIQUE NULLS NOT DISTINCT(token_sha256)"),
            "incoming-extra" => $"CREATE TABLE enrollment_execution.permit_incoming(id uuid REFERENCES {table}(operation_id))",
            "incoming-envelope-missing" => "ALTER TABLE enrollment_execution.sealed_envelopes DROP CONSTRAINT sealed_envelopes_operation_id_fkey",
            "incoming-result-missing" => "ALTER TABLE enrollment_execution.issue_results DROP CONSTRAINT issue_results_operation_id_fkey",
            "incoming-envelope-action" => Incoming("sealed_envelopes", "CASCADE", true),
            "incoming-result-action" => Incoming("issue_results", "CASCADE", true),
            "replica-identity" => $"ALTER TABLE {table} REPLICA IDENTITY FULL",
            "rls" => $"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY",
            "force-rls" => $"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY",
            "immutable-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER mint_permits_immutable",
            "immutable-event" => $"DROP TRIGGER mint_permits_immutable ON {table}; CREATE TRIGGER mint_permits_immutable BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation()",
            "boundary-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER mint_permits_stop_boundary",
            "boundary-event" => $"DROP TRIGGER mint_permits_stop_boundary ON {table}; CREATE TRIGGER mint_permits_stop_boundary AFTER INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION enrollment_execution.lock_execution_stop_boundary()",
            "consistent-missing" => $"DROP TRIGGER mint_permits_consistent ON {table}",
            "consistent-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER mint_permits_consistent",
            "consistent-ordinary" => ReplaceConsistent("", "", "INSERT", ""),
            "consistent-immediate" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY IMMEDIATE", "INSERT", ""),
            "consistent-condition" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY DEFERRED", "INSERT", "WHEN (NEW.format_version=1)"),
            "consistent-event" => ReplaceConsistent("CONSTRAINT", "DEFERRABLE INITIALLY DEFERRED", "INSERT OR UPDATE", ""),
            "stop-missing" => $"DROP TRIGGER mint_permits_stop_consistent ON {table}",
            "stop-disabled" => $"ALTER TABLE {table} DISABLE TRIGGER mint_permits_stop_consistent",
            "validator-swap" => $"DROP TRIGGER mint_permits_consistent ON {table}; DROP TRIGGER mint_permits_stop_consistent ON {table}; CREATE CONSTRAINT TRIGGER mint_permits_consistent AFTER INSERT ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_execution_stop(); CREATE CONSTRAINT TRIGGER mint_permits_stop_consistent AFTER INSERT ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_journal()",
            "envelope-missing" => "ALTER TABLE enrollment_execution.sealed_envelopes RENAME TO renamed_sealed_envelopes",
            "result-missing" => "ALTER TABLE enrollment_execution.issue_results RENAME TO renamed_issue_results",
            "operation-missing" => "ALTER TABLE public.\"EnrollmentGrantOperations\" RENAME TO renamed_grant_operations",
            "validator-missing" => "ALTER FUNCTION enrollment_execution.validate_journal() RENAME TO renamed_validate_journal",
            "stop-validator-missing" => "ALTER FUNCTION enrollment_execution.validate_execution_stop() RENAME TO renamed_validate_execution_stop",
            "boundary-missing" => "ALTER FUNCTION enrollment_execution.lock_execution_stop_boundary() RENAME TO renamed_stop_boundary",
            "extra-local" => $"CREATE TRIGGER permit_extra BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation()",
            "reserved-shadow" => "CREATE TRIGGER mint_permits_immutable BEFORE UPDATE ON enrollment_execution.delivery_acks FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation()",
            "ri-disabled" => ChangeForeignTrigger("mint_permits", 5, "DISABLE"),
            "ri-always" => ChangeForeignTrigger("mint_permits", 5, "ENABLE ALWAYS"),
            "envelope-ri-disabled" => ChangeForeignTrigger("sealed_envelopes", 9, "DISABLE"),
            "envelope-ri-always" => ChangeForeignTrigger("sealed_envelopes", 9, "ENABLE ALWAYS"),
            "result-ri-disabled" => ChangeForeignTrigger("issue_results", 9, "DISABLE"),
            "result-ri-always" => ChangeForeignTrigger("issue_results", 9, "ENABLE ALWAYS"),
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        };
        static string ReplaceUnique(string definition) => $"ALTER TABLE {table} DROP CONSTRAINT mint_permits_token_sha256_key; ALTER TABLE {table} ADD CONSTRAINT mint_permits_token_sha256_key {definition}";
        static string Incoming(string peer, string action, bool drop) => (drop ? $"ALTER TABLE enrollment_execution.{peer} DROP CONSTRAINT {peer}_operation_id_fkey;" : "") + $"ALTER TABLE enrollment_execution.{peer} ADD CONSTRAINT {peer}_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES {table}(operation_id) ON DELETE {action};";
        static string ReplaceForeignKey(string suffix) => $"ALTER TABLE {table} DROP CONSTRAINT mint_permits_operation_id_fkey; ALTER TABLE {table} ADD CONSTRAINT mint_permits_operation_id_fkey FOREIGN KEY(operation_id) REFERENCES public.\"EnrollmentGrantOperations\"(\"Id\") {suffix}";
        static string ReplaceConsistent(string kind, string timing, string events, string condition) =>
            $"DROP TRIGGER mint_permits_consistent ON {table}; CREATE {kind} TRIGGER mint_permits_consistent AFTER {events} ON {table} {timing} FOR EACH ROW {condition} EXECUTE FUNCTION enrollment_execution.validate_journal()";
        static string ChangeForeignTrigger(string peer, int type, string action) => $$"""
            DO $permit_ri_drift$ DECLARE target record; BEGIN
              SELECT trigger.tgname INTO STRICT target FROM pg_catalog.pg_trigger trigger
              JOIN pg_catalog.pg_constraint constraint_row ON constraint_row.oid=trigger.tgconstraint
              WHERE constraint_row.conrelid='enrollment_execution.{{peer}}'::regclass
                AND constraint_row.conname='{{peer}}_operation_id_fkey' AND trigger.tgtype={{type}};
              EXECUTE pg_catalog.format('ALTER TABLE enrollment_execution.mint_permits {{action}} TRIGGER %I',target.tgname);
            END $permit_ri_drift$;
            """;
    }
}

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task DeliveryGeneratedPermitStructureCatalogMatchesSource()
    {
        const string begin = "    -- BEGIN generated delivery permit structure catalog";
        const string end = "    -- END generated delivery permit structure catalog";
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-permits.sql"));
        var query = source[source.IndexOf("WITH ", StringComparison.Ordinal)..].Trim().TrimEnd(';')
            .Replace(":'expected_table_owner_role'", "pg_catalog.pg_get_userbyid(table_owner)", StringComparison.Ordinal);
        var expected = begin + "\n    -- Source: audit-enrollment-delivery-permits.sql\n    ok := ok AND (\n" + query + "\n    );\n" + end;
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        Assert.Equal(1, profile.Split(begin, StringSplitOptions.None).Length - 1);
        Assert.Equal(1, profile.Split(end, StringSplitOptions.None).Length - 1);
        var start = profile.IndexOf(begin, StringComparison.Ordinal);
        var finish = profile.IndexOf(end, StringComparison.Ordinal) + end.Length;
        Assert.Equal(expected.Replace("\r\n", "\n"), profile[start..finish].Replace("\r\n", "\n"));
    }

    private static string DeliveryPermitCatalogProbe()
    {
        var sql = "";
        foreach (var fault in EnrollmentGrantPlanTests.DeliveryPermitCatalogCases.Select(row => (string)row[0]).Where(fault => fault != "none"))
        {
            sql += "SAVEPOINT permit_catalog_case;\n" + EnrollmentGrantPlanTests.DeliveryPermitMutationSql(fault, ":\"execution_runtime_role\"") + ";\n";
            foreach (var role in new[] { "status_runtime_role", "delivery_runtime_role" })
            {
                sql += $"SET LOCAL SESSION AUTHORIZATION :\"{role}\";\n";
                sql += $$"""
                    DO $composed_permit_probe$
                    DECLARE row_count integer; rejected boolean;
                    BEGIN
                      SELECT count(*),bool_and(result.is_valid IS FALSE AND result.diagnostic_code='ProfileDrift' AND result.profile_version=4)
                        INTO row_count,rejected FROM enrollment_execution.audit_delivery_privileges(
                          current_setting('app.catalog_expected_environment_id')::uuid) result;
                      IF row_count<>1 OR rejected IS DISTINCT FROM true THEN
                        RAISE EXCEPTION 'Composed permit catalog accepted: {{fault}}';
                      END IF;
                    END $composed_permit_probe$;

                    """;
                sql += "RESET SESSION AUTHORIZATION;\n";
            }
            sql += "ROLLBACK TO SAVEPOINT permit_catalog_case;\nRELEASE SAVEPOINT permit_catalog_case;\n";
        }
        return sql;
    }
}
