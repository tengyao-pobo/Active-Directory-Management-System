using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static async Task VerifyReadinessStructureAsync(NpgsqlConnection owner, CancellationToken cancellationToken)
    {
        var source = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-readiness-structure.sql"), cancellationToken))
            .Replace(":'expected_table_owner_role'", "@owner", StringComparison.Ordinal);
        async Task Audit(bool expected, string context = "baseline")
        {
            await using var command = new NpgsqlCommand(source, owner);
            command.Parameters.AddWithValue("owner", new NpgsqlConnectionStringBuilder(owner.ConnectionString).Username!);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            Assert.True(await reader.ReadAsync(cancellationToken));
            Assert.True(expected == reader.GetBoolean(0), context);
            Assert.False(await reader.ReadAsync(cancellationToken));
        }
        await Audit(true);
        const string table = "enrollment_execution.profile4_readiness";
        var mutations = new List<string> {
            $"ALTER TABLE {table} RENAME TO readiness_missing",
            $"ALTER TABLE {table} SET UNLOGGED",
            $"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
            $"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
            $"CREATE POLICY unexpected ON {table} USING(true)",
            $"ALTER TABLE {table} ADD COLUMN unexpected text",
            $"ALTER TABLE {table} ADD COLUMN discarded text; ALTER TABLE {table} DROP COLUMN discarded",
            $"ALTER TABLE {table} ALTER COLUMN ready_by SET DEFAULT 'unexpected'",
            $"ALTER TABLE {table} ALTER COLUMN state DROP NOT NULL",
            $"ALTER TABLE {table} DROP CONSTRAINT profile4_readiness_shape; ALTER TABLE {table} ADD CONSTRAINT profile4_readiness_shape CHECK (true)",
            $"ALTER TABLE {table} DROP CONSTRAINT profile4_readiness_ready_at_check; ALTER TABLE {table} ADD CONSTRAINT profile4_readiness_ready_at_check CHECK(isfinite(ready_at)) NO INHERIT",
            $"CREATE INDEX unexpected ON {table}(generation)",
            $"ALTER TABLE {table} DROP CONSTRAINT profile4_readiness_pkey; ALTER TABLE {table} ADD PRIMARY KEY(singleton) INCLUDE(generation)",
            $"ALTER TABLE {table} DROP CONSTRAINT profile4_readiness_pkey; ALTER TABLE {table} ADD PRIMARY KEY(singleton) DEFERRABLE",
            $"ALTER TABLE {table} DISABLE TRIGGER profile4_readiness_transition",
            $"DROP TRIGGER profile4_readiness_transition ON {table}",
            $"CREATE TRIGGER unexpected BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION enrollment_execution.guard_profile4_readiness()",
            $"DROP TRIGGER profile4_readiness_transition ON {table}; CREATE TRIGGER profile4_readiness_transition BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION enrollment_execution.guard_profile4_readiness()",
            $"GRANT SELECT ON {table} TO PUBLIC",
            $"GRANT SELECT(state) ON {table} TO PUBLIC",
            "ALTER FUNCTION enrollment_execution.guard_profile4_readiness() RENAME TO guard_readiness_missing"
        };
        foreach (var suffix in new[] { "singleton_check", "profile_version_check", "generation_check", "installation_nonce_check",
            "attestation_manifest_sha256_check", "state_check", "pending_at_check", "ready_at_check", "shape" })
            mutations.Add($"ALTER TABLE {table} DROP CONSTRAINT profile4_readiness_{suffix}");
        foreach (var mutation in mutations)
        {
            await using var transaction = await owner.BeginTransactionAsync(cancellationToken);
            await using var command = new NpgsqlCommand(mutation, owner);
            await command.ExecuteNonQueryAsync(cancellationToken);
            await Audit(false, mutation);
            await transaction.RollbackAsync(cancellationToken);
            await Audit(true);
        }
    }
}
