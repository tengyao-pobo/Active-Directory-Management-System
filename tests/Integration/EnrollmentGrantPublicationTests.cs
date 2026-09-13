using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static async Task VerifyPublicationCandidateAsync(NpgsqlConnection owner, NpgsqlConnection admin, string executionConnection,
        Guid environment, CancellationToken cancellationToken)
    {
        await using (var authority = await admin.BeginTransactionAsync(cancellationToken))
        {
            await using var identity = new NpgsqlCommand("SELECT CURRENT_USER::text", owner);
            var ownerName = (string)(await identity.ExecuteScalarAsync(cancellationToken))!;
            await using var assume = new NpgsqlCommand("SET LOCAL ROLE " + new NpgsqlCommandBuilder().QuoteIdentifier(ownerName), admin);
            await assume.ExecuteNonQueryAsync(cancellationToken);
            var adaptation = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-profile4-membership.sql"), cancellationToken);
            await using var forbidden = new NpgsqlCommand(adaptation, admin);
            var rejected = await Assert.ThrowsAsync<PostgresException>(async () => { await forbidden.ExecuteNonQueryAsync(cancellationToken); });
            Assert.Equal("55000", rejected.SqlState);
            Assert.Equal("Membership adaptation requires the restricted final owner.", rejected.MessageText);
            await authority.RollbackAsync(cancellationToken);
        }
        async Task Execute(NpgsqlConnection connection, string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection) { CommandTimeout = 3 };
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        var metadata = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-publication-metadata.sql"), cancellationToken);
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-publication.sql"), cancellationToken);
        async Task Valid(bool expected)
        {
            foreach (var sql in new[] { metadata, catalog })
            {
                await using var command = new NpgsqlCommand(sql.Replace(":'expected_table_owner_role'", "CURRENT_USER", StringComparison.Ordinal), owner);
                Assert.Equal(expected, await command.ExecuteScalarAsync(cancellationToken));
            }
        }
        await Valid(true);
        foreach (var mutation in new[] {
            "ALTER FUNCTION enrollment_execution.guard_profile4_publication() RENAME TO missing_publication_guard",
            "ALTER FUNCTION enrollment_execution.guard_profile4_publication() SECURITY INVOKER",
            "ALTER FUNCTION enrollment_execution.guard_profile4_publication() STABLE",
            "ALTER FUNCTION enrollment_execution.guard_profile4_publication() RESET ALL",
            "ALTER FUNCTION enrollment_execution.guard_profile4_publication() STRICT",
            "GRANT EXECUTE ON FUNCTION enrollment_execution.guard_profile4_publication() TO PUBLIC",
            "CREATE FUNCTION enrollment_execution.guard_profile4_publication(integer) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
            "CREATE OR REPLACE FUNCTION enrollment_execution.guard_profile4_publication() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $f$ BEGIN RETURN NEW; END $f$",
            "ALTER TABLE public.\"EnrollmentGrantOperations\" DISABLE TRIGGER enrollment_grant_operation_00_publication",
            "ALTER TABLE public.\"EnrollmentGrantOperations\" ENABLE TRIGGER enrollment_grant_operation_00_publication",
            "ALTER TRIGGER enrollment_grant_operation_00_publication ON public.\"EnrollmentGrantOperations\" RENAME TO changed_publication_guard",
            "DROP TRIGGER enrollment_grant_operation_00_publication ON public.\"EnrollmentGrantOperations\"",
            "DROP TRIGGER enrollment_grant_operation_00_publication ON public.\"EnrollmentGrantOperations\"; CREATE TRIGGER enrollment_grant_operation_00_publication BEFORE INSERT ON public.\"EnrollmentGrantOperations\" FOR EACH ROW WHEN (NEW.\"EnvironmentId\" IS NOT NULL) EXECUTE FUNCTION enrollment_execution.guard_profile4_publication()",
            "DROP TRIGGER enrollment_grant_operation_00_publication ON public.\"EnrollmentGrantOperations\"; CREATE TRIGGER enrollment_grant_operation_00_publication BEFORE INSERT OR UPDATE ON public.\"EnrollmentGrantOperations\" FOR EACH ROW EXECUTE FUNCTION enrollment_execution.guard_profile4_publication()",
            "CREATE TRIGGER extra_publication_guard BEFORE INSERT ON public.\"EnrollmentGrantOperations\" FOR EACH ROW EXECUTE FUNCTION enrollment_execution.guard_profile4_publication()",
            "ALTER FUNCTION enrollment_execution.audit_execution_privileges(uuid) RENAME TO missing_runtime_audit"
        })
        {
            await using var transaction = await owner.BeginTransactionAsync(cancellationToken);
            await Execute(owner, mutation);
            await Valid(false);
            await transaction.RollbackAsync(cancellationToken);
            await Valid(true);
        }
        await using var apiLookup = new NpgsqlCommand("SELECT \"LoginRole\" FROM public.\"DirectoryDatabaseBindings\" WHERE \"Purpose\"='Api'", owner);
        var apiName = (string)(await apiLookup.ExecuteScalarAsync(cancellationToken))!;
        var apiInfo = new NpgsqlConnectionStringBuilder(executionConnection) { Username = apiName, Pooling = false };
        await using var api = new NpgsqlConnection(apiInfo.ConnectionString);
        await api.OpenAsync(cancellationToken);
        await using (var privilege = new NpgsqlCommand("SELECT CURRENT_USER=SESSION_USER AND pg_catalog.has_table_privilege('public.\"EnrollmentGrantOperations\"','INSERT')", api))
            Assert.Equal(true, await privilege.ExecuteScalarAsync(cancellationToken));
        async Task InsertRejected(string state, string message, bool replica = false, bool resetOrigin = false)
        {
            await using var transaction = await api.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
            if (replica) await Execute(api, "SET LOCAL session_replication_role=replica");
            if (resetOrigin) await Execute(api, "SET LOCAL session_replication_role=origin");
            await using var insert = new NpgsqlCommand("INSERT INTO public.\"EnrollmentGrantOperations\"(\"EnvironmentId\") VALUES(@environment)", api) { CommandTimeout = 3 };
            insert.Parameters.AddWithValue("environment", environment);
            var failure = await Assert.ThrowsAsync<PostgresException>(async () => { await insert.ExecuteNonQueryAsync(cancellationToken); });
            Assert.Equal(state, failure.SqlState);
            Assert.Equal(message, failure.MessageText);
            await transaction.RollbackAsync(cancellationToken);
        }
        // The owner snapshot suite leaves a committed Pending generation. These real
        // API INSERTs must reach the publication barrier, not fail from missing grants.
        await InsertRejected("55000", "Enrollment grant publication is unavailable.");
        await using (var closing = await owner.BeginTransactionAsync(cancellationToken))
        {
            await Execute(owner, "SELECT pg_catalog.pg_advisory_xact_lock(1162235478,1)");
            await InsertRejected("55000", "Enrollment grant publication is unavailable.");
            await closing.RollbackAsync(cancellationToken);
        }
        var runtimeSource = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-profile4-runtime-audit.sql"), cancellationToken);
        try
        {
            // Commit the sentinel so the separate physical API LOGIN can actually see it.
            await Execute(owner, "CREATE OR REPLACE FUNCTION enrollment_execution.audit_execution_privileges(p_environment uuid) RETURNS TABLE(is_valid boolean,diagnostic_code text,profile_version smallint) LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $f$ BEGIN RAISE EXCEPTION 'Unpinned runtime must never execute'; END $f$");
            await Valid(false);
            await InsertRejected("55000", "Enrollment grant publication is unavailable.");
        }
        finally
        {
            await using var restore = new NpgsqlCommand(runtimeSource, owner) { CommandTimeout = 10 };
            await restore.ExecuteNonQueryAsync(CancellationToken.None);
        }
        await Valid(true);
        // Only a guard pass-through proof: this intentionally incomplete row must still
        // be rejected by the unchanged queued-plan parent anchor. It is not a valid enqueue.
        await Execute(owner, "UPDATE enrollment_execution.profile4_readiness SET state='Ready',ready_at=statement_timestamp(),ready_by=session_user");
        var quotedApi = new NpgsqlCommandBuilder().QuoteIdentifier(apiName);
        try
        {
            await Execute(admin, $"GRANT SET ON PARAMETER session_replication_role TO {quotedApi}");
            await Valid(false);
            await InsertRejected("55000", "Enrollment grant publication is unavailable.", replica: true);
            await InsertRejected("55000", "Enrollment grant publication is unavailable.", replica: true, resetOrigin: true);
            await InsertRejected("55000", "Enrollment grant publication is unavailable.");
        }
        finally
        {
            await using var revoke = new NpgsqlCommand($"REVOKE SET ON PARAMETER session_replication_role FROM {quotedApi}", admin) { CommandTimeout = 10 };
            await revoke.ExecuteNonQueryAsync(CancellationToken.None);
        }
        await Valid(true);
        await InsertRejected("23514", "Enrollment grant operation requires a queued plan.");
        await VerifyPublicationRejectsUnboundLoginAsync(owner, admin, executionConnection, environment, cancellationToken);
        await VerifyPublicationCommitBoundaryAsync(owner, admin, api, environment, cancellationToken);
        await VerifyProfile4ApiFunctionRootsAsync(owner, api, cancellationToken);
        await VerifyProfile4ApiPoliciesAsync(owner, api, cancellationToken);
        await VerifyProfile4ApiCapabilitiesAsync(owner, admin, api, environment, cancellationToken);
        await VerifyProfile4ApiRelationsAsync(owner, admin, api, cancellationToken);
        await VerifyProfile4ApiTriggersAsync(owner, admin, api, cancellationToken);
    }
}
