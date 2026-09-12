using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    private static readonly SemaphoreSlim ExecutionProvisionLock = new(1, 1);
    private const string ExecutionDefinerRole = "console_execution_definer";

    private sealed record ExecutionRuntimeProfile(NpgsqlDataSource DataSource, string RuntimeRole, string DefinerRole, string QueueDefinerRole)
        : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => DataSource.DisposeAsync();
    }

    private async Task<ExecutionRuntimeProfile> ProvisionExecutionRuntime(Guid environmentId)
    {
        await ExecutionProvisionLock.WaitAsync();
        try
        {
            var ownerConnection = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
            var definerRole = Environment.GetEnvironmentVariable("CONSOLE_TEST_EXECUTION_DEFINER");
            if (string.IsNullOrWhiteSpace(definerRole)) definerRole = ExecutionDefinerRole;
            if (!System.Text.RegularExpressions.Regex.IsMatch(definerRole, "^[a-z_][a-z0-9_]{0,62}$"))
                throw new InvalidOperationException("Invalid execution definer test role.");
            var queueDefinerRole = Environment.GetEnvironmentVariable("CONSOLE_TEST_QUEUE_DEFINER");
            if (string.IsNullOrWhiteSpace(queueDefinerRole)) queueDefinerRole = "console_execution_queue_definer";
            if (!System.Text.RegularExpressions.Regex.IsMatch(queueDefinerRole, "^[a-z_][a-z0-9_]{0,62}$"))
                throw new InvalidOperationException("Invalid execution queue definer test role.");
            var runtimeRole = $"console_execution_{Guid.NewGuid():N}";
            var password = Convert.ToHexString(Guid.NewGuid().ToByteArray());
            await using (var db = Db())
            {
                var roleSql = $"""
                    DO $role$ BEGIN
                      IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='{definerRole.Replace("'", "''", StringComparison.Ordinal)}') THEN
                        CREATE ROLE "{definerRole.Replace("\"", "\"\"", StringComparison.Ordinal)}" NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
                      END IF;
                      IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='{queueDefinerRole.Replace("'", "''", StringComparison.Ordinal)}') THEN
                        CREATE ROLE "{queueDefinerRole.Replace("\"", "\"\"", StringComparison.Ordinal)}" NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
                      END IF;
                    END $role$;
                    CREATE ROLE "{runtimeRole}" LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
                    """;
                await db.Database.ExecuteSqlRawAsync(roleSql);
            }

            var scriptDirectory = AppContext.BaseDirectory;
            var psql = Environment.GetEnvironmentVariable("CONSOLE_TEST_PSQL");
            if (string.IsNullOrWhiteSpace(psql)) psql = "psql";
            var process = new ProcessStartInfo(psql)
            {
                WorkingDirectory = scriptDirectory,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            process.Environment["PGPASSWORD"] = ownerConnection.Password;
            foreach (var argument in new[]
            {
                "-h", ownerConnection.Host!, "-p", ownerConnection.Port.ToString(), "-U", ownerConnection.Username!,
                "-d", ownerConnection.Database!, "-v", "ON_ERROR_STOP=1", "-v", $"execution_runtime_role={runtimeRole}",
                "-v", $"execution_definer_role={definerRole}", "-v", $"expected_table_owner_role={ownerConnection.Username}",
                "-v", $"execution_queue_definer_role={queueDefinerRole}",
                "-v", $"expected_environment_id={environmentId}", "-v", $"DBNAME={ownerConnection.Database}",
                "-f", "provision-enrollment-execution.sql"
            }) process.ArgumentList.Add(argument);
            using var child = Process.Start(process) ?? throw new InvalidOperationException("Unable to start psql.");
            var standardOutput = child.StandardOutput.ReadToEndAsync();
            var standardError = child.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try { await child.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException)
            {
                child.Kill(entireProcessTree: true);
                await child.WaitForExitAsync();
                throw new TimeoutException("Enrollment execution provisioning timed out.");
            }
            if (child.ExitCode != 0)
                throw new InvalidOperationException($"Enrollment execution provisioning failed ({child.ExitCode}): {await standardError}");
            _ = await standardOutput;

            var runtimeConnection = new NpgsqlConnectionStringBuilder(ownerConnection.ConnectionString)
            {
                Username = runtimeRole,
                Password = password,
                Pooling = false
            };
            return new ExecutionRuntimeProfile(NpgsqlDataSource.Create(runtimeConnection.ConnectionString), runtimeRole, definerRole, queueDefinerRole);
        }
        finally { ExecutionProvisionLock.Release(); }
    }

    [Fact]
    public async Task ExecutionProfileProvisionsThroughRealPsqlAndPassesBothAudits()
    {
        var seed = await _fixture.SeedAsync();
        await using var profile = await ProvisionExecutionRuntime(seed.Environment.Id);
        await using var connection = await profile.DataSource.OpenConnectionAsync();
        await using var internalAudit = new NpgsqlCommand(
            "SELECT is_valid,diagnostic_code,profile_version FROM enrollment_execution.audit_execution_privileges(@environment)", connection);
        internalAudit.Parameters.AddWithValue("environment", seed.Environment.Id);
        await using var reader = await internalAudit.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.True(reader.GetBoolean(0));
        Assert.Equal("None", reader.GetString(1));
        Assert.Equal((short)3, reader.GetInt16(2));
        Assert.False(await reader.ReadAsync());
        await reader.DisposeAsync();

        var query = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-execution.sql"));
        query = query.Replace(":'execution_runtime_role'", "@runtime", StringComparison.Ordinal)
            .Replace(":'execution_definer_role'", "@definer", StringComparison.Ordinal)
            .Replace(":'expected_table_owner_role'", "@owner", StringComparison.Ordinal)
            .Replace(":'expected_environment_id'", "@environment", StringComparison.Ordinal);
        await using var external = new NpgsqlCommand(query, connection);
        external.Parameters.AddWithValue("runtime", profile.RuntimeRole);
        external.Parameters.AddWithValue("definer", profile.DefinerRole);
        external.Parameters.AddWithValue("owner", new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Username!);
        external.Parameters.AddWithValue("environment", seed.Environment.Id);
        Assert.True((bool)(await external.ExecuteScalarAsync())!);

        await using var missing = new NpgsqlCommand(
            "SELECT contract_version,outcome FROM enrollment_execution.read_execution_record(@environment,@operation)", connection);
        missing.Parameters.AddWithValue("environment", seed.Environment.Id);
        missing.Parameters.AddWithValue("operation", Guid.NewGuid());
        await using var missingReader = await missing.ExecuteReaderAsync();
        Assert.True(await missingReader.ReadAsync());
        Assert.Equal((short)1, missingReader.GetInt16(0));
        Assert.Equal("NotFound", missingReader.GetString(1));
        Assert.False(await missingReader.ReadAsync());
    }

    [Fact]
    public async Task ExecutionRuntimeHasNoDirectTableOrOwnerHelperAccess()
    {
        var seed = await _fixture.SeedAsync();
        await using var profile = await ProvisionExecutionRuntime(seed.Environment.Id);
        await using var connection = await profile.DataSource.OpenConnectionAsync();
        foreach (var sql in new[]
        {
            "SELECT * FROM public.\"EnrollmentGrantOperations\"",
            "SELECT * FROM enrollment_execution.mint_permits",
            "SELECT * FROM enrollment_execution.lock_plan_context(@environment,@operation)",
            "SELECT enrollment_execution.execution_store_profile()",
            "SELECT enrollment_execution.worker_scope(@environment)"
        })
        {
            await using var command = new NpgsqlCommand(sql, connection);
            command.Parameters.AddWithValue("environment", seed.Environment.Id);
            command.Parameters.AddWithValue("operation", Guid.NewGuid());
            var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteReaderAsync());
            Assert.Equal("42501", error.SqlState);
        }
    }

    [Fact]
    public async Task ExecutionRuntimeCannotUseWrapperForAnotherEnvironment()
    {
        var seed = await _fixture.SeedAsync();
        await using var profile = await ProvisionExecutionRuntime(seed.Environment.Id);
        await using var connection = await profile.DataSource.OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            "SELECT * FROM enrollment_execution.read_execution_record(@environment,@operation)", connection);
        command.Parameters.AddWithValue("environment", seed.OtherEnvironment.Id);
        command.Parameters.AddWithValue("operation", Guid.NewGuid());
        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteReaderAsync());
        Assert.Equal("42501", error.SqlState);
    }

    [Fact]
    public async Task DirectRuntimeGrantMakesInternalAuditFailClosed()
    {
        var seed = await _fixture.SeedAsync();
        await using var profile = await ProvisionExecutionRuntime(seed.Environment.Id);
        await using var db = Db();
        await using var transaction = await db.Database.BeginTransactionAsync();
        await using (var drift = db.Database.GetDbConnection().CreateCommand())
        {
            drift.Transaction = transaction.GetDbTransaction();
            drift.CommandText = $"GRANT SELECT ON public.\"Plans\" TO \"{profile.RuntimeRole.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
            await drift.ExecuteNonQueryAsync();
        }
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = transaction.GetDbTransaction();
        command.CommandText = "SELECT is_valid FROM enrollment_execution.audit_execution_privileges(@environment)";
        command.Parameters.Add(new NpgsqlParameter("environment", seed.Environment.Id));
        Assert.False((bool)(await command.ExecuteScalarAsync())!);
    }

    [Theory]
    [InlineData("GRANT SELECT ON public.\"Plans\" TO PUBLIC")]
    [InlineData("GRANT UPDATE(\"Reason\") ON public.\"Plans\" TO PUBLIC")]
    [InlineData("GRANT EXECUTE ON FUNCTION enrollment_execution.execution_store_profile() TO PUBLIC")]
    [InlineData("DROP POLICY enrollment_execution_worker_reservations_limit ON public.\"EnrollmentGrantRecipientReservations\"")]
    [InlineData("CREATE FUNCTION enrollment_execution.execution_profile_drift() RETURNS integer LANGUAGE sql AS 'SELECT 1'; ALTER FUNCTION enrollment_execution.execution_profile_drift() OWNER TO \"{runtime}\"")]
    [InlineData("CREATE FUNCTION enrollment_execution.execution_profile_drift() RETURNS integer LANGUAGE sql AS 'SELECT 1'; ALTER FUNCTION enrollment_execution.execution_profile_drift() OWNER TO \"{definer}\"")]
    public async Task EffectivePublicPrivilegesAndFunctionOwnershipDriftFailClosed(string driftSql)
    {
        var seed = await _fixture.SeedAsync();
        await using var profile = await ProvisionExecutionRuntime(seed.Environment.Id);
        await using var db = Db();
        await using var transaction = await db.Database.BeginTransactionAsync();
        driftSql = driftSql.Replace("{runtime}", profile.RuntimeRole.Replace("\"", "\"\"", StringComparison.Ordinal), StringComparison.Ordinal)
            .Replace("{definer}", profile.DefinerRole.Replace("\"", "\"\"", StringComparison.Ordinal), StringComparison.Ordinal);
        await db.Database.ExecuteSqlRawAsync(driftSql);
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = transaction.GetDbTransaction();
        command.CommandText = "SELECT is_valid FROM enrollment_execution.audit_execution_privileges(@environment)";
        command.Parameters.Add(new NpgsqlParameter("environment", seed.Environment.Id));
        Assert.False((bool)(await command.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task PrivateCapabilityFootprintAddedAfterProvisionFailsAuditAndWrapper()
    {
        var seed = await _fixture.SeedAsync();
        await using var profile = await ProvisionExecutionRuntime(seed.Environment.Id);
        await using var db = Db();
        var registryExists = (bool)(await db.Database.SqlQueryRaw<bool>(
            "SELECT pg_catalog.to_regclass('agent_private.agent_capability_roles') IS NOT NULL AS \"Value\"").SingleAsync());
        Assert.False(registryExists);

        await using var transaction = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlRawAsync("""
            CREATE SCHEMA agent_private AUTHORIZATION CURRENT_USER;
            CREATE TABLE agent_private.agent_capability_roles(
              role_name name PRIMARY KEY,
              capability text NOT NULL CHECK(capability IN('Ingest','Enrollment','Projection','PlatformGrant','EnrollmentTargetRead')),
              role_kind text NOT NULL CHECK(role_kind IN('Runtime','Definer')));
            ALTER TABLE agent_private.agent_capability_roles ENABLE ROW LEVEL SECURITY;
            ALTER TABLE agent_private.agent_capability_roles FORCE ROW LEVEL SECURITY;
            CREATE POLICY definer_all ON agent_private.agent_capability_roles TO CURRENT_USER USING(true) WITH CHECK(true);
            REVOKE ALL ON agent_private.agent_capability_roles FROM PUBLIC;
            CREATE FUNCTION agent_private.agent_capability_isolation_profile() RETURNS smallint
              LANGUAGE sql SECURITY INVOKER
              SET search_path=pg_catalog,agent_private,pg_temp AS 'SELECT 2::smallint';
            REVOKE ALL ON FUNCTION agent_private.agent_capability_isolation_profile() FROM PUBLIC;
            """);
        Assert.False(await AuditExecutionAsync(db, transaction.GetDbTransaction(), seed.Environment.Id));
        await using var wrapper = db.Database.GetDbConnection().CreateCommand();
        wrapper.Transaction = transaction.GetDbTransaction();
        wrapper.CommandText = $"""
            SET LOCAL SESSION AUTHORIZATION "{profile.RuntimeRole.Replace("\"", "\"\"", StringComparison.Ordinal)}";
            SELECT * FROM enrollment_execution.read_execution_record(@environment,@operation)
            """;
        wrapper.Parameters.Add(new NpgsqlParameter("environment", seed.Environment.Id));
        wrapper.Parameters.Add(new NpgsqlParameter("operation", Guid.NewGuid()));
        var error = await Assert.ThrowsAsync<PostgresException>(() => wrapper.ExecuteReaderAsync());
        Assert.Equal("42501", error.SqlState);
    }

    [Fact]
    public async Task PartialPrivateCapabilityFootprintsFailClosedBeforeAccess()
    {
        var seed = await _fixture.SeedAsync();
        await using var profile = await ProvisionExecutionRuntime(seed.Environment.Id);
        await using var db = Db();
        await using var transaction = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlRawAsync("CREATE SCHEMA agent_private AUTHORIZATION CURRENT_USER; CREATE TABLE agent_private.agent_capability_roles(role_name name PRIMARY KEY,capability text NOT NULL,role_kind text NOT NULL)");
        Assert.False(await AuditExecutionAsync(db, transaction.GetDbTransaction(), seed.Environment.Id));
        await transaction.RollbackAsync();
        await transaction.DisposeAsync();

        await using var second = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlRawAsync("""
            CREATE SCHEMA agent_private AUTHORIZATION CURRENT_USER;
            CREATE FUNCTION agent_private.agent_capability_isolation_profile(integer) RETURNS smallint
              LANGUAGE sql SECURITY INVOKER
              SET search_path=pg_catalog,agent_private,pg_temp AS 'SELECT 2::smallint';
            REVOKE ALL ON FUNCTION agent_private.agent_capability_isolation_profile(integer) FROM PUBLIC;
            """);
        Assert.False(await AuditExecutionAsync(db, second.GetDbTransaction(), seed.Environment.Id));
    }

    private static async Task<bool> AuditExecutionAsync(DbContext db, System.Data.Common.DbTransaction transaction, Guid environmentId)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT is_valid FROM enrollment_execution.audit_execution_privileges(@environment)";
        command.Parameters.Add(new NpgsqlParameter("environment", environmentId));
        return (bool)(await command.ExecuteScalarAsync())!;
    }

    private static async Task ExecuteSqlAsync(DbContext db, System.Data.Common.DbTransaction transaction, string sql)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }
}
