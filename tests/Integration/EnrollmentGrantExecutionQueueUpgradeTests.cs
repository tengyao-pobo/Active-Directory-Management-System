using System.Diagnostics;
using ItManagement.Core;
using ItManagement.EnrollmentGrantExecution;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task V2UpgradePreservesBindingsRejectsUnsafeOwnerAndDoesNotAllowOldInstallerRollback(bool useCanonicalCollation)
    {
        var owner = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        Assert.Contains(owner.Host, new[] { "localhost", "127.0.0.1", "::1" });
        Assert.StartsWith("console_", owner.Database);
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var database = "console_queue_upgrade_" + suffix;
        var api = "cqu_api_" + suffix;
        var locker = "cqu_lock_" + suffix;
        var executor = "cqu_exec_" + suffix;
        var queueOwner = "cqu_queue_" + suffix;
        var worker = "cqu_worker_" + suffix;
        var unsafeOwner = "cqu_login_" + suffix;
        var password = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24));
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var admin = new NpgsqlConnectionStringBuilder(owner.ConnectionString) { Database = "postgres", Pooling = false };
        await using var cleanup = new QueueUpgradeCleanup(admin.ConnectionString, database);
        await using (var connection = new NpgsqlConnection(admin.ConnectionString))
        {
            await connection.OpenAsync(deadline.Token);
            var createSql = $"CREATE DATABASE {database}" + (useCanonicalCollation ? " TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'" : "");
            await using var create = new NpgsqlCommand(createSql, connection);
            await create.ExecuteNonQueryAsync(deadline.Token);
            cleanup.DatabaseCreated = true;
        }
        owner.Database = database;
        owner.Pooling = false;
        await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(owner.ConnectionString).Options);
        await db.Database.MigrateAsync(deadline.Token);
        // DDL identifiers and the password are generated exclusively from fixed prefixes and hexadecimal bytes.
        foreach (var (name, login) in new[] { (api, true), (worker, true), (unsafeOwner, true), (locker, false), (executor, false), (queueOwner, false) })
        {
            var authentication = login ? "LOGIN PASSWORD '" + password + "'" : "NOLOGIN";
            var roleSql = $"CREATE ROLE {name} {authentication} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION";
            await db.Database.ExecuteSqlRawAsync(roleSql, deadline.Token);
            cleanup.CreatedRoles.Add(name);
        }
        var environment = new ManagedEnvironment { Id = Guid.NewGuid(), Name = "Synthetic upgrade", CanonicalDns = "upgrade.example.test", DefaultLocale = "en-US", Version = 1 };
        db.Environments.Add(environment);
        await db.SaveChangesAsync(deadline.Token);
        var variables = new Dictionary<string, string>
        {
            ["runtime_role"] = api, ["enrollment_plan_lock_owner_role"] = locker,
            ["execution_runtime_role"] = worker, ["execution_definer_role"] = executor,
            ["execution_queue_definer_role"] = queueOwner, ["expected_table_owner_role"] = owner.Username!,
            ["expected_environment_id"] = environment.Id.ToString(), ["DBNAME"] = database
        };
        await RequireScript("provision-runtime.sql");
        await RequireScript("enrollment-execution/v2/provision-enrollment-execution.sql");
        Assert.Equal((short)2, await ReadVersion());
        var bindingsBefore = await db.Database.SqlQueryRaw<string>("""
            SELECT row_to_json(binding)::text AS "Value" FROM public."DirectoryDatabaseBindings" binding
            WHERE "Purpose"='EnrollmentGrantExecution'
            """).SingleAsync(deadline.Token);
        var reservationsBefore = await db.Database.SqlQueryRaw<string>("""
            SELECT row_to_json(reservation)::text AS "Value" FROM enrollment_execution.role_reservations reservation ORDER BY role_name
            """).ToArrayAsync(deadline.Token);

        variables["execution_queue_definer_role"] = unsafeOwner;
        var rejected = await RunScript(owner, "upgrade-enrollment-execution-v2-to-v3.sql", variables, deadline.Token);
        Assert.NotEqual(0, rejected.ExitCode);
        Assert.Contains("preflight failed", rejected.Error, StringComparison.Ordinal);
        Assert.Equal((short)2, await ReadVersion());
        Assert.False(await db.Database.SqlQueryRaw<bool>("""
            SELECT pg_catalog.to_regprocedure('enrollment_execution.claim_next(uuid,uuid)') IS NOT NULL AS "Value"
            """).SingleAsync(deadline.Token));

        variables["execution_queue_definer_role"] = queueOwner;
        await RequireScript("upgrade-enrollment-execution-v2-to-v3.sql");
        Assert.Equal((short)3, await ReadVersion());
        Assert.Equal(bindingsBefore, await db.Database.SqlQueryRaw<string>("""
            SELECT row_to_json(binding)::text AS "Value" FROM public."DirectoryDatabaseBindings" binding
            WHERE "Purpose"='EnrollmentGrantExecution'
            """).SingleAsync(deadline.Token));
        Assert.Equal(reservationsBefore, await db.Database.SqlQueryRaw<string>("""
            SELECT row_to_json(reservation)::text AS "Value" FROM enrollment_execution.role_reservations reservation
            WHERE role_kind<>'QueueDefiner' ORDER BY role_name
            """).ToArrayAsync(deadline.Token));
        var runtime = new NpgsqlConnectionStringBuilder(owner.ConnectionString) { Username = worker, Password = password };
        await using var source = NpgsqlDataSource.Create(runtime.ConnectionString);
        var queue = await PostgresEnrollmentGrantWorkQueue.CreateAuditedAsync(source, environment.Id,
            owner.Username!, executor, queueOwner, deadline.Token);
        Assert.Equal(EnrollmentWorkClaimOutcome.NoWork, (await queue.ClaimNextAsync(Guid.NewGuid(), deadline.Token)).Outcome);

        foreach (var privilege in new[] { "SELECT ON public.\"Plans\"", "SELECT(\"RequesterId\") ON public.\"EnrollmentGrantOperations\"" })
        {
            var grantSql = "GRANT " + privilege + " TO " + queueOwner + " WITH GRANT OPTION";
            await db.Database.ExecuteSqlRawAsync(grantSql, deadline.Token);
            var driftedInstaller = await RunScript(owner, "provision-enrollment-execution.sql", variables, deadline.Token);
            Assert.NotEqual(0, driftedInstaller.ExitCode);
            Assert.Equal(bindingsBefore, await db.Database.SqlQueryRaw<string>("""
                SELECT row_to_json(binding)::text AS "Value" FROM public."DirectoryDatabaseBindings" binding
                WHERE "Purpose"='EnrollmentGrantExecution'
                """).SingleAsync(deadline.Token));
            var revokeSql = "REVOKE " + privilege + " FROM " + queueOwner;
            await db.Database.ExecuteSqlRawAsync(revokeSql, deadline.Token);
            Assert.Equal(EnrollmentWorkClaimOutcome.NoWork, (await queue.ClaimNextAsync(Guid.NewGuid(), deadline.Token)).Outcome);
        }

        var oldInstaller = await RunScript(owner, "enrollment-execution/v2/provision-enrollment-execution.sql", variables, deadline.Token);
        Assert.NotEqual(0, oldInstaller.ExitCode);
        Assert.Equal((short)3, await ReadVersion());
        Assert.Equal(EnrollmentWorkClaimOutcome.NoWork, (await queue.ClaimNextAsync(Guid.NewGuid(), deadline.Token)).Outcome);

        async Task<short> ReadVersion() => await db.Database.SqlQueryRaw<short>(
            "SELECT enrollment_execution.execution_store_profile() AS \"Value\"").SingleAsync(deadline.Token);
        async Task RequireScript(string path)
        {
            var result = await RunScript(owner, path, variables, deadline.Token);
            Assert.True(result.ExitCode == 0, result.Error);
        }
    }

    private static async Task<(int ExitCode, string Error)> RunScript(NpgsqlConnectionStringBuilder owner, string path,
        Dictionary<string, string> variables, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("CONSOLE_TEST_PSQL") ?? "psql")
        { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = AppContext.BaseDirectory };
        start.Environment["PGPASSWORD"] = owner.Password;
        foreach (var argument in new[] { "-X", "-h", owner.Host!, "-p", owner.Port.ToString(), "-U", owner.Username!, "-d", owner.Database!, "-v", "ON_ERROR_STOP=1" })
            start.ArgumentList.Add(argument);
        foreach (var (key, value) in variables) { start.ArgumentList.Add("-v"); start.ArgumentList.Add(key + "=" + value); }
        start.ArgumentList.Add("-f"); start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, path));
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start psql.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync(cancellationToken); }
        catch
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None);
            await Task.WhenAll(output, error);
            throw;
        }
        await output;
        return (process.ExitCode, await error);
    }

    private sealed class QueueUpgradeCleanup(string adminConnection, string database) : IAsyncDisposable
    {
        public bool DatabaseCreated { get; set; }
        public List<string> CreatedRoles { get; } = [];

        public async ValueTask DisposeAsync()
        {
            if (!DatabaseCreated && CreatedRoles.Count == 0) return;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await using var connection = new NpgsqlConnection(adminConnection);
            await connection.OpenAsync(deadline.Token);
            using var identifiers = new NpgsqlCommandBuilder();
            if (DatabaseCreated)
            {
                await using var dropDatabase = new NpgsqlCommand(
                    "DROP DATABASE IF EXISTS " + identifiers.QuoteIdentifier(database) + " WITH (FORCE)", connection);
                await dropDatabase.ExecuteNonQueryAsync(deadline.Token);
            }
            foreach (var role in CreatedRoles.AsEnumerable().Reverse())
            {
                await using var dropRole = new NpgsqlCommand("DROP ROLE IF EXISTS " + identifiers.QuoteIdentifier(role), connection);
                await dropRole.ExecuteNonQueryAsync(deadline.Token);
            }
            await using var verify = new NpgsqlCommand("""
                SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname=@database)
                   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=ANY(@roles))
                """, connection);
            verify.Parameters.AddWithValue("database", database);
            verify.Parameters.AddWithValue("roles", NpgsqlTypes.NpgsqlDbType.Array | NpgsqlTypes.NpgsqlDbType.Text, CreatedRoles.ToArray());
            Assert.Equal(true, await verify.ExecuteScalarAsync(deadline.Token));
        }
    }
}
