using ItManagement.Core;
using ItManagement.EnrollmentGrantExecution;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DeliveryIncompleteUpgradeRollsBackToUsableV3(bool canonicalCollation)
    {
        var owner = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        Assert.Contains(owner.Host, new[] { "localhost", "127.0.0.1", "::1" });
        Assert.StartsWith("console_", owner.Database);
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var database = "console_delivery_upgrade_" + suffix;
        var api = "cdu_api_" + suffix;
        var locker = "cdu_lock_" + suffix;
        var executor = "cdu_exec_" + suffix;
        var queue = "cdu_queue_" + suffix;
        var worker = "cdu_worker_" + suffix;
        var delivery = "cdu_delivery_" + suffix;
        var password = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24));
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var admin = new NpgsqlConnectionStringBuilder(owner.ConnectionString) { Database = "postgres", Pooling = false };
        await using var cleanup = new QueueUpgradeCleanup(admin.ConnectionString, database);
        await using (var connection = new NpgsqlConnection(admin.ConnectionString))
        {
            await connection.OpenAsync(deadline.Token);
            var sql = "CREATE DATABASE " + database + (canonicalCollation ? " TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'" : "");
            await using var create = new NpgsqlCommand(sql, connection);
            await create.ExecuteNonQueryAsync(deadline.Token);
            cleanup.DatabaseCreated = true;
        }
        owner.Database = database;
        owner.Pooling = false;
        await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(owner.ConnectionString).Options);
        await db.Database.MigrateAsync(deadline.Token);
        await db.Database.OpenConnectionAsync(deadline.Token);
        // Every resource name/password is generated from fixed prefixes and hexadecimal bytes.
        foreach (var (name, login) in new[] { (api, true), (worker, true), (locker, false), (executor, false), (queue, false), (delivery, false) })
        {
            var authentication = login ? "LOGIN PASSWORD '" + password + "'" : "NOLOGIN";
            await using var createRole = new NpgsqlCommand(
                $"CREATE ROLE {name} {authentication} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION",
                (NpgsqlConnection)db.Database.GetDbConnection());
            await createRole.ExecuteNonQueryAsync(deadline.Token);
            cleanup.CreatedRoles.Add(name);
        }
        var environment = new ManagedEnvironment { Id = Guid.NewGuid(), Name = "Synthetic delivery upgrade", CanonicalDns = "upgrade.example.test", DefaultLocale = "en-US", Version = 1 };
        db.Environments.Add(environment);
        await db.SaveChangesAsync(deadline.Token);
        var variables = new Dictionary<string, string>
        {
            ["runtime_role"] = api, ["enrollment_plan_lock_owner_role"] = locker,
            ["execution_runtime_role"] = worker, ["execution_definer_role"] = executor,
            ["execution_queue_definer_role"] = queue, ["delivery_definer_role"] = delivery,
            ["expected_table_owner_role"] = owner.Username!, ["expected_environment_id"] = environment.Id.ToString(), ["DBNAME"] = database
        };
        foreach (var path in new[] { "provision-runtime.sql", "enrollment-execution/v3/provision-enrollment-execution.sql" })
        {
            var result = await RunScript(owner, path, variables, deadline.Token);
            Assert.True(result.ExitCode == 0, result.Error);
        }
        var bindings = await Snapshot(false);
        var reservations = await Snapshot(true);
        var rejected = await RunScript(owner, "upgrade-enrollment-execution-v3-to-v4.sql", variables, deadline.Token);
        Assert.NotEqual(0, rejected.ExitCode);
        Assert.True(rejected.Error.Contains("v4 postflight failed", StringComparison.Ordinal), rejected.Error);
        Assert.Equal((short)3, await db.Database.SqlQueryRaw<short>("SELECT enrollment_execution.execution_store_profile() AS \"Value\"").SingleAsync(deadline.Token));
        Assert.Equal(bindings, await Snapshot(false));
        Assert.Equal(reservations, await Snapshot(true));
        Assert.True(await db.Database.SqlQueryRaw<bool>("""
            SELECT pg_catalog.to_regprocedure('enrollment_execution.audit_delivery_privileges(uuid)') IS NULL
              AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy WHERE polname LIKE 'enrollment_delivery_%') AS "Value"
            """).SingleAsync(deadline.Token));
        var runtime = new NpgsqlConnectionStringBuilder(owner.ConnectionString) { Username = worker, Password = password };
        await using var source = NpgsqlDataSource.Create(runtime.ConnectionString);
        var store = await PostgresEnrollmentGrantWorkQueue.CreateAuditedAsync(source, environment.Id, owner.Username!, executor, queue, deadline.Token);
        Assert.Equal(EnrollmentWorkClaimOutcome.NoWork, (await store.ClaimNextAsync(Guid.NewGuid(), deadline.Token)).Outcome);

        async Task<string[]> Snapshot(bool reservationRows) => await db.Database.SqlQueryRaw<string>(reservationRows
            ? "SELECT row_to_json(snapshot)::text AS \"Value\" FROM enrollment_execution.role_reservations snapshot ORDER BY row_to_json(snapshot)::text COLLATE \"C\""
            : "SELECT row_to_json(snapshot)::text AS \"Value\" FROM public.\"DirectoryDatabaseBindings\" snapshot ORDER BY row_to_json(snapshot)::text COLLATE \"C\"").ToArrayAsync(deadline.Token);
    }
}
