using ItManagement.Core;
using ItManagement.EnrollmentGrantExecution;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 0)]
    [InlineData(false, 1)]
    [InlineData(true, 1)]
    [InlineData(false, 2)]
    [InlineData(true, 2)]
    public async Task DeliveryUpgradePreservesV3AfterRollback(bool canonicalCollation, int composition)
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
        var statusRuntime = "cdu_status_" + suffix;
        var deliveryRuntime = "cdu_reader_" + suffix;
        var otherWorker = "cdu_other_worker_" + suffix;
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
        var roles = new List<(string Name, bool Login)> { (api, true), (worker, true), (locker, false), (executor, false), (queue, false), (delivery, false) };
        if (composition == 2) roles.AddRange([(statusRuntime, true), (deliveryRuntime, true), (otherWorker, true)]);
        foreach (var (name, login) in roles)
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
        var otherEnvironment = new ManagedEnvironment { Id = Guid.NewGuid(), Name = "Other synthetic delivery environment", CanonicalDns = "other-upgrade.example.test", DefaultLocale = "en-US", Version = 1 };
        if (composition == 2)
        {
            db.Environments.Add(otherEnvironment);
            await db.SaveChangesAsync(deadline.Token);
        }
        var variables = new Dictionary<string, string>
        {
            ["runtime_role"] = api, ["enrollment_plan_lock_owner_role"] = locker,
            ["execution_runtime_role"] = worker, ["execution_definer_role"] = executor,
            ["execution_queue_definer_role"] = queue, ["delivery_definer_role"] = delivery,
            ["status_runtime_role"] = statusRuntime, ["delivery_runtime_role"] = deliveryRuntime,
            ["other_environment_id"] = otherEnvironment.Id.ToString(),
            ["expected_table_owner_role"] = owner.Username!, ["expected_environment_id"] = environment.Id.ToString(), ["DBNAME"] = database
        };
        foreach (var path in new[] { "provision-runtime.sql", "enrollment-execution/v3/provision-enrollment-execution.sql" })
        {
            var result = await RunScript(owner, path, variables, deadline.Token);
            Assert.True(result.ExitCode == 0, result.Error);
        }
        if (composition == 2)
        {
            var otherVariables = new Dictionary<string, string>(variables)
            {
                ["execution_runtime_role"] = otherWorker, ["expected_environment_id"] = otherEnvironment.Id.ToString()
            };
            var otherProvision = await RunScript(owner, "enrollment-execution/v3/provision-enrollment-execution.sql", otherVariables, deadline.Token);
            Assert.True(otherProvision.ExitCode == 0, otherProvision.Error);
        }
        var bindings = await Snapshot(false);
        var reservations = await Snapshot(true);
        var auditIdentity = await AuditIdentity();
        var pairPrivileges = composition == 2 ? await PairPrivileges() : null;
        if (composition == 2) Assert.Empty(pairPrivileges!);
        if (composition > 0)
        {
            // Compose the exact staged sources only in this disposable database. Even a
            // successful postflight ends with ROLLBACK; the real upgrade remains uncomposed.
            var path = Path.Combine(AppContext.BaseDirectory, "delivery-candidate-" + suffix + ".sql");
            try
            {
                var script = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "upgrade-enrollment-execution-v3-to-v4.sql"), deadline.Token);
                const string include = "\\ir enrollment-delivery-profile.sql";
                const string begin = "BEGIN;";
                const string postflight = "DO $postflight$";
                const string commit = "COMMIT;";
                foreach (var marker in new[] { include, begin, postflight, commit })
                    Assert.Equal(1, script.Split(marker, StringSplitOptions.None).Length - 1);
                var pairScript = "";
                if (composition == 2)
                {
                    pairScript = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "provision-enrollment-delivery.sql"), deadline.Token);
                    foreach (var marker in new[] { begin, commit })
                        Assert.Equal(1, pairScript.Split(marker, StringSplitOptions.None).Length - 1);
                    // Preserve the real pair installer's preflight, grants and postflight;
                    // its transaction is owned by the surrounding rollback-only candidate.
                    pairScript = pairScript.Replace(begin, "", StringComparison.Ordinal).Replace(commit, "", StringComparison.Ordinal);
                    pairScript += "\n" + DeliveryAuditSessionProbe();
                    pairScript += "\n" + await DeliveryExternalCatalogProbeAsync(deadline.Token);
                }
                script = script.Replace(include, include + "\n\\ir enrollment-delivery-identity.sql", StringComparison.Ordinal)
                    .Replace(begin, begin + """

                    CREATE TEMP TABLE delivery_upgrade_audit_identity ON COMMIT DROP AS
                      SELECT oid,proowner,proacl FROM pg_catalog.pg_proc
                      WHERE oid='enrollment_execution.audit_execution_privileges(uuid)'::regprocedure;
                    """, StringComparison.Ordinal)
                    .Replace(postflight, """
                    DO $verify_preserved_audit$
                    BEGIN
                      IF NOT EXISTS(SELECT 1 FROM delivery_upgrade_audit_identity before
                          JOIN pg_catalog.pg_proc after ON after.oid=before.oid
                          WHERE after.proowner=before.proowner AND after.proacl IS NOT DISTINCT FROM before.proacl) THEN
                        RAISE EXCEPTION 'Execution audit identity or ACL changed during upgrade.';
                      END IF;
                    END $verify_preserved_audit$;

                    """ + postflight, StringComparison.Ordinal)
                    .Replace(commit, pairScript + "\nROLLBACK;", StringComparison.Ordinal);
                await File.WriteAllTextAsync(path, script, deadline.Token);
                var candidate = await RunScript(owner, path, variables, deadline.Token);
                Assert.True(candidate.ExitCode == 0, candidate.Error);
            }
            finally { File.Delete(path); }
        }
        else
        {
            var rejected = await RunScript(owner, "upgrade-enrollment-execution-v3-to-v4.sql", variables, deadline.Token);
            Assert.NotEqual(0, rejected.ExitCode);
            Assert.True(rejected.Error.Contains("v4 postflight failed", StringComparison.Ordinal), rejected.Error);
        }
        Assert.Equal((short)3, await db.Database.SqlQueryRaw<short>("SELECT enrollment_execution.execution_store_profile() AS \"Value\"").SingleAsync(deadline.Token));
        Assert.Equal(bindings, await Snapshot(false));
        Assert.Equal(reservations, await Snapshot(true));
        Assert.Equal(auditIdentity, await AuditIdentity());
        if (composition == 2) Assert.Equal(pairPrivileges, await PairPrivileges());
        Assert.True(await db.Database.SqlQueryRaw<bool>("""
            SELECT pg_catalog.to_regprocedure('enrollment_execution.audit_delivery_privileges(uuid)') IS NULL
              AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy WHERE polname LIKE 'enrollment_delivery_%') AS "Value"
            """).SingleAsync(deadline.Token));
        var runtime = new NpgsqlConnectionStringBuilder(owner.ConnectionString) { Username = worker, Password = password };
        await using var source = NpgsqlDataSource.Create(runtime.ConnectionString);
        var store = await PostgresEnrollmentGrantWorkQueue.CreateAuditedAsync(source, environment.Id, owner.Username!, executor, queue, deadline.Token);
        Assert.Equal(EnrollmentWorkClaimOutcome.NoWork, (await store.ClaimNextAsync(Guid.NewGuid(), deadline.Token)).Outcome);

        async Task<string> AuditIdentity() => await db.Database.SqlQueryRaw<string>("""
            SELECT jsonb_build_object('oid',oid,'owner',proowner,'acl',proacl,'body',prosrc)::text AS "Value"
            FROM pg_catalog.pg_proc WHERE oid='enrollment_execution.audit_execution_privileges(uuid)'::regprocedure
            """).SingleAsync(deadline.Token);

        async Task<string[]> PairPrivileges() => await db.Database.SqlQuery<string>($"""
            SELECT jsonb_build_object('class',acl.classid,'object',acl.objid,'subobject',acl.objsubid,
              'type',acl.deptype,'role',acl.refobjid)::text AS "Value"
            FROM pg_catalog.pg_shdepend acl JOIN pg_catalog.pg_roles role ON role.oid=acl.refobjid
            WHERE acl.refclassid='pg_catalog.pg_authid'::regclass AND role.rolname IN({statusRuntime},{deliveryRuntime})
            ORDER BY acl.classid,acl.objid,acl.objsubid,acl.deptype,acl.refobjid
            """).ToArrayAsync(deadline.Token);

        async Task<string[]> Snapshot(bool reservationRows) => await db.Database.SqlQueryRaw<string>(reservationRows
            ? "SELECT row_to_json(snapshot)::text AS \"Value\" FROM enrollment_execution.role_reservations snapshot ORDER BY row_to_json(snapshot)::text COLLATE \"C\""
            : "SELECT row_to_json(snapshot)::text AS \"Value\" FROM public.\"DirectoryDatabaseBindings\" snapshot ORDER BY row_to_json(snapshot)::text COLLATE \"C\"").ToArrayAsync(deadline.Token);
    }
}
