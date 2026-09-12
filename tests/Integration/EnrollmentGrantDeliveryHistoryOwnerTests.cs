using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task DeliveryHistoryOwnerLoginCanAuditCompleteCandidate()
    {
        var owner = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        Assert.Contains(owner.Host, new[] { "localhost", "127.0.0.1", "::1" });
        Assert.StartsWith("console_", owner.Database);
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var database = "console_history_owner_" + suffix;
        var api = "cdu_api_" + suffix;
        var locker = "cdu_lock_" + suffix;
        var executor = "cdu_exec_" + suffix;
        var queue = "cdu_queue_" + suffix;
        var worker = "cdu_worker_" + suffix;
        var delivery = "cdu_delivery_" + suffix;
        var historyOwner = "cdh_owner_" + suffix;
        var password = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24));
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var admin = new NpgsqlConnectionStringBuilder(owner.ConnectionString) { Database = "postgres", Pooling = false };
        await using var cleanup = new QueueUpgradeCleanup(admin.ConnectionString, database);
        await using (var connection = new NpgsqlConnection(admin.ConnectionString))
        {
            await connection.OpenAsync(deadline.Token);
            var sql = "CREATE DATABASE " + database;
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
        var roles = new List<(string Name, bool Login)> { (api, true), (worker, true), (historyOwner, true), (locker, false), (executor, false), (queue, false), (delivery, false) };
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
        // Commit a test-only composed candidate into a disposable database so a new
        // physical LOGIN can observe it. The actual installer and external gate stay unchanged.
        var candidatePath = Path.Combine(AppContext.BaseDirectory, "history-owner-candidate-" + suffix + ".sql");
        try
        {
            var script = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "upgrade-enrollment-execution-v3-to-v4.sql"), deadline.Token);
            const string include = "\\ir enrollment-delivery-profile.sql";
            Assert.Equal(1, script.Split(include, StringSplitOptions.None).Length - 1);
            script = script.Replace(include, include + "\n\\ir enrollment-delivery-identity.sql", StringComparison.Ordinal);
            await File.WriteAllTextAsync(candidatePath, script, deadline.Token);
            var installed = await RunScript(owner, candidatePath, variables, deadline.Token);
            Assert.True(installed.ExitCode == 0, installed.Error);
        }
        finally { File.Delete(candidatePath); }
        await using (var limit = new NpgsqlCommand($"ALTER ROLE {historyOwner} CONNECTION LIMIT 1 VALID UNTIL '{DateTimeOffset.UtcNow.AddMinutes(15):O}'", (NpgsqlConnection)db.Database.GetDbConnection()))
            await limit.ExecuteNonQueryAsync(deadline.Token);
        await using (var transfer = await db.Database.BeginTransactionAsync(deadline.Token))
        {
            // No REASSIGN OWNED: it can affect shared database ownership outside this fixture.
            // Transfer only explicitly inventoried application objects in this disposable DB.
            var sql = $$"""
                CREATE TEMP TABLE history_policy_before ON COMMIT DROP AS
                  SELECT oid,polname,polrelid,polcmd,polpermissive,polroles,polqual,polwithcheck FROM pg_catalog.pg_policy
                  WHERE polrelid IN(SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','enrollment_execution'));
                CREATE TEMP TABLE history_nonowner_functions_before ON COMMIT DROP AS
                  SELECT p.oid,to_jsonb(p) definition FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname IN('public','enrollment_execution') AND p.proowner<>current_user::regrole;
                DO $history_owner_transfer$
                DECLARE prior_owner oid := current_user::regrole; target_owner name := '{{historyOwner}}'; item record;
                BEGIN
                  IF current_database()<>'{{database}}' OR current_database() NOT LIKE 'console_history_owner_%' THEN
                    RAISE EXCEPTION 'History owner fixture database mismatch';
                  END IF;
                  FOR item IN SELECT n.nspname,c.relname FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                    WHERE c.relowner=prior_owner AND n.nspname IN('public','enrollment_execution') AND c.relkind='r'
                      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=c.oid AND d.refclassid='pg_catalog.pg_extension'::regclass AND d.deptype='e')
                  LOOP EXECUTE pg_catalog.format('ALTER TABLE %I.%I OWNER TO %I',item.nspname,item.relname,target_owner); END LOOP;
                  FOR item IN SELECT n.nspname,c.relname FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                    WHERE c.relowner=prior_owner AND n.nspname IN('public','enrollment_execution') AND c.relkind='S'
                      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=c.oid AND d.refclassid='pg_catalog.pg_extension'::regclass AND d.deptype='e')
                  LOOP EXECUTE pg_catalog.format('ALTER SEQUENCE %I.%I OWNER TO %I',item.nspname,item.relname,target_owner); END LOOP;
                  FOR item IN SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                    WHERE p.proowner=prior_owner AND n.nspname IN('public','enrollment_execution') AND p.prokind='f'
                      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_proc'::regclass AND d.objid=p.oid AND d.refclassid='pg_catalog.pg_extension'::regclass AND d.deptype='e')
                  LOOP EXECUTE pg_catalog.format('ALTER FUNCTION %s OWNER TO %I',item.oid::regprocedure,target_owner); END LOOP;
                  FOR item IN SELECT n.nspname,c.relname,p.polname,
                    (SELECT string_agg(CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE pg_catalog.quote_ident(
                      CASE WHEN role_oid=prior_owner THEN target_owner::text ELSE pg_catalog.pg_get_userbyid(role_oid) END) END,',' ORDER BY role_oid)
                      FROM unnest(p.polroles) role_oid) target_roles
                    FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid
                    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                    WHERE n.nspname IN('public','enrollment_execution') AND prior_owner=ANY(p.polroles)
                  LOOP EXECUTE pg_catalog.format('ALTER POLICY %I ON %I.%I TO %s',item.polname,item.nspname,item.relname,item.target_roles); END LOOP;
                  FOR item IN SELECT nspname FROM pg_catalog.pg_namespace
                    WHERE nspowner=prior_owner AND nspname='enrollment_execution'
                  LOOP EXECUTE pg_catalog.format('ALTER SCHEMA %I OWNER TO %I',item.nspname,target_owner); END LOOP;
                  EXECUTE pg_catalog.format('ALTER DATABASE %I OWNER TO %I',current_database(),target_owner);
                  IF EXISTS(SELECT 1 FROM history_policy_before before FULL JOIN pg_catalog.pg_policy after ON after.oid=before.oid
                    WHERE before.oid IS NOT NULL AND (after.oid IS NULL
                      OR (before.polname,before.polrelid,before.polcmd,before.polpermissive,before.polqual::text,before.polwithcheck::text)
                        IS DISTINCT FROM (after.polname,after.polrelid,after.polcmd,after.polpermissive,after.polqual::text,after.polwithcheck::text)
                      OR ARRAY(SELECT CASE WHEN role_oid=prior_owner THEN target_owner::regrole::oid ELSE role_oid END FROM unnest(before.polroles) role_oid ORDER BY 1)
                        IS DISTINCT FROM after.polroles)) THEN RAISE EXCEPTION 'Owner fixture changed policy semantics'; END IF;
                  IF EXISTS(SELECT 1 FROM history_nonowner_functions_before before LEFT JOIN pg_catalog.pg_proc after ON after.oid=before.oid
                    WHERE before.definition IS DISTINCT FROM to_jsonb(after)) THEN RAISE EXCEPTION 'Owner fixture changed another definer function'; END IF;
                  IF EXISTS(SELECT 1 FROM pg_catalog.pg_shdepend d WHERE d.refobjid=target_owner::regrole
                    AND d.refclassid='pg_catalog.pg_authid'::regclass AND d.deptype='o'
                    AND NOT (d.dbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
                      OR (d.classid='pg_catalog.pg_database'::regclass AND d.objid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())))) THEN
                    RAISE EXCEPTION 'Owner fixture escaped database scope'; END IF;
                END $history_owner_transfer$;
                """;
            await using var command = new NpgsqlCommand(sql, (NpgsqlConnection)db.Database.GetDbConnection());
            await command.ExecuteNonQueryAsync(deadline.Token);
            await transfer.CommitAsync(deadline.Token);
        }
        var actualOwner = new NpgsqlConnectionStringBuilder(owner.ConnectionString) { Username = historyOwner, Password = password, Pooling = false };
        await using var ownerLogin = new NpgsqlConnection(actualOwner.ConnectionString);
        await ownerLogin.OpenAsync(deadline.Token);
        await using (var identity = new NpgsqlCommand("SELECT current_user=session_user AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid) FROM pg_catalog.pg_roles r WHERE rolname=current_user", ownerLogin))
            Assert.Equal(true, await identity.ExecuteScalarAsync(deadline.Token));
        await using var audit = new NpgsqlCommand("SELECT is_valid,diagnostic_code,profile_version FROM enrollment_execution.audit_execution_privileges(@environment)", ownerLogin);
        audit.Parameters.AddWithValue("environment", environment.Id);
        await using var reader = await audit.ExecuteReaderAsync(deadline.Token);
        Assert.True(await reader.ReadAsync(deadline.Token));
        Assert.True(reader.GetBoolean(0), "Real non-bypass owner must pass the complete candidate profile");
        Assert.Equal("None", reader.GetString(1));
        Assert.Equal((short)4, reader.GetInt16(2));
        Assert.False(await reader.ReadAsync(deadline.Token));
    }
}
