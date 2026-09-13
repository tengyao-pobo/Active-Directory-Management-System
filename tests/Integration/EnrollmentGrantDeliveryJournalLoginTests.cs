using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using System.Security.Cryptography;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Theory]
    [InlineData("normal")]
    [InlineData("stopped")]
    [InlineData("missing-column")]
    public async Task DeliveryJournalLoginCommitsOrRollsBackDeferredValidation(string fault)
    {
        // Journal/trigger layer only: the test wrapper deliberately omits production
        // authorization and profile audits, which require separate end-to-end tests.
        var owner = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        Assert.Contains(owner.Host, new[] { "localhost", "127.0.0.1", "::1" });
        Assert.StartsWith("console_", owner.Database);
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var database = "console_delivery_journal_" + suffix;
        var definer = "cdj_def_" + suffix;
        var runtime = "cdj_run_" + suffix;
        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        var admin = new NpgsqlConnectionStringBuilder(owner.ConnectionString) { Database = "postgres", Pooling = false };
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var cleanup = new QueueUpgradeCleanup(admin.ConnectionString, database);
        await using (var connection = new NpgsqlConnection(admin.ConnectionString))
        {
            await connection.OpenAsync(deadline.Token);
            await using var create = new NpgsqlCommand("CREATE DATABASE " + database, connection);
            await create.ExecuteNonQueryAsync(deadline.Token);
            cleanup.DatabaseCreated = true;
        }
        owner.Database = database;
        owner.Pooling = false;
        await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(owner.ConnectionString).Options);
        await db.Database.MigrateAsync(deadline.Token);
        await db.Database.OpenConnectionAsync(deadline.Token);
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, (NpgsqlConnection)db.Database.GetDbConnection());
            await command.ExecuteNonQueryAsync(deadline.Token);
        }
        foreach (var (name, login) in new[] { (definer, false), (runtime, true) })
        {
            await Execute($"CREATE ROLE {name} {(login ? "LOGIN PASSWORD '" + password + "'" : "NOLOGIN")} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION");
            cleanup.CreatedRoles.Add(name);
        }
        await Execute(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-journal.sql"), deadline.Token));
        var policySource = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-profile.sql"), deadline.Token);
        var policyStart = policySource.IndexOf("CREATE POLICY enrollment_delivery_operations_allow", StringComparison.Ordinal);
        var policyEnd = policySource.IndexOf("CREATE FUNCTION enrollment_execution.audit_delivery_privileges(", policyStart, StringComparison.Ordinal);
        Assert.True(policyStart >= 0 && policyEnd > policyStart);
        await Execute(policySource[policyStart..policyEnd].Replace(":\"delivery_definer_role\"", '"' + definer + '"', StringComparison.Ordinal));
        // Copy the operation and journal grants from the installer, not a broader substitute.
        var installer = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "upgrade-enrollment-execution-v3-to-v4.sql"), deadline.Token);
        var grantStart = installer.IndexOf("GRANT SELECT(\"EnvironmentId\",\"Id\",\"RequesterId\",\"DirectoryObjectId\",\"PlanHash\"", StringComparison.Ordinal);
        var grantEnd = installer.IndexOf("REVOKE CREATE ON SCHEMA", grantStart, StringComparison.Ordinal);
        Assert.True(grantStart >= 0 && grantEnd > grantStart);
        await Execute(installer[grantStart..grantEnd].Replace(":\"delivery_definer_role\"", '"' + definer + '"', StringComparison.Ordinal));
        var revokeEnd = installer.IndexOf(';', grantEnd);
        Assert.True(revokeEnd > grantEnd);
        await Execute(installer[grantEnd..(revokeEnd + 1)].Replace(":\"delivery_definer_role\"", '"' + definer + '"', StringComparison.Ordinal));
        await Execute($"GRANT USAGE ON SCHEMA enrollment_execution TO {definer},{runtime}; GRANT CONNECT ON DATABASE {database} TO {runtime}");
        if (fault == "missing-column") await Execute($"REVOKE SELECT(\"RecipientKeyFingerprint\") ON public.\"EnrollmentGrantOperations\" FROM {definer}");

        var now = new DateTimeOffset(DateTime.UtcNow.Ticks / 10 * 10, TimeSpan.Zero);
        var operation = new EnrollmentGrantOperation
        {
            Id = Guid.NewGuid(), EnvironmentId = Guid.NewGuid(), PlanId = Guid.NewGuid(), RequestId = Guid.NewGuid(), ApprovalId = Guid.NewGuid(),
            RequesterId = Guid.NewGuid(), ApproverId = Guid.NewGuid(), RequesterOperatorId = Guid.NewGuid(), ApproverOperatorId = Guid.NewGuid(),
            PlanHash = new string('a', 64), DirectoryObjectId = Guid.NewGuid(), ServerDeviceId = Guid.NewGuid(), DirectoryGeneration = Guid.NewGuid(),
            MappingCreatedAt = now.AddMinutes(-1), EnvironmentVersion = 1, RecipientSpki = [1], RecipientKeyFingerprint = RandomNumberGenerator.GetBytes(32),
            QueuedAt = now, AuthorizationNotAfter = now.AddMinutes(5)
        };
        var other = Guid.NewGuid();
        var ciphertext = RandomNumberGenerator.GetBytes(384);
        var ciphertextHash = SHA256.HashData(ciphertext);
        var tokenHash = RandomNumberGenerator.GetBytes(32);
        var digest = RandomNumberGenerator.GetBytes(32);
        // Synthetic journal graph: unrelated API/approval foreign keys and the intentionally
        // inconsistent stop+issued case are seeded only in this disposable owner transaction.
        await using (var seed = await db.Database.BeginTransactionAsync(deadline.Token))
        {
            await db.Database.ExecuteSqlRawAsync("SET LOCAL session_replication_role=replica", deadline.Token);
            db.EnrollmentGrantOperations.Add(operation);
            await db.SaveChangesAsync(deadline.Token);
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO enrollment_execution.mint_permits(operation_id,format_version,issued_at,not_after,token_sha256,recipient_fingerprint,ciphertext_sha256,authorization_digest)
                VALUES({operation.Id},1,{now},{now.AddSeconds(60)},{tokenHash},{operation.RecipientKeyFingerprint},{ciphertextHash},{digest});
                INSERT INTO enrollment_execution.sealed_envelopes(operation_id,ciphertext) VALUES({operation.Id},{ciphertext});
                INSERT INTO enrollment_execution.issue_results(operation_id,outcome,diagnostic,recorded_at,grant_id,environment_id,directory_object_id,device_id,
                    mapping_created_at,grant_created_at,grant_expires_at,issue_contract_version,mint_permit_not_after,token_sha256,authorization_digest)
                VALUES({operation.Id},'Issued','None',{now.AddSeconds(1)},{Guid.NewGuid()},{operation.EnvironmentId},{operation.DirectoryObjectId},{operation.ServerDeviceId},
                    {operation.MappingCreatedAt},{now.AddSeconds(1)},{now.AddSeconds(601)},2,{now.AddSeconds(60)},{tokenHash},{digest});
                INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at) VALUES({other},'StoredDataInvalid',{now.AddSeconds(2)});
                """, deadline.Token);
            if (fault == "stopped") await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at) VALUES({operation.Id},'StoredDataInvalid',{now.AddSeconds(2)})
                """, deadline.Token);
            await seed.CommitAsync(deadline.Token);
        }
        await Execute($$"""
            CREATE FUNCTION enrollment_execution.test_journal_ack(p_operation uuid,p_environment uuid,p_requester uuid)
            RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $probe$
            BEGIN
              PERFORM set_config('app.delivery_operation_id',p_operation::text,true),
                set_config('app.delivery_environment_id',p_environment::text,true),set_config('app.delivery_requester_id',p_requester::text,true);
              INSERT INTO enrollment_execution.delivery_acks(operation_id,requester_id,ciphertext_sha256,token_sha256,acknowledged_at)
                SELECT p_operation,p_requester,permit.ciphertext_sha256,permit.token_sha256,result.recorded_at
                FROM enrollment_execution.mint_permits permit JOIN enrollment_execution.issue_results result USING(operation_id)
                WHERE permit.operation_id=p_operation;
              IF NOT FOUND THEN RAISE EXCEPTION 'Fixture could not read its journal.'; END IF;
              DELETE FROM enrollment_execution.sealed_envelopes WHERE operation_id=p_operation;
            END $probe$;
            ALTER FUNCTION enrollment_execution.test_journal_ack(uuid,uuid,uuid) OWNER TO {{definer}};
            REVOKE ALL ON FUNCTION enrollment_execution.test_journal_ack(uuid,uuid,uuid) FROM PUBLIC;
            GRANT EXECUTE ON FUNCTION enrollment_execution.test_journal_ack(uuid,uuid,uuid) TO {{runtime}};
            CREATE FUNCTION enrollment_execution.test_other_stop(p_context uuid,p_target uuid) RETURNS bigint
              LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $probe$
            DECLARE visible bigint;
            BEGIN
              PERFORM set_config('app.delivery_operation_id',p_context::text,true);
              SELECT count(*) INTO visible FROM enrollment_execution.execution_stops WHERE operation_id=p_target;
              RETURN visible;
            END $probe$;
            ALTER FUNCTION enrollment_execution.test_other_stop(uuid,uuid) OWNER TO {{definer}};
            REVOKE ALL ON FUNCTION enrollment_execution.test_other_stop(uuid,uuid) FROM PUBLIC;
            GRANT EXECUTE ON FUNCTION enrollment_execution.test_other_stop(uuid,uuid) TO {{runtime}};
            """);
        var runtimeSettings = new NpgsqlConnectionStringBuilder(owner.ConnectionString) { Username = runtime, Password = password, Pooling = false };
        await using var caller = new NpgsqlConnection(runtimeSettings.ConnectionString);
        await caller.OpenAsync(deadline.Token);
        await using (var identity = new NpgsqlCommand("SELECT SESSION_USER=CURRENT_USER AND SESSION_USER=@role AND current_setting('session_replication_role')='origin'", caller))
        {
            identity.Parameters.AddWithValue("role", runtime);
            Assert.Equal(true, await identity.ExecuteScalarAsync(deadline.Token));
        }
        await using (var direct = new NpgsqlCommand("SELECT 1 FROM enrollment_execution.execution_stops", caller))
        {
            var denied = await Assert.ThrowsAsync<PostgresException>(() => direct.ExecuteScalarAsync(deadline.Token));
            Assert.Equal("42501", denied.SqlState);
        }
        await using (var privileges = new NpgsqlCommand("""
            SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class relation
              WHERE relation.oid IN('public."EnrollmentGrantOperations"'::regclass,'enrollment_execution.mint_permits'::regclass,
                'enrollment_execution.issue_results'::regclass,'enrollment_execution.sealed_envelopes'::regclass,
                'enrollment_execution.delivery_acks'::regclass,'enrollment_execution.execution_stops'::regclass)
                AND (pg_catalog.has_table_privilege(CURRENT_USER,relation.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
                  OR pg_catalog.has_any_column_privilege(CURRENT_USER,relation.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
            """, caller)) Assert.Equal(true, await privileges.ExecuteScalarAsync(deadline.Token));
        await using (var visibility = new NpgsqlCommand("SELECT enrollment_execution.test_other_stop(@context,@other)", caller))
        {
            visibility.Parameters.AddWithValue("context", operation.Id);
            visibility.Parameters.AddWithValue("other", other);
            Assert.Equal(0L, await visibility.ExecuteScalarAsync(deadline.Token));
            visibility.Parameters["context"].Value = other;
            Assert.Equal(1L, await visibility.ExecuteScalarAsync(deadline.Token));
        }
        await using (var transaction = await caller.BeginTransactionAsync(deadline.Token))
        {
            await using var ack = new NpgsqlCommand("SELECT enrollment_execution.test_journal_ack(@operation,@environment,@requester)", caller, transaction);
            ack.Parameters.AddWithValue("operation", operation.Id);
            ack.Parameters.AddWithValue("environment", operation.EnvironmentId);
            ack.Parameters.AddWithValue("requester", operation.RequesterId);
            await ack.ExecuteNonQueryAsync(deadline.Token);
            if (fault == "normal") await transaction.CommitAsync(deadline.Token);
            else
            {
                var error = await Assert.ThrowsAsync<PostgresException>(() => transaction.CommitAsync(deadline.Token));
                Assert.Equal(fault == "stopped" ? "23514" : "42501", error.SqlState);
                Assert.Contains(fault == "stopped" ? "Enrollment stop cannot replace a committed result" : "EnrollmentGrantOperations", error.MessageText, StringComparison.Ordinal);
            }
        }
        Assert.Equal(fault == "normal" ? 1 : 0, await db.Database.SqlQuery<int>($"SELECT count(*)::integer AS \"Value\" FROM enrollment_execution.delivery_acks WHERE operation_id={operation.Id}").SingleAsync(deadline.Token));
        Assert.Equal(fault == "normal" ? 0 : 1, await db.Database.SqlQuery<int>($"SELECT count(*)::integer AS \"Value\" FROM enrollment_execution.sealed_envelopes WHERE operation_id={operation.Id}").SingleAsync(deadline.Token));
    }
}
