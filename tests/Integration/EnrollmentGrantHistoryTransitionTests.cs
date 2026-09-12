using Npgsql;
using System.Text.RegularExpressions;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static async Task VerifyHistoryTransitionAsync(NpgsqlConnection owner, NpgsqlConnection admin,
        string runtimeConnection, Guid environment, CancellationToken cancellationToken)
    {
        async Task Execute(NpgsqlConnection connection, string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-history-transition.sql"), cancellationToken);
        var bootstrap = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "activate-enrollment-profile4-candidate.sql"), cancellationToken);
        var carrier = bootstrap[(bootstrap.IndexOf("BEGIN;", StringComparison.Ordinal) + 6)..bootstrap.IndexOf("\\ir ", StringComparison.Ordinal)]
            .Replace(":'expected_generation'", "@generation", StringComparison.Ordinal)
            .Replace(":'expected_installation_nonce'", "@nonce", StringComparison.Ordinal)
            .Replace(":'expected_manifest_sha256'", "@manifest", StringComparison.Ordinal);
        var readySource = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-profile4-ready.sql"), cancellationToken);
        var manifest = Regex.Match(readySource, "expected_manifest constant bytea := decode\\('([0-9a-f]{64})','hex'\\);").Groups[1].Value;
        Assert.Equal(64, manifest.Length);
        var nonce = Guid.Parse("33333333-3333-3333-3333-333333333333");
        await Execute(owner, "UPDATE enrollment_execution.profile4_readiness SET state='PendingHistoryAudit',generation=3,installation_nonce='33333333-3333-3333-3333-333333333333',pending_at=statement_timestamp(),ready_at=NULL,ready_by=NULL");
        async Task<string> State()
        {
            await using var command = new NpgsqlCommand("SELECT row_to_json(r)::text FROM enrollment_execution.profile4_readiness r", owner);
            return (string)(await command.ExecuteScalarAsync(cancellationToken))!;
        }
        async Task<string> Policies()
        {
            await using var command = new NpgsqlCommand("SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY oid),'[]'::jsonb)::text FROM pg_catalog.pg_policy p", owner);
            return (string)(await command.ExecuteScalarAsync(cancellationToken))!;
        }
        var pending = await State();
        var policies = await Policies();
        async Task Clean()
        {
            Assert.Equal(pending, await State());
            Assert.Equal(policies, await Policies());
            await using var command = new NpgsqlCommand("SELECT pg_catalog.to_regclass('pg_temp.profile4_history_expected') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory' AND classid=1162235478 AND objid=1 AND objsubid=2)", owner);
            Assert.Equal(true, await command.ExecuteScalarAsync(cancellationToken));
            await using var structure = new NpgsqlCommand("SELECT is_valid AND diagnostic_code='None' AND profile_version=4 FROM enrollment_execution.audit_execution_profile_structure(@environment)", owner);
            structure.Parameters.AddWithValue("environment", environment);
            Assert.Equal(true, await structure.ExecuteScalarAsync(cancellationToken));
            await using var closed = new NpgsqlCommand("SELECT NOT is_valid AND diagnostic_code='ProfileDrift' AND profile_version=4 FROM enrollment_execution.audit_execution_privileges(@environment)", owner);
            closed.Parameters.AddWithValue("environment", environment);
            Assert.Equal(true, await closed.ExecuteScalarAsync(cancellationToken));
        }
        async Task Reject(string mode, string expectedCode)
        {
            await using var transaction = await owner.BeginTransactionAsync(cancellationToken);
            if (mode != "missing")
            {
                await using var input = new NpgsqlCommand(carrier, owner);
                input.Parameters.AddWithValue("generation", mode == "generation" ? 99L : 3L);
                input.Parameters.AddWithValue("nonce", mode == "nonce" ? Guid.NewGuid() : nonce);
                input.Parameters.AddWithValue("manifest", mode == "manifest" ? new string('c', 64) : manifest);
                await input.ExecuteNonQueryAsync(cancellationToken);
                if (mode == "empty") await Execute(owner, "DELETE FROM pg_temp.profile4_history_expected");
                if (mode == "multiple")
                    await Execute(owner, "ALTER TABLE pg_temp.profile4_history_expected DROP CONSTRAINT profile4_history_expected_pkey; INSERT INTO pg_temp.profile4_history_expected SELECT * FROM pg_temp.profile4_history_expected");
            }
            var candidate = source;
            if (mode == "final")
            {
                // Test-only fault after Ready UPDATE; final ordinary audit must reject and roll everything back.
                const string marker = "    -- Separate statement: STABLE audit must see this transaction's preceding Ready update.";
                Assert.Equal(1, candidate.Split(marker, StringSplitOptions.None).Length - 1);
                candidate = candidate.Replace(marker, """
                    ALTER TABLE enrollment_execution.profile4_readiness DISABLE TRIGGER profile4_readiness_transition;
                    UPDATE enrollment_execution.profile4_readiness SET ready_by='wrong_final_owner';
                    ALTER TABLE enrollment_execution.profile4_readiness ENABLE TRIGGER profile4_readiness_transition;
                    """ + "\n" + marker, StringComparison.Ordinal);
            }
            var failure = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, candidate));
            Assert.True(failure.SqlState == expectedCode, mode + ": " + failure.SqlState + " " + failure.MessageText);
            if (mode == "final") Assert.Equal("History final runtime audit failed.", failure.MessageText);
            if (mode == "history") Assert.Equal("Enrollment delivery history is inconsistent.", failure.MessageText);
            if (mode == "ownerflags") Assert.Equal("History audit owner context is invalid.", failure.MessageText);
            await transaction.RollbackAsync(cancellationToken);
            if (mode != "ownerflags") await Clean();
        }
        foreach (var (mode, code) in new[] { ("missing", "55000"), ("generation", "55000"), ("nonce", "55000"),
            ("manifest", "55000"), ("empty", "P0002"), ("multiple", "P0003"), ("final", "55000") })
            await Reject(mode, code);
        await Execute(owner, "CREATE TEMP TABLE profile4_history_expected(marker text); INSERT INTO pg_temp.profile4_history_expected VALUES('preserve-existing-input')");
        await using (var transaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await using var input = new NpgsqlCommand(carrier, owner);
            input.Parameters.AddWithValue("generation", 3L);
            input.Parameters.AddWithValue("nonce", nonce);
            input.Parameters.AddWithValue("manifest", manifest);
            var occupied = await Assert.ThrowsAsync<PostgresException>(async () => { await input.ExecuteNonQueryAsync(cancellationToken); });
            Assert.Equal("42P07", occupied.SqlState);
            await transaction.RollbackAsync(cancellationToken);
        }
        await using (var existing = new NpgsqlCommand("SELECT marker FROM pg_temp.profile4_history_expected", owner))
            Assert.Equal("preserve-existing-input", await existing.ExecuteScalarAsync(cancellationToken));
        await Execute(owner, "DROP TABLE pg_temp.profile4_history_expected");
        await Clean();
        var ownerName = new NpgsqlConnectionStringBuilder(owner.ConnectionString).Username!;
        var quotedOwner = "\"" + ownerName.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        await Execute(admin, $"ALTER ROLE {quotedOwner} CREATEDB");
        try { await Reject("ownerflags", "55000"); }
        finally
        {
            await using var restore = new NpgsqlCommand($"ALTER ROLE {quotedOwner} NOCREATEDB", admin) { CommandTimeout = 10 };
            await restore.ExecuteNonQueryAsync(CancellationToken.None);
        }
        await Clean();
        await Execute(admin, "BEGIN; SET LOCAL session_replication_role=replica; INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at) VALUES(gen_random_uuid(),'StoredDataInvalid',clock_timestamp()); COMMIT;");
        await Reject("history", "23514");
        await Execute(admin, "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM enrollment_execution.execution_stops; COMMIT;");
        await Clean();

        // Release the fixture's sole owner connection so psql performs a new physical owner LOGIN.
        var ownerInfo = new NpgsqlConnectionStringBuilder(owner.ConnectionString)
        {
            Password = new NpgsqlConnectionStringBuilder(runtimeConnection).Password,
            Pooling = false
        };
        var variables = new Dictionary<string, string>
        {
            ["expected_generation"] = "3", ["expected_installation_nonce"] = nonce.ToString(),
            ["expected_manifest_sha256"] = manifest
        };
        await owner.CloseAsync();
        string? committedReady = null;
        try
        {
            var wrongVariables = new Dictionary<string, string>(variables) { ["expected_generation"] = "99" };
            var rejected = await RunScript(ownerInfo, "activate-enrollment-profile4-candidate.sql", wrongVariables, cancellationToken);
            Assert.NotEqual(0, rejected.ExitCode);
            Assert.Contains("History pending installation tuple does not match.", rejected.Error, StringComparison.Ordinal);
            await owner.OpenAsync(cancellationToken);
            await Execute(owner, "SET search_path=pg_catalog,pg_temp; SET row_security=on");
            await Clean();
            await owner.CloseAsync();
            var activated = await RunScript(ownerInfo, "activate-enrollment-profile4-candidate.sql", variables, cancellationToken);
            Assert.True(activated.ExitCode == 0, activated.Error);
            await owner.OpenAsync(cancellationToken);
            committedReady = await State();
            await owner.CloseAsync();
            var repeated = await RunScript(ownerInfo, "activate-enrollment-profile4-candidate.sql", variables, cancellationToken);
            Assert.NotEqual(0, repeated.ExitCode);
            Assert.Contains("History pending installation tuple does not match.", repeated.Error, StringComparison.Ordinal);
        }
        finally
        {
            if (owner.State != System.Data.ConnectionState.Open) await owner.OpenAsync(cancellationToken);
            await Execute(owner, "SET search_path=pg_catalog,pg_temp; SET row_security=on");
        }
        Assert.Equal(committedReady, await State());
        Assert.Equal(policies, await Policies());
        await using (var cleanup = new NpgsqlCommand("SELECT pg_catalog.to_regclass('pg_temp.profile4_history_expected') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory' AND classid=1162235478 AND objid=1 AND objsubid=2)", owner))
            Assert.Equal(true, await cleanup.ExecuteScalarAsync(cancellationToken));
        await using var audit = new NpgsqlCommand("SELECT is_valid AND diagnostic_code='None' AND profile_version=4 FROM enrollment_execution.audit_execution_privileges(@environment)", owner);
        audit.Parameters.AddWithValue("environment", environment);
        Assert.Equal(true, await audit.ExecuteScalarAsync(cancellationToken));
        await using var state = new NpgsqlCommand("SELECT state='Ready' AND generation=3 AND installation_nonce=@nonce AND ready_by=current_user::name FROM enrollment_execution.profile4_readiness", owner);
        state.Parameters.AddWithValue("nonce", nonce);
        Assert.Equal(true, await state.ExecuteScalarAsync(cancellationToken));
    }
}
