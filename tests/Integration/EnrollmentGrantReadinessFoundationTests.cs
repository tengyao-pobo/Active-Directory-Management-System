using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static async Task VerifyReadinessFoundationAsync(NpgsqlConnection owner, NpgsqlConnection admin,
        string runtimeConnection, string statusConnection, string deliveryConnection, Guid environment, CancellationToken cancellationToken)
    {
        async Task Execute(NpgsqlConnection connection, string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await Execute(owner, await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-profile4-readiness.sql"), cancellationToken));
        await VerifyReadinessStructureAsync(owner, cancellationToken);
        var readySource = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-profile4-ready.sql"), cancellationToken);
        await Execute(owner, readySource);
        await VerifyReadinessFunctionsAsync(owner, cancellationToken);
        var manifest = System.Text.RegularExpressions.Regex.Match(readySource, "expected_manifest constant bytea := decode\\('([0-9a-f]{64})','hex'\\);").Groups[1].Value;
        Assert.Equal(64, manifest.Length);
        async Task IsReady(bool expected)
        {
            await using var command = new NpgsqlCommand("SELECT enrollment_execution.profile4_ready()", owner);
            Assert.Equal(expected, await command.ExecuteScalarAsync(cancellationToken));
        }
        await IsReady(false);
        const string insert = "INSERT INTO enrollment_execution.profile4_readiness VALUES (true,4,1,'11111111-1111-1111-1111-111111111111',decode(repeat('ab',32),'hex'),'PendingHistoryAudit',statement_timestamp(),NULL,NULL)";
        foreach (var (before, after) in new[] {
            ("true,4,1", "false,4,1"), ("true,4,1", "true,3,1"), ("true,4,1", "true,4,0"),
            ("11111111-1111-1111-1111-111111111111", "00000000-0000-0000-0000-000000000000"),
            ("repeat('ab',32)", "repeat('ab',31)"), ("'PendingHistoryAudit'", "'Ready'"),
            ("'PendingHistoryAudit'", "'Unknown'"), ("statement_timestamp()", "'infinity'::timestamptz") })
        {
            await using var transaction = await owner.BeginTransactionAsync(cancellationToken);
            var failure = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, insert.Replace(before, after, StringComparison.Ordinal)));
            Assert.Equal("23514", failure.SqlState);
            await transaction.RollbackAsync(cancellationToken);
        }
        await Execute(owner, insert.Replace("repeat('ab',32)", "'" + manifest + "'", StringComparison.Ordinal));
        await IsReady(false);
        async Task<string> Snapshot()
        {
            await using var command = new NpgsqlCommand("SELECT row_to_json(r)::text FROM enrollment_execution.profile4_readiness r", owner);
            return (string)(await command.ExecuteScalarAsync(cancellationToken))!;
        }
        var pending = await Snapshot();
        const string ready = "UPDATE enrollment_execution.profile4_readiness SET state='Ready',ready_at=statement_timestamp(),ready_by=session_user";
        const string profileLock = "SELECT pg_catalog.pg_advisory_xact_lock(1162235478,1)";
        async Task Reject(NpgsqlConnection connection, string mutation, bool takeLock = true)
        {
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            if (takeLock) await Execute(connection, profileLock);
            var failure = await Assert.ThrowsAsync<PostgresException>(() => Execute(connection, mutation));
            Assert.Equal("55000", failure.SqlState);
            await transaction.RollbackAsync(cancellationToken);
        }
        await Reject(admin, ready);
        await Reject(owner, "DELETE FROM enrollment_execution.profile4_readiness");
        await Reject(owner, "UPDATE enrollment_execution.profile4_readiness SET generation=2");
        await Reject(owner, ready + ",generation=2");
        await Reject(owner, ready + ",installation_nonce='22222222-2222-2222-2222-222222222222'");
        await Reject(owner, ready + ",attestation_manifest_sha256=decode(repeat('cd',32),'hex')");
        await Reject(owner, ready + ",pending_at=statement_timestamp()+interval '1 day'");
        await Reject(owner, ready.Replace("ready_by=session_user", "ready_by='another_owner'", StringComparison.Ordinal));
        foreach (var column in new[] { "generation", "installation_nonce", "attestation_manifest_sha256", "pending_at", "state", "ready_at", "ready_by" })
        {
            var mutation = column == "state" ? ready.Replace("state='Ready'", "state=NULL", StringComparison.Ordinal)
                : column == "ready_at" ? ready.Replace("ready_at=statement_timestamp()", "ready_at=NULL", StringComparison.Ordinal)
                : column == "ready_by" ? ready.Replace("ready_by=session_user", "ready_by=NULL", StringComparison.Ordinal)
                : ready + "," + column + "=NULL";
            await Reject(owner, mutation);
        }
        Assert.Equal(pending, await Snapshot());
        await using var runtime = new NpgsqlConnection(runtimeConnection);
        await runtime.OpenAsync(cancellationToken);
        foreach (var sql in new[] { "SELECT * FROM enrollment_execution.profile4_readiness", ready, insert,
            "DELETE FROM enrollment_execution.profile4_readiness", "TRUNCATE enrollment_execution.profile4_readiness",
            "SELECT enrollment_execution.guard_profile4_readiness()", "SELECT enrollment_execution.profile4_ready()" })
        {
            var denied = await Assert.ThrowsAsync<PostgresException>(() => Execute(runtime, sql));
            Assert.Equal("42501", denied.SqlState);
        }
        await using (var transaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await Execute(owner, profileLock);
            await Execute(owner, ready);
            await transaction.RollbackAsync(cancellationToken);
        }
        Assert.Equal(pending, await Snapshot());
        // The trigger must acquire its own transaction lock and wait for an active runtime's shared lock.
        await using (var runtimeTransaction = await runtime.BeginTransactionAsync(cancellationToken))
        await using (var ownerTransaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await Execute(runtime, "SELECT pg_catalog.pg_advisory_xact_lock_shared(1162235478,1)");
            var transition = Execute(owner, ready);
            try
            {
                var waiting = false;
                for (var attempt = 0; attempt < 500 && !waiting; attempt++)
                {
                    await using var probe = new NpgsqlCommand("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=@pid AND locktype='advisory' AND classid=1162235478 AND objid=1 AND objsubid=2 AND mode='ExclusiveLock' AND NOT granted)", admin);
                    probe.Parameters.AddWithValue("pid", owner.ProcessID);
                    waiting = (bool)(await probe.ExecuteScalarAsync(cancellationToken))!;
                    if (!waiting) await Task.Delay(20, cancellationToken);
                }
                Assert.True(waiting, "Transition must wait on the profile lock before changing readiness");
                Assert.False(transition.IsCompleted);
            }
            finally
            {
                await runtimeTransaction.RollbackAsync(cancellationToken);
                await transition;
                await ownerTransaction.RollbackAsync(cancellationToken);
            }
        }
        Assert.Equal(pending, await Snapshot());
        await using (var locks = new NpgsqlCommand("SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory' AND classid=1162235478 AND objid=1 AND objsubid=2)", owner))
            Assert.Equal(true, await locks.ExecuteScalarAsync(cancellationToken));
        await using (var transaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await Execute(owner, "DO $visibility$ BEGIN " + ready + "; IF enrollment_execution.profile4_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Ready update is not visible inside the same owner DO'; END IF; END $visibility$;");
            await transaction.RollbackAsync(cancellationToken);
        }
        await IsReady(false);
        Assert.Equal(pending, await Snapshot());
        // This directly tests the trusted-owner transition primitive, NOT history attestation.
        await using (var transaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await Execute(owner, profileLock);
            await Execute(owner, ready);
            await transaction.CommitAsync(cancellationToken);
        }
        await IsReady(true);
        var active = await Snapshot();
        // Test-admin-equivalent owner drift is rollback-only; the predicate is not a catalog attestation.
        foreach (var mutation in new[] {
            "UPDATE enrollment_execution.profile4_readiness SET attestation_manifest_sha256=decode(repeat('cd',32),'hex')",
            "UPDATE enrollment_execution.profile4_readiness SET ready_by='another_owner'",
            "DELETE FROM enrollment_execution.profile4_readiness" })
        {
            await using var transaction = await owner.BeginTransactionAsync(cancellationToken);
            await Execute(owner, "ALTER TABLE enrollment_execution.profile4_readiness DISABLE TRIGGER profile4_readiness_transition");
            await Execute(owner, mutation);
            await IsReady(false);
            await transaction.RollbackAsync(cancellationToken);
            await IsReady(true);
            Assert.Equal(active, await Snapshot());
        }
        await using (var transaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await Execute(owner, "ALTER TABLE enrollment_execution.profile4_readiness ENABLE ROW LEVEL SECURITY");
            await IsReady(false);
            await transaction.RollbackAsync(cancellationToken);
        }
        await IsReady(true);
        await Reject(owner, ready);
        const string close = "UPDATE enrollment_execution.profile4_readiness SET state='PendingHistoryAudit',generation=2,installation_nonce='22222222-2222-2222-2222-222222222222',pending_at=statement_timestamp(),ready_at=NULL,ready_by=NULL";
        await Reject(owner, close.Replace("generation=2", "generation=3", StringComparison.Ordinal));
        await Reject(owner, close.Replace("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111", StringComparison.Ordinal));
        Assert.Equal(active, await Snapshot());
        await using (var transaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await Execute(owner, profileLock);
            await Execute(owner, close);
            await transaction.CommitAsync(cancellationToken);
        }
        await IsReady(false);
        await using var state = new NpgsqlCommand("SELECT state='PendingHistoryAudit' AND generation=2 AND ready_at IS NULL AND ready_by IS NULL FROM enrollment_execution.profile4_readiness", owner);
        Assert.Equal(true, await state.ExecuteScalarAsync(cancellationToken));
        await VerifyReadinessAuditSplitAsync(owner, runtime, statusConnection, deliveryConnection, environment, cancellationToken);
        await VerifyHistoryTransitionAsync(owner, admin, runtimeConnection, environment, cancellationToken);
        await VerifyReadinessSnapshotAsync(owner, runtimeConnection, statusConnection, deliveryConnection, environment, cancellationToken);
        await VerifyPublicationCandidateAsync(owner, admin, runtimeConnection, environment, cancellationToken);
    }
}
