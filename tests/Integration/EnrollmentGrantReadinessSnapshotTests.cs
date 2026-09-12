using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static async Task VerifyReadinessSnapshotAsync(NpgsqlConnection owner, string executionConnection,
        string statusConnection, string deliveryConnection, Guid environment, CancellationToken cancellationToken)
    {
        var cases = new[] {
            (Connection: executionConnection, Sql: "SELECT is_valid FROM enrollment_execution.audit_execution_privileges(@environment)", DirectAudit: true),
            (Connection: executionConnection, Sql: "SELECT outcome FROM enrollment_execution.claim_next(@environment,NULL::uuid)", DirectAudit: false),
            (Connection: statusConnection, Sql: "SELECT * FROM enrollment_execution.read_grant_status_receipt(@environment,NULL::uuid)", DirectAudit: false),
            (Connection: deliveryConnection, Sql: "SELECT * FROM enrollment_execution.read_grant_delivery(@environment,NULL::uuid,NULL::uuid,NULL::text)", DirectAudit: false)
        };
        foreach (var test in cases)
        {
            // Trusted test-only owner reset between independent stale-snapshot scenarios.
            await using (var ready = new NpgsqlCommand("UPDATE enrollment_execution.profile4_readiness SET state='Ready',ready_at=statement_timestamp(),ready_by=session_user WHERE state='PendingHistoryAudit'", owner))
                await ready.ExecuteNonQueryAsync(cancellationToken);
            await using var runtime = new NpgsqlConnection(test.Connection);
            await runtime.OpenAsync(cancellationToken);
            await using (var stale = await runtime.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken))
            {
                // Do not establish S0 through the repaired audit: that would correctly
                // retain shared advisory and readiness row locks, preventing owner close.
                await using var snapshot = new NpgsqlCommand("SELECT count(*) FROM pg_catalog.pg_class", runtime);
                Assert.True((long)(await snapshot.ExecuteScalarAsync(cancellationToken))! > 0);
                await using var close = new NpgsqlCommand("UPDATE enrollment_execution.profile4_readiness SET state='PendingHistoryAudit',generation=generation+1,installation_nonce=@nonce,pending_at=statement_timestamp(),ready_at=NULL,ready_by=NULL", owner) { CommandTimeout = 3 };
                close.Parameters.AddWithValue("nonce", Guid.NewGuid());
                await close.ExecuteNonQueryAsync(cancellationToken);
                await using var command = new NpgsqlCommand(test.Sql, runtime) { CommandTimeout = 3 };
                command.Parameters.AddWithValue("environment", environment);
                var rejected = await Assert.ThrowsAsync<PostgresException>(async () => { await command.ExecuteScalarAsync(cancellationToken); });
                Assert.Equal("40001", rejected.SqlState);
                await stale.RollbackAsync(cancellationToken);
            }
            await using (var fresh = await runtime.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken))
            {
                await using var command = new NpgsqlCommand(test.Sql, runtime);
                command.Parameters.AddWithValue("environment", environment);
                if (test.DirectAudit) Assert.Equal(false, await command.ExecuteScalarAsync(cancellationToken));
                else
                {
                    var rejected = await Assert.ThrowsAsync<PostgresException>(async () => { await command.ExecuteScalarAsync(cancellationToken); });
                    Assert.Equal("42501", rejected.SqlState);
                    Assert.Equal(test.Connection == executionConnection ? "Execution queue capability is unavailable." : "Enrollment delivery privilege audit failed.", rejected.MessageText);
                }
                await fresh.RollbackAsync(cancellationToken);
            }
            await using var locks = new NpgsqlCommand("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory')", runtime);
            Assert.Equal(false, await locks.ExecuteScalarAsync(cancellationToken));
        }
    }
}
