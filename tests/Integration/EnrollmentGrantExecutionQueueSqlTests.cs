using ItManagement.EnrollmentGrantExecution;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData(1, 2)]
    [InlineData(int.MaxValue, int.MaxValue)]
    public async Task ExpiredQueueClaimsUseNewTokensAndKeepSaturatedHistory(int oldAttempt, int expectedAttempt)
    {
        var operation = await QueuedJournalOperation();
        await using var profile = await ProvisionExecutionRuntime(operation.EnvironmentId);
        var oldToken = Guid.NewGuid();
        // Construct historical scheduling data as the isolated fixture owner, without disabling constraints.
        await using (var fixture = Db())
        {
            await using var transaction = await fixture.Database.BeginTransactionAsync();
            await fixture.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO enrollment_execution.work_queue
                  (environment_id,operation_id,state,attempt,next_attempt_at,seeded_at)
                VALUES({operation.EnvironmentId},{operation.Id},'Ready',0,clock_timestamp(),clock_timestamp());
                INSERT INTO enrollment_execution.claim_leases
                  (claim_token,environment_id,operation_id,attempt,claimed_at,lease_until)
                SELECT {oldToken},{operation.EnvironmentId},{operation.Id},{oldAttempt},
                  moment - interval '121 seconds', moment - interval '1 second'
                FROM (SELECT clock_timestamp() moment) source;
                UPDATE enrollment_execution.work_queue SET state='Claimed',attempt={oldAttempt},active_claim_token={oldToken}
                WHERE environment_id={operation.EnvironmentId} AND operation_id={operation.Id};
                """);
            await transaction.CommitAsync();
        }
        var queue = await OpenWorkQueue(profile, operation.EnvironmentId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        Assert.Equal(EnrollmentWorkClaimOutcome.StaleClaim, (await queue.ClaimNextAsync(oldToken, timeout.Token)).Outcome);
        var newToken = Guid.NewGuid();
        var result = await queue.ClaimNextAsync(newToken, timeout.Token);
        Assert.Equal(EnrollmentWorkClaimOutcome.Claimed, result.Outcome);
        Assert.Equal(expectedAttempt, result.Claim!.Attempt);
        Assert.Equal(operation.Id, result.Claim.OperationId);
        Assert.Equal(newToken, result.Claim.ClaimToken);
        Assert.Equal(EnrollmentWorkClaimOutcome.StaleClaim, (await queue.ClaimNextAsync(oldToken, timeout.Token)).Outcome);
        var oldClaim = result.Claim with { ClaimToken = oldToken, Attempt = oldAttempt };
        Assert.Equal(EnrollmentWorkTransitionOutcome.StaleClaim, (await queue.CompleteAsync(oldClaim, timeout.Token)).Outcome);
        Assert.Equal(EnrollmentWorkTransitionOutcome.StaleClaim, (await queue.DeferAsync(oldClaim, EnrollmentWorkRetryReason.Retryable, timeout.Token)).Outcome);
        Assert.Equal(EnrollmentWorkClaimOutcome.Existing, (await queue.ClaimNextAsync(newToken, timeout.Token)).Outcome);
        await using var verification = Db();
        Assert.Equal(2L, await verification.Database.SqlQuery<long>($"""
            SELECT count(*) AS "Value" FROM enrollment_execution.claim_leases WHERE operation_id={operation.Id}
            """).SingleAsync(timeout.Token));
    }

    [Theory]
    [InlineData("UPDATE enrollment_execution.claim_leases SET attempt=attempt+1 WHERE claim_token={0}")]
    [InlineData("DELETE FROM enrollment_execution.claim_leases WHERE claim_token={0}")]
    [InlineData("DELETE FROM enrollment_execution.work_queue WHERE active_claim_token={0}")]
    public async Task QueueAndTokenHistoryCannotBeRewrittenEvenByFixtureOwner(string mutation)
    {
        var operation = await QueuedJournalOperation();
        await using var profile = await ProvisionExecutionRuntime(operation.EnvironmentId);
        var queue = await OpenWorkQueue(profile, operation.EnvironmentId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var token = Guid.NewGuid();
        Assert.Equal(EnrollmentWorkClaimOutcome.Claimed, (await queue.ClaimNextAsync(token, timeout.Token)).Outcome);
        await using var fixture = Db();
        await using var transaction = await fixture.Database.BeginTransactionAsync(timeout.Token);
        var error = await Assert.ThrowsAsync<PostgresException>(() =>
            fixture.Database.ExecuteSqlRawAsync(mutation, new object[] { token }, timeout.Token));
        Assert.Equal("55000", error.SqlState);
    }

    [Fact]
    public async Task OutboxCannotBeMarkedDeliveredWhileItsQueueClaimIsActive()
    {
        var operation = await QueuedJournalOperation();
        await using var profile = await ProvisionExecutionRuntime(operation.EnvironmentId);
        var queue = await OpenWorkQueue(profile, operation.EnvironmentId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        Assert.Equal(EnrollmentWorkClaimOutcome.Claimed, (await queue.ClaimNextAsync(Guid.NewGuid(), timeout.Token)).Outcome);
        await using var fixture = Db();
        await using var transaction = await fixture.Database.BeginTransactionAsync(timeout.Token);
        var error = await Assert.ThrowsAsync<PostgresException>(async () =>
        {
            await fixture.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE public."Outbox" SET "DeliveredAt"=clock_timestamp() WHERE "Id"={operation.Id};
                SET CONSTRAINTS ALL IMMEDIATE;
                """, timeout.Token);
        });
        Assert.Equal("23514", error.SqlState);
    }

    [Fact]
    public async Task UnclaimedOutboxCannotBeMarkedDelivered()
    {
        var operation = await QueuedJournalOperation();
        await using var profile = await ProvisionExecutionRuntime(operation.EnvironmentId);
        await using var fixture = Db();
        await using var transaction = await fixture.Database.BeginTransactionAsync();
        var error = await Assert.ThrowsAsync<PostgresException>(() => fixture.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE public."Outbox" SET "DeliveredAt"=clock_timestamp() WHERE "Id"={operation.Id};
            SET CONSTRAINTS ALL IMMEDIATE;
            """));
        Assert.Equal("23514", error.SqlState);
    }

    [Theory]
    [InlineData("REVOKE EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid) FROM \"{queue}\"")]
    [InlineData("GRANT EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid) TO \"{queue}\" WITH GRANT OPTION")]
    [InlineData("GRANT EXECUTE ON FUNCTION public.directory_database_access(uuid,uuid) TO \"{queue}\"")]
    [InlineData("GRANT SELECT ON public.\"Plans\" TO \"{queue}\" WITH GRANT OPTION")]
    [InlineData("GRANT SELECT(\"RequesterId\") ON public.\"EnrollmentGrantOperations\" TO \"{queue}\" WITH GRANT OPTION")]
    [InlineData("ALTER FUNCTION public.has_environment_membership(uuid,uuid) VOLATILE")]
    [InlineData("ALTER FUNCTION public.has_environment_membership(uuid,uuid) OWNER TO \"{queue}\"")]
    [InlineData("CREATE OR REPLACE FUNCTION public.has_environment_membership(p_environment_id uuid,p_principal_id uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=off AS 'SELECT true'")]
    [InlineData("ALTER TRIGGER work_queue_outbox_consistent ON public.\"Outbox\" RENAME TO unexpected_queue_trigger")]
    public async Task QueuePrivilegeOrGuardDriftFailsAuditBeforeClaim(string mutation)
    {
        var operation = await QueuedJournalOperation();
        await using var profile = await ProvisionExecutionRuntime(operation.EnvironmentId);
        await using var fixture = Db();
        await using var transaction = await fixture.Database.BeginTransactionAsync();
        await fixture.Database.ExecuteSqlRawAsync(mutation.Replace("{queue}", profile.QueueDefinerRole, StringComparison.Ordinal));
        var connection = fixture.Database.GetDbConnection();
        await using (var audit = connection.CreateCommand())
        {
            audit.Transaction = Microsoft.EntityFrameworkCore.Storage.DbContextTransactionExtensions.GetDbTransaction(transaction);
            audit.CommandText = "SELECT is_valid FROM enrollment_execution.audit_execution_privileges(@env)";
            audit.Parameters.Add(new NpgsqlParameter("env", operation.EnvironmentId));
            Assert.Equal(false, await audit.ExecuteScalarAsync());
        }
        await using var wrapper = connection.CreateCommand();
        wrapper.Transaction = Microsoft.EntityFrameworkCore.Storage.DbContextTransactionExtensions.GetDbTransaction(transaction);
        wrapper.CommandText = $"""
            SET LOCAL SESSION AUTHORIZATION "{profile.RuntimeRole}";
            SELECT * FROM enrollment_execution.claim_next(@env,@token)
            """;
        wrapper.Parameters.Add(new NpgsqlParameter("env", operation.EnvironmentId));
        wrapper.Parameters.Add(new NpgsqlParameter("token", Guid.NewGuid()));
        var error = await Assert.ThrowsAsync<PostgresException>(() => wrapper.ExecuteReaderAsync());
        Assert.Equal("42501", error.SqlState);
    }
}
