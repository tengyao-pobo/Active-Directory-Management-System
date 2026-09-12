using System.Data;
using ItManagement.EnrollmentGrantDelivery;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData("EnrollmentGrantStatusRefresh")]
    [InlineData("EnrollmentGrantDelivery")]
    public async Task ClosedDeliveryPoolGateRejectsReadinessAndNeverInvokesOperation(string purpose)
    {
        // Existing restricted synthetic API login deliberately has no profile4 delivery capability.
        // This exercises the real connection/transaction path, not completed profile4 attestation.
        await using var source = NpgsqlDataSource.Create(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")!);
        var owner = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Username!;
        var pool = new PostgresEnrollmentDeliveryPool(source, Guid.NewGuid(), owner, "unprovisioned_delivery_definer", purpose);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => pool.VerifyAsync(CancellationToken.None));
        Assert.Equal("EnrollmentDeliveryPrivilegeAuditFailed", error.Message);

        var called = false;
        var result = await pool.RunAsync((_, _, _) =>
        {
            called = true;
            return Task.FromResult("Accepted");
        }, () => "Unknown", value => value == "Accepted", CancellationToken.None);
        Assert.Equal("Unknown", result);
        Assert.False(called);

        // Failed attestation must dispose its transaction and release the shared deployment lock.
        await using var connection = await source.OpenConnectionAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        await using var command = new NpgsqlCommand(
            "SELECT pg_catalog.pg_try_advisory_xact_lock(1162235478,1)", connection, transaction);
        Assert.Equal(true, await command.ExecuteScalarAsync());
    }

    [Theory]
    [InlineData("EnrollmentGrantStatusRefresh")]
    [InlineData("EnrollmentGrantDelivery")]
    public async Task DeliveryPoolWaitsForDeploymentLockBeforeClosedGateAndPropagatesCancellation(string purpose)
    {
        await using var source = NpgsqlDataSource.Create(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")!);
        var owner = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Username!;
        var pool = new PostgresEnrollmentDeliveryPool(source, Guid.NewGuid(), owner, "unprovisioned_delivery_definer", purpose);
        await using var deployment = await source.OpenConnectionAsync();
        await using var transaction = await deployment.BeginTransactionAsync(IsolationLevel.Serializable);
        await using (var locking = new NpgsqlCommand(
            "SELECT pg_catalog.pg_advisory_xact_lock(1162235478,1)", deployment, transaction))
            await locking.ExecuteNonQueryAsync();

        // Without the shared lock first, the false gate would immediately produce an audit error.
        // A separate physical connection instead waits for deployment until explicitly cancelled.
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pool.VerifyAsync(cancellation.Token));
        await transaction.RollbackAsync();

        // Cancellation leaves no poisoned transaction: a new verification reaches the closed gate.
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => pool.VerifyAsync(CancellationToken.None));
        Assert.Equal("EnrollmentDeliveryPrivilegeAuditFailed", error.Message);
    }
}
