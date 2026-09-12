using System.Data;
using Xunit;

namespace ItManagement.EnrollmentGrantExecution.Tests;

public sealed class PostgresExecutionQueueCodecTests
{
    private static readonly Guid EnvironmentId = Guid.Parse("ad900000-0000-0000-0000-000000000001");
    private static readonly Guid Token = Guid.Parse("ad900000-0000-0000-0000-000000000002");
    private static readonly DateTime Now = new(2026, 9, 12, 0, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData("Claimed")]
    [InlineData("Existing")]
    public async Task ActiveClaimBindsTheRequestedEnvironmentAndToken(string outcome)
    {
        using var table = ClaimTable(outcome);
        using var reader = table.CreateDataReader();
        var result = await PostgresExecutionQueueCodec.ReadClaimAsync(reader, EnvironmentId, Token, CancellationToken.None);
        Assert.Equal(outcome, result.Outcome.ToString());
        Assert.Equal(Token, result.Claim!.ClaimToken);
        Assert.Equal(EnvironmentId, result.Claim.EnvironmentId);
        Assert.Equal(TimeSpan.FromSeconds(120), result.Claim.LeaseUntil - result.Claim.ClaimedAt);
    }

    [Theory]
    [InlineData("environment")]
    [InlineData("token")]
    [InlineData("expired")]
    [InlineData("extended")]
    [InlineData("attempt")]
    [InlineData("numeric-outcome")]
    [InlineData("null-payload")]
    [InlineData("multiple-rows")]
    [InlineData("column-name")]
    [InlineData("sub-microsecond")]
    [InlineData("negative-infinity")]
    [InlineData("positive-infinity")]
    public async Task MalformedOrReboundClaimsAreUnknown(string defect)
    {
        using var table = ClaimTable("Existing");
        var row = table.Rows[0];
        switch (defect)
        {
            case "environment": row[3] = Guid.NewGuid(); break;
            case "token": row[5] = Guid.NewGuid(); break;
            case "expired": row[2] = Now.AddSeconds(120); break;
            case "extended": row[8] = Now.AddSeconds(121); break;
            case "attempt": row[6] = 0; break;
            case "numeric-outcome": row[1] = "1"; break;
            case "null-payload": row[4] = DBNull.Value; break;
            case "multiple-rows": table.ImportRow(row); break;
            case "column-name": table.Columns[4].ColumnName = "untrusted_operation"; break;
            case "sub-microsecond": row[2] = Now.AddTicks(1); break;
            case "negative-infinity": row[7] = DateTime.MinValue; row[8] = DateTime.MinValue.AddSeconds(120); row[2] = DateTime.MinValue.AddSeconds(1); break;
            case "positive-infinity": row[8] = DateTime.MaxValue; break;
        }
        using var reader = table.CreateDataReader();
        var result = await PostgresExecutionQueueCodec.ReadClaimAsync(reader, EnvironmentId, Token, CancellationToken.None);
        Assert.Equal(EnrollmentWorkClaimOutcome.OutcomeUnknown, result.Outcome);
        Assert.Null(result.Claim);
    }

    [Theory]
    [InlineData("NoWork")]
    [InlineData("AlreadyDeferred")]
    [InlineData("AlreadyCompleted")]
    [InlineData("StaleClaim")]
    [InlineData("TokenConflict")]
    public async Task NonAssignmentsMustNotCarryAnOperation(string outcome)
    {
        using var table = ClaimTable(outcome);
        for (var column = 3; column < 9; column++) table.Rows[0][column] = DBNull.Value;
        using (var reader = table.CreateDataReader())
        {
            var result = await PostgresExecutionQueueCodec.ReadClaimAsync(reader, EnvironmentId, Token, CancellationToken.None);
            Assert.Equal(outcome, result.Outcome.ToString());
            Assert.Null(result.Claim);
        }
        table.Rows[0][4] = Guid.NewGuid();
        using var leaked = table.CreateDataReader();
        Assert.Equal(EnrollmentWorkClaimOutcome.OutcomeUnknown,
            (await PostgresExecutionQueueCodec.ReadClaimAsync(leaked, EnvironmentId, Token, CancellationToken.None)).Outcome);
    }

    [Theory]
    [InlineData("Deferred", 5, true)]
    [InlineData("Deferred", 0, false)]
    [InlineData("Deferred", 301, false)]
    [InlineData("AlreadyDeferred", -5, true)]
    [InlineData("AlreadyDeferred", 301, false)]
    [InlineData("Completed", null, true)]
    [InlineData("Completed", 5, false)]
    [InlineData("3", null, false)]
    public async Task TransitionShapePreservesRetryTimeAndRejectsFalseCompletion(string outcome, int? retrySeconds, bool valid)
    {
        using var table = Table(("contract_version", typeof(short)), ("outcome", typeof(string)),
            ("queried_at", typeof(DateTime)), ("next_attempt_at", typeof(DateTime)));
        table.Rows.Add((short)1, outcome, Now, retrySeconds is { } seconds ? Now.AddSeconds(seconds) : DBNull.Value);
        using var reader = table.CreateDataReader();
        var result = await PostgresExecutionQueueCodec.ReadTransitionAsync(reader, CancellationToken.None);
        Assert.Equal(valid, result.Outcome != EnrollmentWorkTransitionOutcome.OutcomeUnknown);
    }

    [Theory]
    [InlineData(2, false)]
    [InlineData(2, true)]
    [InlineData(3, false)]
    [InlineData(3, true)]
    public async Task InfiniteTransitionTimesAreUnknown(int column, bool positive)
    {
        using var table = Table(("contract_version", typeof(short)), ("outcome", typeof(string)),
            ("queried_at", typeof(DateTime)), ("next_attempt_at", typeof(DateTime)));
        table.Rows.Add((short)1, "AlreadyDeferred", Now, Now.AddSeconds(5));
        table.Rows[0][column] = positive ? DateTime.MaxValue : DateTime.MinValue;
        using var reader = table.CreateDataReader();
        Assert.Equal(EnrollmentWorkTransitionOutcome.OutcomeUnknown,
            (await PostgresExecutionQueueCodec.ReadTransitionAsync(reader, CancellationToken.None)).Outcome);
    }

    private static DataTable ClaimTable(string outcome)
    {
        var table = Table(("contract_version", typeof(short)), ("outcome", typeof(string)), ("queried_at", typeof(DateTime)),
            ("environment_id", typeof(Guid)), ("operation_id", typeof(Guid)), ("claim_token", typeof(Guid)),
            ("attempt", typeof(int)), ("claimed_at", typeof(DateTime)), ("lease_until", typeof(DateTime)));
        table.Rows.Add((short)1, outcome, Now.AddSeconds(1), EnvironmentId, Guid.NewGuid(), Token, 1, Now, Now.AddSeconds(120));
        return table;
    }

    private static DataTable Table(params (string Name, Type Type)[] columns)
    {
        var table = new DataTable();
        foreach (var (name, type) in columns)
        {
            var column = table.Columns.Add(name, type);
            if (type == typeof(DateTime)) column.DateTimeMode = DataSetDateTime.Utc;
        }
        return table;
    }
}
