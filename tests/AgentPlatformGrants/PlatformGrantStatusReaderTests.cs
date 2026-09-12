using System.Data;
using Npgsql;

namespace ItManagement.AgentPlatformGrants.Tests;

public sealed class PlatformGrantStatusReaderTests
{
    [Theory]
    [InlineData((short)2, false)]
    [InlineData((short)3, true)]
    [InlineData((short)4, true)]
    [InlineData((short)5, false)]
    public void RevokerAcceptsOnlyTheTwoStagedDeploymentProfiles(short version, bool expected) =>
        Assert.Equal(expected, PostgresPlatformGrantRevocationRepository.AcceptsAuditProfile(version));

    [Theory]
    [InlineData((short)2, false)]
    [InlineData((short)3, true)]
    [InlineData((short)4, true)]
    [InlineData((short)5, false)]
    public void IssuerAcceptsOnlyTheTwoStagedDeploymentProfiles(short version, bool expected) =>
        Assert.Equal(expected, PostgresPlatformGrantRepository.AcceptsAuditProfile(version));

    [Theory]
    [InlineData((short)1, "read_initial_enrollment_grant_status(@expected_environment_id,@operation_id,@grant_id,@directory_object_id,@device_id,@mapping_created_at,@token_sha256,@authorization_digest,@created_at,@expires_at)", 10)]
    [InlineData((short)2, "read_initial_enrollment_grant_status(@expected_environment_id,@operation_id,@grant_id,@directory_object_id,@device_id,@mapping_created_at,@token_sha256,@authorization_digest,@created_at,@expires_at,@issue_contract_version,@mint_permit_not_after)", 12)]
    public void ReadCommandUsesTheVersionedStatusFunctionAndBindsTheEntireReceipt(
        short version, string expectedCall, int parameterCount)
    {
        var receipt = Receipt(version);
        using var command = new NpgsqlCommand();

        PostgresPlatformGrantStatusReader.ConfigureReadCommand(command, receipt, receipt.EnvironmentId);

        Assert.Contains(expectedCall, command.CommandText, StringComparison.Ordinal);
        Assert.Equal(parameterCount, command.Parameters.Count);
        Assert.Equal(receipt.EnvironmentId, command.Parameters["expected_environment_id"].Value);
        Assert.Equal(receipt.OperationId, command.Parameters["operation_id"].Value);
        Assert.Equal(receipt.GrantId, command.Parameters["grant_id"].Value);
        Assert.Equal(receipt.DirectoryObjectId, command.Parameters["directory_object_id"].Value);
        Assert.Equal(receipt.DeviceId, command.Parameters["device_id"].Value);
        Assert.Equal(receipt.MappingCreatedAt, command.Parameters["mapping_created_at"].Value);
        Assert.Equal(receipt.GetTokenSha256(), Assert.IsType<byte[]>(command.Parameters["token_sha256"].Value));
        Assert.Equal(receipt.GetAuthorizationDigest(), Assert.IsType<byte[]>(command.Parameters["authorization_digest"].Value));
        Assert.Equal(receipt.CreatedAt, command.Parameters["created_at"].Value);
        Assert.Equal(receipt.ExpiresAt, command.Parameters["expires_at"].Value);
        if (version == 2)
        {
            Assert.Equal((short)2, command.Parameters["issue_contract_version"].Value);
            Assert.Equal(receipt.MintPermitNotAfter, command.Parameters["mint_permit_not_after"].Value);
        }
    }

    [Fact]
    public void StartupGateNamesOnlyTheTwoStatusFunctionsAndExplicitlyDeniesMutatingCapabilities()
    {
        var sql = PostgresPlatformGrantStatusReader.AuditSql;

        Assert.Equal(2, Count(sql, "has_function_privilege(SESSION_USER,'agent_private.read_initial_enrollment_grant_status("));
        Assert.Equal(2, Count(sql, "NOT pg_catalog.has_function_privilege(SESSION_USER,'agent_private.issue_initial_enrollment_grant("));
        Assert.Equal(2, Count(sql, "NOT pg_catalog.has_function_privilege(SESSION_USER,'agent_private.read_initial_enrollment_grant("));
        Assert.Equal(2, Count(sql, "NOT pg_catalog.has_function_privilege(SESSION_USER,'agent_private.revoke_initial_enrollment_grant("));
    }

    [Fact]
    public async Task StatusResponseUsesTheSharedStrictReceiptNormalizer()
    {
        var receipt = Receipt(2);
        await using var reader = Reader(receipt);

        var result = await PostgresPlatformGrantRevocationRepository.ReadResponseAsync(
            reader, receipt, CancellationToken.None);

        Assert.Equal(PlatformGrantEffectiveState.Available, result.State);
        Assert.Equal(PlatformGrantDiagnostic.None, result.Diagnostic);
        Assert.Equal(receipt.CreatedAt.AddSeconds(1), result.ObservedAt);
        Assert.Null(result.StateChangedAt);
    }

    [Theory]
    [InlineData("changed-environment")]
    [InlineData("changed-deadline")]
    [InlineData("unknown-state")]
    [InlineData("second-row")]
    public async Task StatusResponseFailsClosedForAnUnboundOrAmbiguousRow(string variant)
    {
        var receipt = Receipt(2);
        await using var reader = Reader(receipt, variant);

        var result = await PostgresPlatformGrantRevocationRepository.ReadResponseAsync(
            reader, receipt, CancellationToken.None);

        Assert.Equal(PlatformGrantEffectiveState.Unknown, result.State);
        Assert.Equal(PlatformGrantDiagnostic.ResponseUnavailable, result.Diagnostic);
        Assert.Null(result.ObservedAt);
        Assert.Null(result.StateChangedAt);
    }

    [Fact]
    public async Task StatusResponseRequiresExactlyOneRow()
    {
        var receipt = Receipt(1);
        await using var reader = Reader(receipt, "no-row");

        var result = await PostgresPlatformGrantRevocationRepository.ReadResponseAsync(
            reader, receipt, CancellationToken.None);

        Assert.Equal(PlatformGrantEffectiveState.Unknown, result.State);
        Assert.Equal(PlatformGrantDiagnostic.ResponseUnavailable, result.Diagnostic);
    }

    [Fact]
    public async Task WrongEnvironmentIsRejectedBeforeOpeningAConnection()
    {
        await using var dataSource = NpgsqlDataSource.Create(
            "Host=127.0.0.1;Port=1;Database=unused;Username=unused;Password=unused;Timeout=1");
        var receipt = Receipt(2);
        var statusReader = new PostgresPlatformGrantStatusReader(dataSource, Guid.NewGuid());

        var result = await statusReader.ReadAsync(receipt, CancellationToken.None);

        Assert.Equal(PlatformGrantEffectiveState.Unknown, result.State);
        Assert.Equal(PlatformGrantDiagnostic.OperationConflict, result.Diagnostic);
    }

    private static DataTableReader Reader(PlatformGrantReceipt receipt, string? variant = null)
    {
        var table = new DataTable();
        foreach (var (name, type) in Columns()) table.Columns.Add(name, type);
        if (variant != "no-row")
        {
            var values = Row(receipt);
            if (variant == "changed-environment") values[2] = Guid.NewGuid();
            if (variant == "changed-deadline") values[13] = receipt.MintPermitNotAfter!.Value.AddSeconds(1);
            if (variant == "unknown-state") values[0] = "FutureState";
            table.Rows.Add(values);
            if (variant == "second-row") table.Rows.Add((object[])values.Clone());
        }
        return table.CreateDataReader();
    }

    private static object[] Row(PlatformGrantReceipt receipt) =>
    [
        "Available", "None", receipt.EnvironmentId, receipt.OperationId, receipt.GrantId,
        receipt.DirectoryObjectId, receipt.DeviceId, receipt.MappingCreatedAt,
        receipt.GetTokenSha256(), receipt.GetAuthorizationDigest(), receipt.CreatedAt, receipt.ExpiresAt,
        receipt.IssueContractVersion, receipt.MintPermitNotAfter is { } deadline ? deadline : DBNull.Value,
        receipt.CreatedAt.AddSeconds(1), DBNull.Value
    ];

    private static IEnumerable<(string Name, Type Type)> Columns() =>
    [
        ("state", typeof(string)), ("diagnostic_code", typeof(string)), ("environment_id", typeof(Guid)),
        ("operation_id", typeof(Guid)), ("grant_id", typeof(Guid)), ("directory_object_id", typeof(Guid)),
        ("device_id", typeof(Guid)), ("mapping_created_at", typeof(DateTimeOffset)),
        ("token_sha256", typeof(byte[])), ("authorization_digest", typeof(byte[])),
        ("created_at", typeof(DateTimeOffset)), ("expires_at", typeof(DateTimeOffset)),
        ("issue_contract_version", typeof(short)), ("mint_permit_not_after", typeof(DateTimeOffset)),
        ("observed_at", typeof(DateTimeOffset)), ("state_changed_at", typeof(DateTimeOffset))
    ];

    private static PlatformGrantReceipt Receipt(short version)
    {
        var created = new DateTimeOffset(2026, 9, 12, 8, 0, 0, TimeSpan.Zero);
        return new PlatformGrantReceipt(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            created.AddSeconds(-1), created, created.AddMinutes(10), version,
            version == 2 ? created.AddSeconds(30) : null,
            Enumerable.Range(0, 32).Select(value => (byte)value).ToArray(),
            Enumerable.Range(32, 32).Select(value => (byte)value).ToArray());
    }

    private static int Count(string value, string needle) =>
        (value.Length - value.Replace(needle, string.Empty, StringComparison.Ordinal).Length) / needle.Length;
}
