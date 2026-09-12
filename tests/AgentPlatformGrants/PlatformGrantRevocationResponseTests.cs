namespace ItManagement.AgentPlatformGrants.Tests;

public sealed class PlatformGrantRevocationResponseTests
{
    public static IEnumerable<object[]> ReceiptFieldChanges()
    {
        foreach (var field in new[] { "environment", "issue", "grant", "directory", "device", "mapping", "token", "digest", "created", "expires" })
            foreach (var missing in new[] { false, true }) yield return [field, missing];
    }

    public static IEnumerable<object[]> SuccessfulRevocations()
    {
        foreach (var outcome in new[] { "Completed", "AlreadyCompleted" })
            foreach (var disposition in new[] { "Revoked", "Expired", "Consumed", "AlreadyRevoked" })
                yield return [outcome, disposition];
    }

    [Theory]
    [InlineData("Available", PlatformGrantEffectiveState.Available)]
    [InlineData("Expired", PlatformGrantEffectiveState.Expired)]
    [InlineData("Consumed", PlatformGrantEffectiveState.Consumed)]
    [InlineData("Revoked", PlatformGrantEffectiveState.Revoked)]
    public void ReadAcceptsKnownStateOnlyWithTheExactOriginalReceipt(string state, PlatformGrantEffectiveState expected)
    {
        var sample = Sample();
        var row = ReadRow(sample.Receipt) with
        {
            State = state,
            ObservedAt = state == "Expired" ? sample.Receipt.ExpiresAt : sample.Receipt.CreatedAt.AddSeconds(1),
            StateChangedAt = state is "Consumed" or "Revoked" ? sample.Receipt.CreatedAt : null
        };
        var result = PostgresPlatformGrantRevocationRepository.NormalizeRead(row, sample.Receipt);
        Assert.Equal(expected, result.State);
        Assert.Equal(PlatformGrantDiagnostic.None, result.Diagnostic);
        Assert.Equal(row.ObservedAt, result.ObservedAt);
        Assert.Equal(row.StateChangedAt, result.StateChangedAt);
    }

    [Theory]
    [MemberData(nameof(ReceiptFieldChanges))]
    public void ReadRejectsEveryChangedOrMissingReceiptField(string field, bool missing)
    {
        var sample = Sample(); var original = ReadRow(sample.Receipt);
        var changed = Change(original, field, missing);
        var result = PostgresPlatformGrantRevocationRepository.NormalizeRead(changed, sample.Receipt);
        Assert.Equal(PlatformGrantEffectiveState.Unknown, result.State);
        Assert.Equal(PlatformGrantDiagnostic.ResponseUnavailable, result.Diagnostic);
    }

    [Theory]
    [InlineData(null, "None")]
    [InlineData("available", "None")]
    [InlineData("FutureState", "None")]
    [InlineData("Available", null)]
    [InlineData("Available", "ReceiptUnavailable")]
    [InlineData("Available", "FutureDiagnostic")]
    public void ReadRejectsUnknownOrContradictoryStatusPairs(string? state, string? diagnostic)
    {
        var sample = Sample();
        var result = PostgresPlatformGrantRevocationRepository.NormalizeRead(
            ReadRow(sample.Receipt) with { State = state, Diagnostic = diagnostic }, sample.Receipt);
        Assert.Equal(PlatformGrantEffectiveState.Unknown, result.State);
        Assert.Equal(PlatformGrantDiagnostic.ResponseUnavailable, result.Diagnostic);
    }

    [Theory]
    [MemberData(nameof(SuccessfulRevocations))]
    public void RevokePreservesEachTerminalDispositionAndExactReplay(string outcome, string disposition)
    {
        var sample = Sample(); var row = RevokeRow(sample, outcome, disposition);
        var result = PostgresPlatformGrantRevocationRepository.NormalizeRevocation(row, sample.RevokeId, sample.Authorization);
        Assert.Equal(Enum.Parse<PlatformGrantRevocationOutcome>(outcome), result.Outcome);
        Assert.Equal(PlatformGrantDiagnostic.None, result.Diagnostic);
        Assert.NotNull(result.Receipt);
        Assert.Equal(sample.RevokeId, result.Receipt.RevocationOperationId);
        Assert.Equal(sample.Receipt, result.Receipt.IssueReceipt);
        Assert.Equal(Enum.Parse<PlatformGrantRevocationDisposition>(disposition), result.Receipt.Disposition);
        Assert.Equal(row.CompletedAt, result.Receipt.CompletedAt);
        Assert.Equal(row.EffectiveRevokedAt, result.Receipt.EffectiveRevokedAt);
    }

    [Theory]
    [MemberData(nameof(ReceiptFieldChanges))]
    public void RevokeRejectsEveryChangedOrMissingOriginalReceiptField(string field, bool missing)
    {
        var sample = Sample(); var changed = Change(ReadRow(sample.Receipt), field, missing);
        var row = RevokeRow(sample) with
        {
            EnvironmentId = changed.EnvironmentId, IssueOperationId = changed.OperationId,
            GrantId = changed.GrantId, DirectoryObjectId = changed.DirectoryObjectId, DeviceId = changed.DeviceId,
            MappingCreatedAt = changed.MappingCreatedAt, TokenSha256 = changed.TokenSha256,
            IssueAuthorizationDigest = changed.AuthorizationDigest, IssueCreatedAt = changed.CreatedAt, IssueExpiresAt = changed.ExpiresAt
        };
        AssertUnknown(PostgresPlatformGrantRevocationRepository.NormalizeRevocation(row, sample.RevokeId, sample.Authorization));
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("missing-operation")]
    [InlineData("digest")]
    [InlineData("missing-digest")]
    [InlineData("missing-completed")]
    [InlineData("missing-revoked")]
    [InlineData("unknown-disposition")]
    [InlineData("unknown-outcome")]
    [InlineData("failure-diagnostic")]
    [InlineData("consumed-with-revoked-time")]
    public void RevokeRejectsUnboundOrContradictoryCompletion(string variant)
    {
        var sample = Sample(); var valid = RevokeRow(sample);
        var row = variant switch
        {
            "operation" => valid with { RevocationOperationId = Guid.NewGuid() },
            "missing-operation" => valid with { RevocationOperationId = null },
            "digest" => valid with { RevokeAuthorizationDigest = new byte[32] },
            "missing-digest" => valid with { RevokeAuthorizationDigest = null },
            "missing-completed" => valid with { CompletedAt = null },
            "missing-revoked" => valid with { EffectiveRevokedAt = null },
            "unknown-disposition" => valid with { Disposition = "FutureDisposition" },
            "unknown-outcome" => valid with { Outcome = "FutureOutcome" },
            "failure-diagnostic" => valid with { Diagnostic = "OperationConflict" },
            _ => valid with { Disposition = "Consumed" }
        };
        AssertUnknown(PostgresPlatformGrantRevocationRepository.NormalizeRevocation(row, sample.RevokeId, sample.Authorization));
    }

    [Theory]
    [InlineData("ReceiptUnavailable", PlatformGrantDiagnostic.ReceiptUnavailable)]
    [InlineData("OperationConflict", PlatformGrantDiagnostic.OperationConflict)]
    public void UnknownOutcomesRetainDiagnosticsOnlyForTheExactRequest(string diagnostic, PlatformGrantDiagnostic expected)
    {
        var sample = Sample();
        var read = PostgresPlatformGrantRevocationRepository.NormalizeRead(
            ReadRow(sample.Receipt) with { State = "OutcomeUnknown", Diagnostic = diagnostic, ObservedAt = null }, sample.Receipt);
        Assert.Equal(PlatformGrantEffectiveState.Unknown, read.State); Assert.Equal(expected, read.Diagnostic);
        var row = RevokeRow(sample) with
        {
            Outcome = "OutcomeUnknown", Diagnostic = diagnostic, Disposition = null, CompletedAt = null, EffectiveRevokedAt = null
        };
        var result = PostgresPlatformGrantRevocationRepository.NormalizeRevocation(row, sample.RevokeId, sample.Authorization);
        Assert.Equal(PlatformGrantRevocationOutcome.OutcomeUnknown, result.Outcome);
        Assert.Equal(expected, result.Diagnostic); Assert.Null(result.Receipt);
        AssertUnknown(PostgresPlatformGrantRevocationRepository.NormalizeRevocation(
            row with { RevocationOperationId = Guid.NewGuid() }, sample.RevokeId, sample.Authorization));
        AssertUnknown(PostgresPlatformGrantRevocationRepository.NormalizeRevocation(
            row with { Disposition = "Consumed" }, sample.RevokeId, sample.Authorization));
    }

    [Fact]
    public void UnauthorizedResponseMustNotCarryReceiptData()
    {
        var sample = Sample();
        var read = new PlatformGrantStateDatabaseResult("Unauthorized", "PrivilegeAuditFailed", null, null, null, null, null, null, null, null, null, null, null, null);
        Assert.Equal(PlatformGrantDiagnostic.PrivilegeAuditFailed,
            PostgresPlatformGrantRevocationRepository.NormalizeRead(read, sample.Receipt).Diagnostic);
        Assert.Equal(PlatformGrantDiagnostic.ResponseUnavailable,
            PostgresPlatformGrantRevocationRepository.NormalizeRead(read with { GrantId = sample.Receipt.GrantId }, sample.Receipt).Diagnostic);
        var revoke = new PlatformGrantRevocationDatabaseResult("Unauthorized", "PrivilegeAuditFailed", null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null);
        Assert.Equal(PlatformGrantRevocationOutcome.Unauthorized,
            PostgresPlatformGrantRevocationRepository.NormalizeRevocation(revoke, sample.RevokeId, sample.Authorization).Outcome);
        AssertUnknown(PostgresPlatformGrantRevocationRepository.NormalizeRevocation(
            revoke with { GrantId = sample.Receipt.GrantId }, sample.RevokeId, sample.Authorization));
    }

    [Fact]
    public void ReceiptAndAuthorizationOwnTheirBytesAndUseValueEquality()
    {
        var sample = Sample(); var receipt = sample.Receipt;
        var token = receipt.GetTokenSha256(); var digest = receipt.GetAuthorizationDigest();
        var copy = new PlatformGrantReceipt(receipt.EnvironmentId, receipt.OperationId, receipt.GrantId, receipt.DirectoryObjectId,
            receipt.DeviceId, receipt.MappingCreatedAt, receipt.CreatedAt, receipt.ExpiresAt, token, digest);
        Assert.Equal(receipt, copy); Assert.Equal(receipt.GetHashCode(), copy.GetHashCode());
        token[0] ^= 1; digest[0] ^= 1;
        copy.GetTokenSha256()[1] ^= 1; copy.GetAuthorizationDigest()[1] ^= 1;
        Assert.Equal(receipt, copy);
        var different = new PlatformGrantReceipt(receipt.EnvironmentId, receipt.OperationId, receipt.GrantId, receipt.DirectoryObjectId,
            receipt.DeviceId, receipt.MappingCreatedAt, receipt.CreatedAt, receipt.ExpiresAt, token, digest);
        Assert.NotEqual(receipt, different);
        var revokeDigest = Enumerable.Repeat((byte)7, 32).ToArray();
        var authorization = ValidatedGrantRevocationAuthorization.FromValidatedPlan(receipt, revokeDigest);
        revokeDigest[0] = 0; authorization.GetDigest()[1] = 0;
        Assert.All(authorization.GetDigest(), value => Assert.Equal((byte)7, value));
    }

    [Theory]
    [InlineData("missing-observation")]
    [InlineData("observation-before-issue")]
    [InlineData("observation-offset")]
    [InlineData("observation-submicrosecond")]
    [InlineData("observation-max")]
    [InlineData("available-at-expiry")]
    [InlineData("expired-before-expiry")]
    [InlineData("available-with-change")]
    [InlineData("consumed-without-change")]
    [InlineData("revoked-without-change")]
    [InlineData("change-before-issue")]
    [InlineData("change-after-observation")]
    [InlineData("consumed-at-expiry")]
    [InlineData("change-offset")]
    [InlineData("change-submicrosecond")]
    [InlineData("unknown-with-observation")]
    public void ReadRejectsImpossibleOrNoncanonicalSnapshotTimes(string variant)
    {
        var sample = Sample(); var r = sample.Receipt; var valid = ReadRow(r);
        var row = variant switch
        {
            "missing-observation" => valid with { ObservedAt = null },
            "observation-before-issue" => valid with { ObservedAt = r.CreatedAt.AddTicks(-10) },
            "observation-offset" => valid with { ObservedAt = valid.ObservedAt!.Value.ToOffset(TimeSpan.FromHours(8)) },
            "observation-submicrosecond" => valid with { ObservedAt = valid.ObservedAt!.Value.AddTicks(1) },
            "observation-max" => valid with { ObservedAt = DateTimeOffset.MaxValue },
            "available-at-expiry" => valid with { ObservedAt = r.ExpiresAt },
            "expired-before-expiry" => valid with { State = "Expired", ObservedAt = r.ExpiresAt.AddTicks(-10) },
            "available-with-change" => valid with { StateChangedAt = r.CreatedAt },
            "consumed-without-change" => valid with { State = "Consumed" },
            "revoked-without-change" => valid with { State = "Revoked" },
            "change-before-issue" => valid with { State = "Revoked", StateChangedAt = r.CreatedAt.AddTicks(-10) },
            "change-after-observation" => valid with { State = "Revoked", StateChangedAt = valid.ObservedAt!.Value.AddTicks(10) },
            "consumed-at-expiry" => valid with { State = "Consumed", ObservedAt = r.ExpiresAt, StateChangedAt = r.ExpiresAt },
            "change-offset" => valid with { State = "Revoked", StateChangedAt = r.CreatedAt.ToOffset(TimeSpan.FromHours(8)) },
            "change-submicrosecond" => valid with { State = "Revoked", StateChangedAt = r.CreatedAt.AddTicks(1) },
            _ => valid with { State = "OutcomeUnknown", Diagnostic = "ReceiptUnavailable" }
        };
        var result = PostgresPlatformGrantRevocationRepository.NormalizeRead(row, r);
        Assert.Equal(PlatformGrantEffectiveState.Unknown, result.State);
        Assert.Equal(PlatformGrantDiagnostic.ResponseUnavailable, result.Diagnostic);
        Assert.Null(result.ObservedAt); Assert.Null(result.StateChangedAt);
    }

    [Theory]
    [InlineData("completed-before-issue")]
    [InlineData("completed-offset")]
    [InlineData("completed-submicrosecond")]
    [InlineData("completed-min")]
    [InlineData("completed-max")]
    [InlineData("revoked-at-expiry")]
    [InlineData("expired-before-expiry")]
    [InlineData("effective-before-issue")]
    [InlineData("effective-after-completed")]
    [InlineData("effective-offset")]
    [InlineData("effective-submicrosecond")]
    [InlineData("revoked-not-at-completed")]
    [InlineData("expired-not-at-completed")]
    public void RevokeRejectsImpossibleOrNoncanonicalReceiptTimes(string variant)
    {
        var sample = Sample(); var r = sample.Receipt; var valid = RevokeRow(sample);
        var row = variant switch
        {
            "completed-before-issue" => valid with { CompletedAt = r.CreatedAt.AddTicks(-10), EffectiveRevokedAt = r.CreatedAt.AddTicks(-10) },
            "completed-offset" => valid with { CompletedAt = valid.CompletedAt!.Value.ToOffset(TimeSpan.FromHours(8)) },
            "completed-submicrosecond" => valid with { CompletedAt = valid.CompletedAt!.Value.AddTicks(1) },
            "completed-min" => valid with { CompletedAt = DateTimeOffset.MinValue },
            "completed-max" => valid with { CompletedAt = DateTimeOffset.MaxValue },
            "revoked-at-expiry" => valid with { CompletedAt = r.ExpiresAt, EffectiveRevokedAt = r.ExpiresAt },
            "expired-before-expiry" => valid with { Disposition = "Expired", CompletedAt = r.ExpiresAt.AddTicks(-10), EffectiveRevokedAt = r.ExpiresAt.AddTicks(-10) },
            "effective-before-issue" => valid with { Disposition = "AlreadyRevoked", EffectiveRevokedAt = r.CreatedAt.AddTicks(-10) },
            "effective-after-completed" => valid with { Disposition = "AlreadyRevoked", EffectiveRevokedAt = valid.CompletedAt!.Value.AddTicks(10) },
            "effective-offset" => valid with { EffectiveRevokedAt = valid.EffectiveRevokedAt!.Value.ToOffset(TimeSpan.FromHours(8)) },
            "effective-submicrosecond" => valid with { EffectiveRevokedAt = valid.EffectiveRevokedAt!.Value.AddTicks(1) },
            "revoked-not-at-completed" => valid with { EffectiveRevokedAt = r.CreatedAt },
            _ => valid with { Disposition = "Expired", CompletedAt = r.ExpiresAt.AddSeconds(1), EffectiveRevokedAt = r.ExpiresAt }
        };
        foreach (var outcome in new[] { "Completed", "AlreadyCompleted" })
            AssertUnknown(PostgresPlatformGrantRevocationRepository.NormalizeRevocation(row with { Outcome = outcome }, sample.RevokeId, sample.Authorization));
    }

    [Theory]
    [InlineData("Revoked", -10)]
    [InlineData("Expired", 0)]
    [InlineData("Consumed", -10)]
    [InlineData("Consumed", 0)]
    [InlineData("AlreadyRevoked", -10)]
    [InlineData("AlreadyRevoked", 0)]
    public void RevocationTimeBoundaryPreservesValidDisposition(string disposition, long expiryOffsetTicks)
    {
        var sample = Sample(); var completed = sample.Receipt.ExpiresAt.AddTicks(expiryOffsetTicks);
        var row = RevokeRow(sample, disposition: disposition) with
        {
            CompletedAt = completed,
            EffectiveRevokedAt = disposition == "Consumed" ? null : disposition == "AlreadyRevoked" ? sample.Receipt.CreatedAt : completed
        };
        var result = PostgresPlatformGrantRevocationRepository.NormalizeRevocation(row, sample.RevokeId, sample.Authorization);
        Assert.Equal(PlatformGrantRevocationOutcome.Completed, result.Outcome);
        Assert.Equal(Enum.Parse<PlatformGrantRevocationDisposition>(disposition), result.Receipt!.Disposition);
    }

    [Theory]
    [InlineData("mapping-offset")]
    [InlineData("mapping-submicrosecond")]
    [InlineData("mapping-min")]
    [InlineData("mapping-after-issue")]
    [InlineData("created-offset")]
    [InlineData("created-submicrosecond")]
    [InlineData("expires-offset")]
    [InlineData("expires-submicrosecond")]
    [InlineData("expires-max")]
    [InlineData("ttl-short")]
    [InlineData("ttl-long")]
    public void ExactEchoDoesNotValidateAnImpossibleOriginalIssueReceipt(string variant)
    {
        var sample = Sample(); var r = sample.Receipt;
        var mapping = r.MappingCreatedAt; var created = r.CreatedAt; var expires = r.ExpiresAt;
        switch (variant)
        {
            case "mapping-offset": mapping = mapping.ToOffset(TimeSpan.FromHours(8)); break;
            case "mapping-submicrosecond": mapping = mapping.AddTicks(1); break;
            case "mapping-min": mapping = DateTimeOffset.MinValue; break;
            case "mapping-after-issue": mapping = created.AddTicks(10); break;
            case "created-offset": created = created.ToOffset(TimeSpan.FromHours(8)); break;
            case "created-submicrosecond": created = created.AddTicks(1); break;
            case "expires-offset": expires = expires.ToOffset(TimeSpan.FromHours(8)); break;
            case "expires-submicrosecond": expires = expires.AddTicks(1); break;
            case "expires-max": expires = DateTimeOffset.MaxValue; break;
            case "ttl-short": expires = expires.AddTicks(-10); break;
            case "ttl-long": expires = expires.AddTicks(10); break;
        }
        var invalid = new PlatformGrantReceipt(r.EnvironmentId, r.OperationId, r.GrantId, r.DirectoryObjectId,
            r.DeviceId, mapping, created, expires, r.GetTokenSha256(), r.GetAuthorizationDigest());
        var read = PostgresPlatformGrantRevocationRepository.NormalizeRead(ReadRow(invalid), invalid);
        Assert.Equal(PlatformGrantEffectiveState.Unknown, read.State);
        Assert.Equal(PlatformGrantDiagnostic.ResponseUnavailable, read.Diagnostic);
        Assert.Null(read.ObservedAt); Assert.Null(read.StateChangedAt);
        var authorization = ValidatedGrantRevocationAuthorization.FromValidatedPlan(invalid, sample.Authorization.GetDigest());
        var input = new Input(invalid, sample.RevokeId, authorization);
        AssertUnknown(PostgresPlatformGrantRevocationRepository.NormalizeRevocation(RevokeRow(input), input.RevokeId, authorization));
    }

    private static PlatformGrantStateDatabaseResult Change(PlatformGrantStateDatabaseResult row, string field, bool missing) => field switch
    {
        "environment" => row with { EnvironmentId = missing ? null : Guid.NewGuid() },
        "issue" => row with { OperationId = missing ? null : Guid.NewGuid() },
        "grant" => row with { GrantId = missing ? null : Guid.NewGuid() },
        "directory" => row with { DirectoryObjectId = missing ? null : Guid.NewGuid() },
        "device" => row with { DeviceId = missing ? null : Guid.NewGuid() },
        "mapping" => row with { MappingCreatedAt = missing ? null : row.MappingCreatedAt!.Value.AddTicks(10) },
        "token" => row with { TokenSha256 = missing ? null : new byte[32] },
        "digest" => row with { AuthorizationDigest = missing ? null : new byte[32] },
        "created" => row with { CreatedAt = missing ? null : row.CreatedAt!.Value.AddTicks(10) },
        "expires" => row with { ExpiresAt = missing ? null : row.ExpiresAt!.Value.AddTicks(10) },
        _ => throw new ArgumentOutOfRangeException(nameof(field))
    };

    private static void AssertUnknown(PlatformGrantRevocationResult result)
    {
        Assert.Equal(PlatformGrantRevocationOutcome.Unknown, result.Outcome);
        Assert.Equal(PlatformGrantDiagnostic.ResponseUnavailable, result.Diagnostic);
        Assert.Null(result.Receipt);
    }

    private static PlatformGrantStateDatabaseResult ReadRow(PlatformGrantReceipt receipt) => new("Available", "None",
        receipt.EnvironmentId, receipt.OperationId, receipt.GrantId, receipt.DirectoryObjectId, receipt.DeviceId,
        receipt.MappingCreatedAt, receipt.GetTokenSha256(), receipt.GetAuthorizationDigest(), receipt.CreatedAt, receipt.ExpiresAt,
        receipt.CreatedAt.AddSeconds(1), null, receipt.IssueContractVersion, receipt.MintPermitNotAfter);

    private static PlatformGrantRevocationDatabaseResult RevokeRow(Input sample, string outcome = "Completed", string disposition = "Revoked")
    {
        var r = sample.Receipt;
        var completed = disposition == "Expired" ? r.ExpiresAt.AddSeconds(1) : r.CreatedAt.AddSeconds(1);
        DateTimeOffset? revoked = disposition == "Consumed" ? null : completed;
        return new(outcome, "None", r.EnvironmentId, sample.RevokeId, r.OperationId, r.GrantId, r.DirectoryObjectId, r.DeviceId,
            r.MappingCreatedAt, r.GetTokenSha256(), r.GetAuthorizationDigest(), r.CreatedAt, r.ExpiresAt,
            sample.Authorization.GetDigest(), disposition, completed, revoked, r.IssueContractVersion, r.MintPermitNotAfter);
    }

    private static Input Sample()
    {
        var created = new DateTimeOffset(2026, 9, 12, 0, 0, 0, TimeSpan.Zero);
        var receipt = new PlatformGrantReceipt(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            created.AddMinutes(-1), created, created.AddSeconds(600), Enumerable.Repeat((byte)1, 32).ToArray(), Enumerable.Repeat((byte)2, 32).ToArray());
        return new(receipt, Guid.NewGuid(), ValidatedGrantRevocationAuthorization.FromValidatedPlan(receipt, Enumerable.Repeat((byte)3, 32).ToArray()));
    }

    private sealed record Input(PlatformGrantReceipt Receipt, Guid RevokeId, ValidatedGrantRevocationAuthorization Authorization);
}
