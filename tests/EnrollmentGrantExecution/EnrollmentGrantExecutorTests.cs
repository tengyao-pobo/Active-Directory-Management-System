using System.Collections.Concurrent;
using System.Security.Cryptography;
using ItManagement.AgentEnrollment.Crypto;
using ItManagement.AgentPlatformGrants;
using Xunit;

namespace ItManagement.EnrollmentGrantExecution.Tests;

public sealed class EnrollmentGrantExecutorTests
{
    [Fact]
    public async Task CreatesPersistsIssuesAndRecordsOneGrant()
    {
        var operation = Operation();
        var store = new Store(operation);
        var issuer = new Issuer((authorization, persisted) =>
        {
            var permit = Assert.IsType<PersistedEnrollmentGrantPermit>(store.Record.Permit);
            return new(PlatformGrantOutcome.Created, PlatformGrantDiagnostic.None,
                Receipt(operation, permit, Guid.NewGuid(), At(2, 30)));
        });

        var result = await new EnrollmentGrantExecutor(store, issuer).ExecuteAsync(operation.EnvironmentId, operation.Id, default);

        Assert.Equal(EnrollmentGrantExecutionOutcome.GrantAvailable, result.Outcome);
        Assert.Equal(1, store.AuthorizeCalls); Assert.Equal(1, issuer.Calls); Assert.Equal(1, store.RecordCalls);
        Assert.Equal(EnrollmentGrantExecutionState.Completed, store.Record.State);
    }

    [Fact]
    public async Task DurablePermitRecoveryDoesNotSealAnotherCandidate()
    {
        var operation = Operation();
        var candidate = Candidate(operation);
        var permit = Permit(operation, candidate);
        var store = new Store(PermitRecord(operation, permit, candidate));
        var issuer = SuccessfulIssuer(operation, permit);

        Assert.Equal(EnrollmentGrantExecutionOutcome.GrantAvailable,
            (await new EnrollmentGrantExecutor(store, issuer).ExecuteAsync(operation.EnvironmentId, operation.Id, default)).Outcome);
        Assert.Equal(0, store.AuthorizeCalls); Assert.Equal(1, issuer.Calls);
    }

    [Fact]
    public async Task UnknownPermitCommitReadsBackBeforeIssue()
    {
        var operation = Operation();
        var store = new Store(operation) { PermitOutcome = EnrollmentGrantPermitStoreOutcome.OutcomeUnknown, PersistOnUnknown = true };
        var issuer = new Issuer((_, _) =>
        {
            var permit = Assert.IsType<PersistedEnrollmentGrantPermit>(store.Record.Permit);
            return new(PlatformGrantOutcome.AlreadyCreated, PlatformGrantDiagnostic.None,
                Receipt(operation, permit, Guid.NewGuid(), At(2, 30)));
        });

        var result = await new EnrollmentGrantExecutor(store, issuer).ExecuteAsync(operation.EnvironmentId, operation.Id, default);
        Assert.Equal(EnrollmentGrantExecutionOutcome.GrantAvailable, result.Outcome);
        Assert.Equal(2, store.ReadCalls); Assert.Equal(1, store.AuthorizeCalls); Assert.Equal(1, issuer.Calls);
    }

    [Fact]
    public async Task UnknownPermitCommitWithoutReadbackNeverIssuesCandidate()
    {
        var operation = Operation();
        var store = new Store(operation) { PermitOutcome = EnrollmentGrantPermitStoreOutcome.OutcomeUnknown };
        var issuer = new Issuer((_, _) => throw new InvalidOperationException());

        var result = await new EnrollmentGrantExecutor(store, issuer).ExecuteAsync(operation.EnvironmentId, operation.Id, default);
        Assert.Equal(EnrollmentGrantExecutionOutcome.OutcomeUnknown, result.Outcome);
        Assert.Equal(2, store.ReadCalls); Assert.Equal(0, issuer.Calls); Assert.Equal(0, store.RecordCalls);
    }

    [Fact]
    public async Task StoredPermitWithStopReasonIsRejectedWithoutPrivateIssue()
    {
        var operation = Operation();
        var store = new Store(operation) { StoredStopReason = EnrollmentGrantExecutionStopReason.AuthorizationChanged };
        var issuer = new Issuer((_, _) => throw new InvalidOperationException());

        var result = await new EnrollmentGrantExecutor(store, issuer)
            .ExecuteAsync(operation.EnvironmentId, operation.Id, default);

        Assert.Equal(EnrollmentGrantExecutionOutcome.OutcomeUnknown, result.Outcome);
        Assert.Equal(0, issuer.Calls);
    }

    [Fact]
    public async Task AuthorizationStopIsDurableWithoutPermitOrPrivateIssue()
    {
        var operation = Operation();
        var store = new Store(operation) { PermitOutcome = EnrollmentGrantPermitStoreOutcome.AuthorizationRejected };
        var issuer = new Issuer((_, _) => throw new InvalidOperationException());
        var executor = new EnrollmentGrantExecutor(store, issuer);

        var first = await executor.ExecuteAsync(operation.EnvironmentId, operation.Id, default);
        var recovered = await executor.ExecuteAsync(operation.EnvironmentId, operation.Id, default);

        Assert.Equal(EnrollmentGrantExecutionOutcome.PermanentRejected, first.Outcome);
        Assert.Equal(EnrollmentGrantExecutionStopReason.AuthorizationChanged, first.StopReason);
        Assert.Equal(first, recovered); Assert.Null(store.Record.Permit); Assert.Equal(0, issuer.Calls); Assert.Equal(0, store.RecordCalls);
    }

    [Fact]
    public async Task CorruptObservedIdentityUsesTrustedLookupKeyForQuarantine()
    {
        var requested = Operation(); var corrupt = Operation(environmentId: Guid.NewGuid());
        var store = new Store(new EnrollmentGrantExecutionRecord(corrupt, EnrollmentGrantExecutionState.Queued, null, null, null, null));
        var result = await new EnrollmentGrantExecutor(store, new Issuer((_, _) => throw new InvalidOperationException()))
            .ExecuteAsync(requested.EnvironmentId, requested.Id, default);
        Assert.Equal(EnrollmentGrantExecutionOutcome.Quarantined, result.Outcome);
        Assert.Equal(requested.EnvironmentId, store.LastQuarantineEnvironmentId);
        Assert.Equal(requested.Id, store.LastQuarantineOperationId);
    }

    [Fact]
    public async Task UnknownResultCommitReadsBackTerminalState()
    {
        var operation = Operation(); var candidate = Candidate(operation); var permit = Permit(operation, candidate);
        var store = new Store(PermitRecord(operation, permit, candidate))
        {
            RecordOutcome = EnrollmentGrantRecordOutcome.OutcomeUnknown,
            PersistRecordOnUnknown = true
        };
        var result = await new EnrollmentGrantExecutor(store, SuccessfulIssuer(operation, permit))
            .ExecuteAsync(operation.EnvironmentId, operation.Id, default);
        Assert.Equal(EnrollmentGrantExecutionOutcome.GrantAvailable, result.Outcome);
        Assert.Equal(2, store.ReadCalls); Assert.Equal(EnrollmentGrantExecutionState.Completed, store.Record.State);
    }

    [Fact]
    public async Task UnknownResultCommitWithoutReadbackDoesNotClaimSuccess()
    {
        var operation = Operation(); var candidate = Candidate(operation); var permit = Permit(operation, candidate);
        var store = new Store(PermitRecord(operation, permit, candidate))
        {
            RecordOutcome = EnrollmentGrantRecordOutcome.OutcomeUnknown
        };
        var result = await new EnrollmentGrantExecutor(store, SuccessfulIssuer(operation, permit))
            .ExecuteAsync(operation.EnvironmentId, operation.Id, default);
        Assert.Equal(EnrollmentGrantExecutionOutcome.OutcomeUnknown, result.Outcome);
        Assert.Equal(EnrollmentGrantExecutionState.PermitStored, store.Record.State);
    }

    [Fact]
    public async Task ParallelCandidatesConvergeOnPersistedWinner()
    {
        var operation = Operation();
        var store = new Store(operation) { InitialReadBarrier = new Barrier(2) };
        var issuer = new Issuer((_, persisted) =>
        {
            var permit = Assert.IsType<PersistedEnrollmentGrantPermit>(store.Record.Permit);
            return new(PlatformGrantOutcome.AlreadyCreated, PlatformGrantDiagnostic.None,
                Receipt(operation, permit, Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), At(2, 30)));
        });
        var executor = new EnrollmentGrantExecutor(store, issuer);

        var results = await Task.WhenAll(
            Task.Run(() => executor.ExecuteAsync(operation.EnvironmentId, operation.Id, default)),
            Task.Run(() => executor.ExecuteAsync(operation.EnvironmentId, operation.Id, default)));

        Assert.All(results, result => Assert.Equal(EnrollmentGrantExecutionOutcome.GrantAvailable, result.Outcome));
        Assert.Equal(2, store.AuthorizeCalls); Assert.Equal(2, issuer.Calls);
    }

    [Fact]
    public async Task ExpiredPermitStillCallsPrivateIssueForExactReceiptRecovery()
    {
        var operation = Operation();
        var candidate = Candidate(operation); var permit = Permit(operation, candidate);
        var store = new Store(PermitRecord(operation, permit, candidate));
        var issuer = SuccessfulIssuer(operation, permit, PlatformGrantOutcome.AlreadyCreated);

        var result = await new EnrollmentGrantExecutor(store, issuer).ExecuteAsync(operation.EnvironmentId, operation.Id, default);

        Assert.Equal(EnrollmentGrantExecutionOutcome.GrantAvailable, result.Outcome);
        Assert.Equal(1, issuer.Calls);
    }

    [Fact]
    public async Task AcknowledgedTerminalHasNoEnvelopeAndNeverReissues()
    {
        var operation = Operation(); var candidate = Candidate(operation); var permit = Permit(operation, candidate);
        var receipt = Receipt(operation, permit, Guid.NewGuid(), At(2, 30));
        var recorded = new EnrollmentGrantRecordedResult(PlatformGrantOutcome.Created, PlatformGrantDiagnostic.None,
            receipt, At(2, 31));
        var acknowledgement = new EnrollmentGrantDeliveryAcknowledgement(operation.RequesterId,
            permit.GetTokenSha256(), permit.GetCiphertextSha256(), At(2, 32));
        var store = new Store(new EnrollmentGrantExecutionRecord(operation, EnrollmentGrantExecutionState.Acknowledged,
            permit, null, recorded, acknowledgement));
        var issuer = new Issuer((_, _) => throw new InvalidOperationException());

        var result = await new EnrollmentGrantExecutor(store, issuer).ExecuteAsync(operation.EnvironmentId, operation.Id, default);

        Assert.Equal(EnrollmentGrantExecutionOutcome.NoWork, result.Outcome);
        Assert.Equal(0, issuer.Calls); Assert.Equal(0, store.QuarantineCalls);
    }

    [Fact]
    public async Task CompletedWithoutEnvelopeAndMalformedAcknowledgementAreQuarantined()
    {
        var operation = Operation(); var candidate = Candidate(operation); var permit = Permit(operation, candidate);
        var receipt = Receipt(operation, permit, Guid.NewGuid(), At(2, 30));
        var recorded = new EnrollmentGrantRecordedResult(PlatformGrantOutcome.Created, PlatformGrantDiagnostic.None,
            receipt, At(2, 31));
        var missingEnvelope = new Store(new EnrollmentGrantExecutionRecord(operation,
            EnrollmentGrantExecutionState.Completed, permit, null, recorded, null));
        Assert.Equal(EnrollmentGrantExecutionOutcome.Quarantined,
            (await new EnrollmentGrantExecutor(missingEnvelope, new Issuer((_, _) => throw new InvalidOperationException()))
                .ExecuteAsync(operation.EnvironmentId, operation.Id, default)).Outcome);

        var badAck = new EnrollmentGrantDeliveryAcknowledgement(Guid.NewGuid(), permit.GetTokenSha256(),
            permit.GetCiphertextSha256(), At(2, 32));
        var acknowledged = new Store(new EnrollmentGrantExecutionRecord(operation,
            EnrollmentGrantExecutionState.Acknowledged, permit, null, recorded, badAck));
        Assert.Equal(EnrollmentGrantExecutionOutcome.Quarantined,
            (await new EnrollmentGrantExecutor(acknowledged, new Issuer((_, _) => throw new InvalidOperationException()))
                .ExecuteAsync(operation.EnvironmentId, operation.Id, default)).Outcome);
    }

    [Fact]
    public async Task ImpossibleReceiptIsQuarantined()
    {
        var operation = Operation(); var store = new Store(operation);
        var issuer = new Issuer((_, _) =>
        {
            var permit = Assert.IsType<PersistedEnrollmentGrantPermit>(store.Record.Permit);
            return new(PlatformGrantOutcome.Created, PlatformGrantDiagnostic.None,
                Receipt(Operation(environmentId: Guid.NewGuid()), permit, Guid.NewGuid(), At(2, 30)));
        });

        var result = await new EnrollmentGrantExecutor(store, issuer).ExecuteAsync(operation.EnvironmentId, operation.Id, default);

        Assert.Equal(EnrollmentGrantExecutionOutcome.Quarantined, result.Outcome);
        Assert.Equal(1, store.QuarantineCalls); Assert.Equal(EnrollmentGrantExecutionState.Quarantined, store.Record.State);
        Assert.NotNull(store.Record.Permit); Assert.NotNull(store.Record.Envelope);

        var recovered = await new EnrollmentGrantExecutor(store, new Issuer((_, _) => throw new InvalidOperationException()))
            .ExecuteAsync(operation.EnvironmentId, operation.Id, default);
        Assert.Equal(EnrollmentGrantExecutionOutcome.Quarantined, recovered.Outcome);
        Assert.Equal(EnrollmentGrantExecutionStopReason.ReceiptMismatch, recovered.StopReason);
        Assert.Equal(1, store.QuarantineCalls);
    }

    [Fact]
    public async Task OperationConflictIsQuarantinedAndTransientResultsAreNotRecorded()
    {
        var operation = Operation(); var candidate = Candidate(operation); var permit = Permit(operation, candidate);
        var conflictStore = new Store(PermitRecord(operation, permit, candidate));
        var conflict = new Issuer((_, _) => new(PlatformGrantOutcome.OutcomeUnknown, PlatformGrantDiagnostic.OperationConflict, null));
        Assert.Equal(EnrollmentGrantExecutionOutcome.Quarantined,
            (await new EnrollmentGrantExecutor(conflictStore, conflict).ExecuteAsync(operation.EnvironmentId, operation.Id, default)).Outcome);

        var unknownStore = new Store(PermitRecord(operation, permit, candidate));
        var unknown = new Issuer((_, _) => new(PlatformGrantOutcome.Unknown, PlatformGrantDiagnostic.ConnectionUnavailable, null));
        var result = await new EnrollmentGrantExecutor(unknownStore, unknown).ExecuteAsync(operation.EnvironmentId, operation.Id, default);
        Assert.Equal(EnrollmentGrantExecutionOutcome.OutcomeUnknown, result.Outcome);
        Assert.Equal(PlatformGrantDiagnostic.ConnectionUnavailable, result.Diagnostic);
        Assert.Equal(0, unknownStore.RecordCalls); Assert.Equal(0, unknownStore.QuarantineCalls);
    }

    [Fact]
    public async Task PermanentRejectAllowlistRecordsOnlyDefiniteOutcomes()
    {
        var operation = Operation(); var candidate = Candidate(operation); var permit = Permit(operation, candidate);
        var store = new Store(PermitRecord(operation, permit, candidate));
        var issuer = new Issuer((_, _) => new(PlatformGrantOutcome.PermanentRejected, PlatformGrantDiagnostic.MintPermitExpired, null));
        Assert.Equal(EnrollmentGrantExecutionOutcome.PermanentRejected,
            (await new EnrollmentGrantExecutor(store, issuer).ExecuteAsync(operation.EnvironmentId, operation.Id, default)).Outcome);
        Assert.Equal(EnrollmentGrantExecutionOutcome.PermanentRejected,
            (await new EnrollmentGrantExecutor(store, new Issuer((_, _) => throw new InvalidOperationException()))
                .ExecuteAsync(operation.EnvironmentId, operation.Id, default)).Outcome);

        var badStore = new Store(PermitRecord(operation, permit, candidate));
        var bad = new Issuer((_, _) => new(PlatformGrantOutcome.PermanentRejected, PlatformGrantDiagnostic.InvalidMintPermit, null));
        Assert.Equal(EnrollmentGrantExecutionOutcome.Quarantined,
            (await new EnrollmentGrantExecutor(badStore, bad).ExecuteAsync(operation.EnvironmentId, operation.Id, default)).Outcome);
    }

    [Fact]
    public async Task InvalidOperationTimeAndDualPrincipalShapesAreQuarantinedBeforeIssue()
    {
        var operation = Operation();
        var invalid = new[]
        {
            Copy(operation, mappingCreatedAt: operation.QueuedAt.AddTicks(10)),
            Copy(operation, authorizationNotAfter: operation.QueuedAt.AddSeconds(600).AddTicks(10)),
            Copy(operation, approverId: operation.RequesterId)
        };

        foreach (var value in invalid)
        {
            var store = new Store(value); var issuer = new Issuer((_, _) => throw new InvalidOperationException());
            var result = await new EnrollmentGrantExecutor(store, issuer).ExecuteAsync(value.EnvironmentId, value.Id, default);
            Assert.Equal(EnrollmentGrantExecutionOutcome.Quarantined, result.Outcome);
            Assert.Equal(EnrollmentGrantExecutionStopReason.StoredDataInvalid, result.StopReason);
            Assert.Equal(0, issuer.Calls);
        }
    }

    [Fact]
    public async Task MintPermitExpiredRecordedBeforeDeadlineIsNotAcceptedAsTerminal()
    {
        var operation = Operation(); var candidate = Candidate(operation); var permit = Permit(operation, candidate);
        var result = new EnrollmentGrantRecordedResult(PlatformGrantOutcome.PermanentRejected,
            PlatformGrantDiagnostic.MintPermitExpired, null, permit.MintPermitNotAfter.AddTicks(-10));
        var store = new Store(new EnrollmentGrantExecutionRecord(operation,
            EnrollmentGrantExecutionState.PermanentRejected, permit, null, result, null));

        var execution = await new EnrollmentGrantExecutor(store, new Issuer((_, _) => throw new InvalidOperationException()))
            .ExecuteAsync(operation.EnvironmentId, operation.Id, default);

        Assert.Equal(EnrollmentGrantExecutionOutcome.Quarantined, execution.Outcome);
        Assert.Equal(1, store.QuarantineCalls);
    }

    [Fact]
    public async Task CancellationPropagatesWithoutRecording()
    {
        var operation = Operation(); var store = new Store(operation);
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new EnrollmentGrantExecutor(store, new Issuer((_, _) => throw new InvalidOperationException()))
                .ExecuteAsync(operation.EnvironmentId, operation.Id, cancellation.Token));
        Assert.Equal(0, store.RecordCalls); Assert.Equal(0, store.QuarantineCalls);
    }

    [Fact]
    public void AuthorizationDigestHasStableVectorAndBindsEveryField()
    {
        var operation = Operation();
        var tokenHash = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var ciphertextHash = Enumerable.Repeat((byte)0x22, 32).ToArray();
        var digest = EnrollmentGrantAuthorizationDigest.Compute(operation, 1, At(2), At(3),
            tokenHash, operation.GetRecipientKeyFingerprint(), ciphertextHash);
        Assert.Equal("210FEA5449810D619EF3E5FED16435448AF5C7E48063A4A0651BC10FF14CE255",
            Convert.ToHexString(digest));

        var changed = Operation(environmentVersion: operation.EnvironmentVersion + 1);
        Assert.NotEqual(digest, EnrollmentGrantAuthorizationDigest.Compute(changed, 1, At(2), At(3),
            tokenHash, operation.GetRecipientKeyFingerprint(), ciphertextHash));
    }

    [Fact]
    public void AuthorizationDigestBindsAllIndependentlyVariableOperationAndPermitFields()
    {
        var operation = Operation();
        var token = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var ciphertext = Enumerable.Repeat((byte)0x22, 32).ToArray();
        var baseline = Digest(operation, At(2), At(3), token, operation.GetRecipientKeyFingerprint(), ciphertext);
        foreach (var index in Enumerable.Range(0, 19).Except([15, 16]))
        {
            var changedOperation = ChangedOperation(operation, index);
            Assert.NotEqual(baseline, Digest(changedOperation, At(2), At(3), token,
                changedOperation.GetRecipientKeyFingerprint(), ciphertext));
        }

        using var otherKey = RSA.Create(3072);
        var otherSpki = otherKey.ExportSubjectPublicKeyInfo();
        var changedKeyOperation = Copy(operation, recipientSpki: otherSpki,
            recipientKeyFingerprint: SHA256.HashData(otherSpki));
        Assert.NotEqual(baseline, Digest(changedKeyOperation, At(2), At(3), token,
            changedKeyOperation.GetRecipientKeyFingerprint(), ciphertext));

        Assert.NotEqual(baseline, Digest(operation, At(2).AddTicks(10), At(3), token, operation.GetRecipientKeyFingerprint(), ciphertext));
        Assert.NotEqual(baseline, Digest(operation, At(2), At(3).AddTicks(-10), token, operation.GetRecipientKeyFingerprint(), ciphertext));
        Assert.NotEqual(baseline, Digest(operation, At(2), At(3), Mutate(token), operation.GetRecipientKeyFingerprint(), ciphertext));
        Assert.NotEqual(baseline, Digest(operation, At(2), At(3), token, Mutate(operation.GetRecipientKeyFingerprint()), ciphertext));
        Assert.NotEqual(baseline, Digest(operation, At(2), At(3), token, operation.GetRecipientKeyFingerprint(), Mutate(ciphertext)));
        Assert.Throws<ArgumentException>(() => EnrollmentGrantAuthorizationDigest.Compute(operation, 2, At(2), At(3),
            token, operation.GetRecipientKeyFingerprint(), ciphertext));
    }

    [Fact]
    public void SensitiveEnvelopeDataIsDefensivelyCopiedAndNotFormatted()
    {
        var operation = Operation(); var candidate = Candidate(operation); var permit = Permit(operation, candidate);
        var envelope = new PersistedEnrollmentGrantEnvelope(candidate.GetCiphertext());
        var token = permit.GetTokenSha256(); var ciphertext = envelope.GetCiphertext();
        var tokenText = Convert.ToBase64String(token); var ciphertextText = Convert.ToBase64String(ciphertext);
        token[0] ^= 0xff; ciphertext[0] ^= 0xff;
        Assert.NotEqual(token, permit.GetTokenSha256()); Assert.NotEqual(ciphertext, envelope.GetCiphertext());
        Assert.DoesNotContain(tokenText, permit.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(ciphertextText, permit.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(tokenText, candidate.ToString(), StringComparison.Ordinal);
    }

    private static Issuer SuccessfulIssuer(EnrollmentGrantExecutionOperation operation, PersistedEnrollmentGrantPermit permit,
        PlatformGrantOutcome outcome = PlatformGrantOutcome.Created) => new((_, _) => new(outcome,
            PlatformGrantDiagnostic.None, Receipt(operation, permit, Guid.NewGuid(), At(2, 30))));

    private static PlatformGrantReceipt Receipt(EnrollmentGrantExecutionOperation operation,
        PersistedEnrollmentGrantPermit permit, Guid grantId, DateTimeOffset createdAt) => new(operation.EnvironmentId,
        operation.Id, grantId, operation.DirectoryObjectId, operation.ServerDeviceId, operation.MappingCreatedAt,
        createdAt, createdAt.AddSeconds(600), 2, permit.MintPermitNotAfter,
        permit.GetTokenSha256(), permit.GetAuthorizationDigest());

    private static EnrollmentGrantEnvelopeCandidate Candidate(EnrollmentGrantExecutionOperation operation) =>
        new(SealedEnrollmentGrant.Seal(operation.GetRecipientSpki(), operation.EnvironmentId, operation.Id));

    private static PersistedEnrollmentGrantPermit Permit(EnrollmentGrantExecutionOperation operation,
        EnrollmentGrantEnvelopeCandidate candidate)
    {
        var digest = EnrollmentGrantAuthorizationDigest.Compute(operation, 1, At(2), At(3), candidate.GetTokenSha256(),
            candidate.GetRecipientKeyFingerprint(), candidate.GetCiphertextSha256());
        return new(1, At(2), At(3), candidate.GetTokenSha256(), candidate.GetRecipientKeyFingerprint(),
            candidate.GetCiphertextSha256(), digest);
    }

    private static EnrollmentGrantExecutionRecord PermitRecord(EnrollmentGrantExecutionOperation operation,
        PersistedEnrollmentGrantPermit permit, EnrollmentGrantEnvelopeCandidate candidate) => new(operation,
        EnrollmentGrantExecutionState.PermitStored, permit,
        new PersistedEnrollmentGrantEnvelope(candidate.GetCiphertext()), null, null);

    private static EnrollmentGrantExecutionOperation Operation(Guid? environmentId = null, long environmentVersion = 7)
    {
        var spki = Convert.FromBase64String(SpkiBase64); var fingerprint = SHA256.HashData(spki);
        return new(environmentId ?? Guid.Parse("11111111-1111-1111-1111-111111111111"),
            Guid.Parse("22222222-2222-2222-2222-222222222222"), Guid.Parse("33333333-3333-3333-3333-333333333333"),
            Guid.Parse("44444444-4444-4444-4444-444444444444"), Guid.Parse("55555555-5555-5555-5555-555555555555"),
            Guid.Parse("66666666-6666-6666-6666-666666666666"), Guid.Parse("77777777-7777-7777-7777-777777777777"),
            Guid.Parse("88888888-8888-8888-8888-888888888888"), Guid.Parse("99999999-9999-9999-9999-999999999999"),
            new string('a', 64), Guid.Parse("aaaaaaaa-1111-1111-1111-111111111111"),
            Guid.Parse("bbbbbbbb-1111-1111-1111-111111111111"), At(0), Guid.Parse("cccccccc-1111-1111-1111-111111111111"),
            environmentVersion, spki, fingerprint, At(1), At(11));
    }

    private static DateTimeOffset At(int minute, int second = 0) =>
        new(2026, 9, 12, 0, minute, second, TimeSpan.Zero);

    private static byte[] Digest(EnrollmentGrantExecutionOperation operation, DateTimeOffset issued,
        DateTimeOffset deadline, byte[] token, byte[] fingerprint, byte[] ciphertext) =>
        EnrollmentGrantAuthorizationDigest.Compute(operation, 1, issued, deadline, token, fingerprint, ciphertext);

    private static byte[] Mutate(byte[] value)
    {
        var changed = (byte[])value.Clone(); changed[0] ^= 0xff; return changed;
    }

    private static EnrollmentGrantExecutionOperation ChangedOperation(EnrollmentGrantExecutionOperation value, int index) => index switch
    {
        0 => Copy(value, environmentId: Guid.NewGuid()), 1 => Copy(value, id: Guid.NewGuid()),
        2 => Copy(value, planId: Guid.NewGuid()), 3 => Copy(value, requestId: Guid.NewGuid()),
        4 => Copy(value, approvalId: Guid.NewGuid()), 5 => Copy(value, requesterId: Guid.NewGuid()),
        6 => Copy(value, approverId: Guid.NewGuid()), 7 => Copy(value, requesterOperatorId: Guid.NewGuid()),
        8 => Copy(value, approverOperatorId: Guid.NewGuid()), 9 => Copy(value, planHash: new string('b', 64)),
        10 => Copy(value, directoryObjectId: Guid.NewGuid()), 11 => Copy(value, serverDeviceId: Guid.NewGuid()),
        12 => Copy(value, mappingCreatedAt: value.MappingCreatedAt.AddTicks(10)),
        13 => Copy(value, directoryGeneration: Guid.NewGuid()), 14 => Copy(value, environmentVersion: value.EnvironmentVersion + 1),
        17 => Copy(value, queuedAt: value.QueuedAt.AddTicks(10)),
        18 => Copy(value, authorizationNotAfter: value.AuthorizationNotAfter.AddTicks(-10)),
        _ => throw new ArgumentOutOfRangeException(nameof(index))
    };

    private static EnrollmentGrantExecutionOperation Copy(EnrollmentGrantExecutionOperation value,
        Guid? environmentId = null, Guid? id = null, Guid? planId = null, Guid? requestId = null,
        Guid? approvalId = null, Guid? requesterId = null, Guid? approverId = null,
        Guid? requesterOperatorId = null, Guid? approverOperatorId = null, string? planHash = null,
        Guid? directoryObjectId = null, Guid? serverDeviceId = null, DateTimeOffset? mappingCreatedAt = null,
        Guid? directoryGeneration = null, long? environmentVersion = null, byte[]? recipientSpki = null,
        byte[]? recipientKeyFingerprint = null, DateTimeOffset? queuedAt = null,
        DateTimeOffset? authorizationNotAfter = null) => new(environmentId ?? value.EnvironmentId, id ?? value.Id,
        planId ?? value.PlanId, requestId ?? value.RequestId, approvalId ?? value.ApprovalId,
        requesterId ?? value.RequesterId, approverId ?? value.ApproverId,
        requesterOperatorId ?? value.RequesterOperatorId, approverOperatorId ?? value.ApproverOperatorId,
        planHash ?? value.PlanHash, directoryObjectId ?? value.DirectoryObjectId,
        serverDeviceId ?? value.ServerDeviceId, mappingCreatedAt ?? value.MappingCreatedAt,
        directoryGeneration ?? value.DirectoryGeneration, environmentVersion ?? value.EnvironmentVersion,
        recipientSpki ?? value.GetRecipientSpki(), recipientKeyFingerprint ?? value.GetRecipientKeyFingerprint(),
        queuedAt ?? value.QueuedAt, authorizationNotAfter ?? value.AuthorizationNotAfter);

    private sealed class Issuer(Func<ValidatedGrantAuthorization, ValidatedPersistedPlatformGrant, PlatformGrantResult> handler) : IPlatformGrantIssuer
    {
        public int Calls { get; private set; }
        public Task<PlatformGrantResult> IssueAsync(Guid operationId, ValidatedGrantAuthorization authorization,
            ValidatedPersistedPlatformGrant persistedGrant, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++; return Task.FromResult(handler(authorization, persistedGrant));
        }
    }

    private sealed class Store : IEnrollmentGrantExecutionStore
    {
        private readonly object _gate = new();
        public Store(EnrollmentGrantExecutionOperation operation) : this(new EnrollmentGrantExecutionRecord(
            operation, EnrollmentGrantExecutionState.Queued, null, null, null, null)) { }
        public Store(EnrollmentGrantExecutionRecord record) => Record = record;
        public EnrollmentGrantExecutionRecord Record { get; private set; }
        public EnrollmentGrantPermitStoreOutcome PermitOutcome { get; init; } = EnrollmentGrantPermitStoreOutcome.Stored;
        public EnrollmentGrantExecutionStopReason? StoredStopReason { get; init; }
        public bool PersistOnUnknown { get; init; }
        public EnrollmentGrantRecordOutcome RecordOutcome { get; init; } = EnrollmentGrantRecordOutcome.Recorded;
        public bool PersistRecordOnUnknown { get; init; }
        public Barrier? InitialReadBarrier { get; init; }
        public int ReadCalls, AuthorizeCalls, RecordCalls, QuarantineCalls;
        public Guid LastQuarantineEnvironmentId, LastQuarantineOperationId;

        public Task<EnrollmentGrantStoreReadResult> ReadAsync(Guid environmentId, Guid operationId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Interlocked.Increment(ref ReadCalls);
            if (InitialReadBarrier is not null && Record.Permit is null) InitialReadBarrier.SignalAndWait(cancellationToken);
            return Task.FromResult(new EnrollmentGrantStoreReadResult(EnrollmentGrantStoreReadOutcome.Found, Record));
        }

        public Task<EnrollmentGrantPermitStoreResult> AuthorizeAndStoreCandidateAsync(EnrollmentGrantExecutionOperation operation,
            EnrollmentGrantEnvelopeCandidate candidate, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Interlocked.Increment(ref AuthorizeCalls);
            lock (_gate)
            {
                if (Record.Permit is not null) return Task.FromResult(new EnrollmentGrantPermitStoreResult(
                    EnrollmentGrantPermitStoreOutcome.Existing, Record.Permit, Record.Envelope));
                if (PermitOutcome == EnrollmentGrantPermitStoreOutcome.AuthorizationRejected)
                {
                    Record = new(operation, EnrollmentGrantExecutionState.PermanentRejected, null, null, null, null,
                        EnrollmentGrantExecutionStopReason.AuthorizationChanged);
                    return Task.FromResult(new EnrollmentGrantPermitStoreResult(PermitOutcome, null, null,
                        EnrollmentGrantExecutionStopReason.AuthorizationChanged));
                }
                if (PermitOutcome == EnrollmentGrantPermitStoreOutcome.OutcomeUnknown && !PersistOnUnknown)
                    return Task.FromResult(new EnrollmentGrantPermitStoreResult(PermitOutcome, null, null));
                var permit = Permit(operation, candidate);
                var envelope = new PersistedEnrollmentGrantEnvelope(candidate.GetCiphertext());
                Record = new(operation, EnrollmentGrantExecutionState.PermitStored, permit, envelope, null, null);
                return Task.FromResult(new EnrollmentGrantPermitStoreResult(PermitOutcome,
                    PermitOutcome == EnrollmentGrantPermitStoreOutcome.OutcomeUnknown ? null : permit,
                    PermitOutcome == EnrollmentGrantPermitStoreOutcome.OutcomeUnknown ? null : envelope,
                    StoredStopReason));
            }
        }

        public Task<EnrollmentGrantRecordResult> RecordDefiniteResultAsync(EnrollmentGrantExecutionOperation operation,
            PersistedEnrollmentGrantPermit permit, EnrollmentGrantDefiniteResult result, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Interlocked.Increment(ref RecordCalls);
            lock (_gate)
            {
                if (Record.State is EnrollmentGrantExecutionState.Completed or EnrollmentGrantExecutionState.PermanentRejected)
                    return Task.FromResult(new EnrollmentGrantRecordResult(EnrollmentGrantRecordOutcome.AlreadyRecorded));
                if (RecordOutcome != EnrollmentGrantRecordOutcome.OutcomeUnknown || PersistRecordOnUnknown)
                    Record = new(operation,
                        result.Outcome == PlatformGrantOutcome.PermanentRejected ? EnrollmentGrantExecutionState.PermanentRejected : EnrollmentGrantExecutionState.Completed,
                        permit, result.Outcome == PlatformGrantOutcome.PermanentRejected ? null : Record.Envelope,
                        new EnrollmentGrantRecordedResult(result.Outcome, result.Diagnostic, result.Receipt,
                            result.Diagnostic == PlatformGrantDiagnostic.MintPermitExpired ? permit.MintPermitNotAfter : At(2, 31)), null);
                return Task.FromResult(new EnrollmentGrantRecordResult(RecordOutcome));
            }
        }

        public Task<EnrollmentGrantRecordResult> QuarantineAsync(Guid environmentId, Guid operationId,
            EnrollmentGrantExecutionOperation? observedOperation, PersistedEnrollmentGrantPermit? permit,
            EnrollmentGrantExecutionStopReason reason, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Interlocked.Increment(ref QuarantineCalls);
            LastQuarantineEnvironmentId = environmentId; LastQuarantineOperationId = operationId;
            Record = new(Record.Operation, EnrollmentGrantExecutionState.Quarantined, permit,
                permit is null ? null : Record.Envelope, null, null, reason);
            return Task.FromResult(new EnrollmentGrantRecordResult(EnrollmentGrantRecordOutcome.Recorded));
        }
    }

    private const string SpkiBase64 = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAl+iMe5xLwL/5QZI0X6381UpQF/3h3t4CN1WHtSKmmRUInVy6i8ilX1cAXVfd1eQqTCvEsBbee1q/4rnRW7AE0kKZDntIYDZKXDSVVrUYiixLgJpDqH777c0ICzDPVdHvFHbTOInviCD8j25sCUKlKoJYDTRjx+BtfiAEfZ3Ktuqtby59Z6Piai3gc6mw25Ov2qbJ3P9PHcJ3VqeaD04cP2fRqTyOBSbf4tLK2DsSCtodCd7Oew1r5tRYahA1trI8aKsJXPQZ2vvpvAY+IyFngtwEXXIpnsAnfzDVqhhW2mUcpMrVDK2Hg6+EdGqY5v9dWqoITqY7aJh1/dWjeDaWQI8uWeZ/VrFd/Ab8ZjO9h8reKRp2470jCY5j1X8jcVMJ5AUlngV1a5bz/nJffjUVmIUGoreXsdvjHA/KiVXOf7f/JkHxmyZJi82R5rPFAb6Q3mOVozQJZJl+SBWpjsn9p5DdajI9apFk7IA1e/GVt1MZbsjz6qhqoe6JRBkJPZbhAgMBAAE=";
}
