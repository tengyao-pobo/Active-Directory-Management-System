using System.Security.Cryptography;
using ItManagement.AgentEnrollment.Crypto;
using ItManagement.AgentPlatformGrants;

namespace ItManagement.EnrollmentGrantExecution;

public enum EnrollmentGrantExecutionState { Queued, PermitStored, Completed, Acknowledged, PermanentRejected, Quarantined }
public enum EnrollmentGrantStoreReadOutcome { Found, NotFound, OutcomeUnknown }
public enum EnrollmentGrantPermitStoreOutcome { Stored, Existing, AuthorizationRejected, OutcomeUnknown }
public enum EnrollmentGrantRecordOutcome { Recorded, AlreadyRecorded, Conflict, OutcomeUnknown }
public enum EnrollmentGrantExecutionOutcome { NoWork, Reconciling, GrantAvailable, PermanentRejected, Quarantined, OutcomeUnknown }
public enum EnrollmentGrantExecutionStopReason { AuthorizationChanged, AuthorizationExpired, StoredDataInvalid, OperationConflict, ReceiptMismatch }

public sealed class EnrollmentGrantExecutionOperation
{
    private readonly byte[] _recipientSpki;
    private readonly byte[] _recipientKeyFingerprint;

    public EnrollmentGrantExecutionOperation(Guid environmentId, Guid id, Guid planId, Guid requestId,
        Guid approvalId, Guid requesterId, Guid approverId, Guid requesterOperatorId, Guid approverOperatorId,
        string planHash, Guid directoryObjectId, Guid serverDeviceId, DateTimeOffset mappingCreatedAt,
        Guid directoryGeneration, long environmentVersion, ReadOnlySpan<byte> recipientSpki,
        ReadOnlySpan<byte> recipientKeyFingerprint, DateTimeOffset queuedAt, DateTimeOffset authorizationNotAfter)
    {
        EnvironmentId = environmentId; Id = id; PlanId = planId; RequestId = requestId; ApprovalId = approvalId;
        RequesterId = requesterId; ApproverId = approverId; RequesterOperatorId = requesterOperatorId;
        ApproverOperatorId = approverOperatorId; PlanHash = planHash; DirectoryObjectId = directoryObjectId;
        ServerDeviceId = serverDeviceId; MappingCreatedAt = mappingCreatedAt; DirectoryGeneration = directoryGeneration;
        EnvironmentVersion = environmentVersion; _recipientSpki = recipientSpki.ToArray();
        _recipientKeyFingerprint = recipientKeyFingerprint.ToArray(); QueuedAt = queuedAt;
        AuthorizationNotAfter = authorizationNotAfter;
    }

    public Guid EnvironmentId { get; }
    public Guid Id { get; }
    public Guid PlanId { get; }
    public Guid RequestId { get; }
    public Guid ApprovalId { get; }
    public Guid RequesterId { get; }
    public Guid ApproverId { get; }
    public Guid RequesterOperatorId { get; }
    public Guid ApproverOperatorId { get; }
    public string PlanHash { get; }
    public Guid DirectoryObjectId { get; }
    public Guid ServerDeviceId { get; }
    public DateTimeOffset MappingCreatedAt { get; }
    public Guid DirectoryGeneration { get; }
    public long EnvironmentVersion { get; }
    public DateTimeOffset QueuedAt { get; }
    public DateTimeOffset AuthorizationNotAfter { get; }
    public byte[] GetRecipientSpki() => (byte[])_recipientSpki.Clone();
    public byte[] GetRecipientKeyFingerprint() => (byte[])_recipientKeyFingerprint.Clone();

    internal bool IsValid()
    {
        if (EnvironmentId == Guid.Empty || Id == Guid.Empty || PlanId == Guid.Empty || RequestId == Guid.Empty ||
            ApprovalId == Guid.Empty || RequesterId == Guid.Empty || ApproverId == Guid.Empty ||
            RequesterId == ApproverId ||
            RequesterOperatorId == Guid.Empty || ApproverOperatorId == Guid.Empty ||
            RequesterOperatorId == ApproverOperatorId || DirectoryObjectId == Guid.Empty || ServerDeviceId == Guid.Empty ||
            DirectoryGeneration == Guid.Empty || EnvironmentVersion <= 0 || !Canonical(MappingCreatedAt) ||
            !Canonical(QueuedAt) || !Canonical(AuthorizationNotAfter) || AuthorizationNotAfter <= QueuedAt ||
            MappingCreatedAt > QueuedAt || AuthorizationNotAfter - QueuedAt > TimeSpan.FromSeconds(600) ||
            PlanHash is null || PlanHash.Length != 64 || PlanHash.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')) ||
            _recipientKeyFingerprint.Length != 32)
            return false;
        try
        {
            var key = EnrollmentGrantRecipientKey.Validate(_recipientSpki);
            return CryptographicOperations.FixedTimeEquals(key.GetFingerprintSha256(), _recipientKeyFingerprint);
        }
        catch (SealedEnrollmentGrantException) { return false; }
    }

    internal static bool Canonical(DateTimeOffset value) => value.Offset == TimeSpan.Zero && value.Ticks % 10 == 0 &&
        value != DateTimeOffset.MinValue && value != DateTimeOffset.MaxValue;
}

public sealed class EnrollmentGrantEnvelopeCandidate
{
    private readonly byte[] _tokenSha256, _recipientFingerprint, _ciphertextSha256, _ciphertext;
    internal EnrollmentGrantEnvelopeCandidate(SealedEnrollmentGrant grant)
    {
        _tokenSha256 = grant.GetTokenSha256();
        _recipientFingerprint = grant.GetRecipientSubjectPublicKeyInfoSha256();
        _ciphertext = grant.GetCiphertext();
        _ciphertextSha256 = SHA256.HashData(_ciphertext);
    }
    public int PermitVersion => 1;
    public byte[] GetTokenSha256() => (byte[])_tokenSha256.Clone();
    public byte[] GetRecipientKeyFingerprint() => (byte[])_recipientFingerprint.Clone();
    public byte[] GetCiphertextSha256() => (byte[])_ciphertextSha256.Clone();
    public byte[] GetCiphertext() => (byte[])_ciphertext.Clone();
    internal bool IsValid() => _tokenSha256.Length == 32 && _recipientFingerprint.Length == 32 &&
        _ciphertextSha256.Length == 32 && _ciphertext.Length == 384 &&
        CryptographicOperations.FixedTimeEquals(SHA256.HashData(_ciphertext), _ciphertextSha256);
}

public sealed class PersistedEnrollmentGrantPermit
{
    private readonly byte[] _tokenSha256, _recipientFingerprint, _ciphertextSha256, _authorizationDigest;
    public PersistedEnrollmentGrantPermit(int permitVersion, DateTimeOffset permitIssuedAt,
        DateTimeOffset mintPermitNotAfter, ReadOnlySpan<byte> tokenSha256, ReadOnlySpan<byte> recipientKeyFingerprint,
        ReadOnlySpan<byte> ciphertextSha256, ReadOnlySpan<byte> authorizationDigest)
    {
        PermitVersion = permitVersion; PermitIssuedAt = permitIssuedAt; MintPermitNotAfter = mintPermitNotAfter;
        _tokenSha256 = tokenSha256.ToArray(); _recipientFingerprint = recipientKeyFingerprint.ToArray();
        _ciphertextSha256 = ciphertextSha256.ToArray();
        _authorizationDigest = authorizationDigest.ToArray();
    }
    public int PermitVersion { get; }
    public DateTimeOffset PermitIssuedAt { get; }
    public DateTimeOffset MintPermitNotAfter { get; }
    public byte[] GetTokenSha256() => (byte[])_tokenSha256.Clone();
    public byte[] GetRecipientKeyFingerprint() => (byte[])_recipientFingerprint.Clone();
    public byte[] GetCiphertextSha256() => (byte[])_ciphertextSha256.Clone();
    public byte[] GetAuthorizationDigest() => (byte[])_authorizationDigest.Clone();
    internal bool IsValid(EnrollmentGrantExecutionOperation operation)
    {
        if (PermitVersion != 1 || !EnrollmentGrantExecutionOperation.Canonical(PermitIssuedAt) ||
            !EnrollmentGrantExecutionOperation.Canonical(MintPermitNotAfter) || MintPermitNotAfter <= PermitIssuedAt ||
            MintPermitNotAfter - PermitIssuedAt > TimeSpan.FromSeconds(60) || MintPermitNotAfter > operation.AuthorizationNotAfter ||
            PermitIssuedAt < operation.QueuedAt ||
            _tokenSha256.Length != 32 || _recipientFingerprint.Length != 32 || _ciphertextSha256.Length != 32 ||
            _authorizationDigest.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(_recipientFingerprint, operation.GetRecipientKeyFingerprint())) return false;
        return CryptographicOperations.FixedTimeEquals(
            EnrollmentGrantAuthorizationDigest.Compute(operation, this), _authorizationDigest);
    }
}

public sealed class PersistedEnrollmentGrantEnvelope
{
    private readonly byte[] _ciphertext;
    public PersistedEnrollmentGrantEnvelope(ReadOnlySpan<byte> ciphertext) => _ciphertext = ciphertext.ToArray();
    public byte[] GetCiphertext() => (byte[])_ciphertext.Clone();
    internal bool IsValid(PersistedEnrollmentGrantPermit permit) => _ciphertext.Length == 384 &&
        CryptographicOperations.FixedTimeEquals(SHA256.HashData(_ciphertext), permit.GetCiphertextSha256());
}

public sealed record EnrollmentGrantDefiniteResult(PlatformGrantOutcome Outcome, PlatformGrantDiagnostic Diagnostic,
    PlatformGrantReceipt? Receipt);
public sealed record EnrollmentGrantRecordedResult(PlatformGrantOutcome Outcome, PlatformGrantDiagnostic Diagnostic,
    PlatformGrantReceipt? Receipt, DateTimeOffset RecordedAt);
public sealed class EnrollmentGrantDeliveryAcknowledgement
{
    private readonly byte[] _tokenSha256, _ciphertextSha256;
    public EnrollmentGrantDeliveryAcknowledgement(Guid requesterId, ReadOnlySpan<byte> tokenSha256,
        ReadOnlySpan<byte> ciphertextSha256, DateTimeOffset acknowledgedAt)
    {
        RequesterId = requesterId; _tokenSha256 = tokenSha256.ToArray();
        _ciphertextSha256 = ciphertextSha256.ToArray(); AcknowledgedAt = acknowledgedAt;
    }
    public Guid RequesterId { get; }
    public DateTimeOffset AcknowledgedAt { get; }
    public byte[] GetTokenSha256() => (byte[])_tokenSha256.Clone();
    public byte[] GetCiphertextSha256() => (byte[])_ciphertextSha256.Clone();
    internal bool IsValid(EnrollmentGrantExecutionOperation operation, PersistedEnrollmentGrantPermit permit,
        EnrollmentGrantRecordedResult result) => RequesterId == operation.RequesterId &&
        EnrollmentGrantExecutionOperation.Canonical(AcknowledgedAt) && AcknowledgedAt >= result.RecordedAt &&
        _tokenSha256.Length == 32 && _ciphertextSha256.Length == 32 &&
        CryptographicOperations.FixedTimeEquals(_tokenSha256, permit.GetTokenSha256()) &&
        CryptographicOperations.FixedTimeEquals(_ciphertextSha256, permit.GetCiphertextSha256());
}
public sealed record EnrollmentGrantExecutionRecord(EnrollmentGrantExecutionOperation Operation,
    EnrollmentGrantExecutionState State, PersistedEnrollmentGrantPermit? Permit, PersistedEnrollmentGrantEnvelope? Envelope,
    EnrollmentGrantRecordedResult? Result, EnrollmentGrantDeliveryAcknowledgement? Acknowledgement,
    EnrollmentGrantExecutionStopReason? StopReason = null);
public sealed record EnrollmentGrantStoreReadResult(EnrollmentGrantStoreReadOutcome Outcome, EnrollmentGrantExecutionRecord? Record);
public sealed record EnrollmentGrantPermitStoreResult(EnrollmentGrantPermitStoreOutcome Outcome,
    PersistedEnrollmentGrantPermit? Permit, PersistedEnrollmentGrantEnvelope? Envelope,
    EnrollmentGrantExecutionStopReason? StopReason = null);
public sealed record EnrollmentGrantRecordResult(EnrollmentGrantRecordOutcome Outcome);
public sealed record EnrollmentGrantExecutionResult(EnrollmentGrantExecutionOutcome Outcome,
    PlatformGrantDiagnostic Diagnostic, EnrollmentGrantExecutionStopReason? StopReason = null);
