using ItManagement.AgentEnrollment.Crypto;

namespace ItManagement.AgentEnrollment;

public sealed class EnrollmentBearerToken
{
    private readonly byte[] _bytes;
    private EnrollmentBearerToken(byte[] bytes) => _bytes = bytes;
    public static EnrollmentBearerToken FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 32) throw new ArgumentException("Enrollment token must contain exactly 32 bytes.", nameof(bytes));
        return new(bytes.ToArray());
    }
    internal byte[] GetBytes() => (byte[])_bytes.Clone();
}

public enum EnrollmentSubmissionOutcome { Pending, Issued, RecoveryRequired, PermanentRejected, IdentityConflict, Unknown }
public enum EnrollmentDiagnosticCode { None, ProtocolRejected, AuthenticationFailed, GrantUnavailable, DeviceUnavailable, LeaseUnavailable, IssuerOutcomeUnknown, IssuerPermanentFailure, PrivilegeAuditFailed, ConnectionUnavailable, ResponseUnavailable }

public sealed record EnrollmentIdentity(Guid RequestId, Guid IssuanceId, Guid RegistrationId, long RegistrationEpoch);

public sealed class PersistedIssuedCertificate
{
    private readonly byte[] _leaf, _leafHash, _spkiHash, _serial;
    private readonly byte[][] _intermediates;
    internal PersistedIssuedCertificate(Guid bindingId,byte[] leaf,byte[][] intermediates,byte[] leafHash,byte[] spkiHash,
        byte[] serial,DateTimeOffset notBefore,DateTimeOffset notAfter)
    {
        BindingId=bindingId; _leaf=(byte[])leaf.Clone(); _intermediates=intermediates.Select(x=>(byte[])x.Clone()).ToArray();
        _leafHash=(byte[])leafHash.Clone(); _spkiHash=(byte[])spkiHash.Clone(); _serial=(byte[])serial.Clone();
        NotBefore=notBefore; NotAfter=notAfter;
    }
    public Guid BindingId { get; }
    public DateTimeOffset NotBefore { get; }
    public DateTimeOffset NotAfter { get; }
    public byte[] GetLeafDer() => (byte[])_leaf.Clone();
    public byte[][] GetIntermediateDer() => _intermediates.Select(x=>(byte[])x.Clone()).ToArray();
    public byte[] GetLeafSha256() => (byte[])_leafHash.Clone();
    public byte[] GetSubjectPublicKeyInfoSha256() => (byte[])_spkiHash.Clone();
    public byte[] GetSerialNumber() => (byte[])_serial.Clone();
}

public sealed record EnrollmentSubmissionResult(EnrollmentSubmissionOutcome Outcome,EnrollmentDiagnosticCode DiagnosticCode,
    EnrollmentIdentity? Identity,PersistedIssuedCertificate? Certificate);

public enum IssuanceClaimOutcome { Claimed, None, Unauthorized, Unknown }
public sealed class IssuanceClaim
{
    private readonly byte[] _csrDer, _csrHash, _spkiHash;
    internal IssuanceClaim(Guid requestId,Guid issuanceId,Guid leaseToken,Guid deviceId,Guid deviceGuid,Guid registrationId,
        long epoch,byte[] csrDer,byte[] csrHash,byte[] spkiHash,int profile)
    { RequestId=requestId;IssuanceId=issuanceId;LeaseToken=leaseToken;DeviceId=deviceId;DeviceGuid=deviceGuid;
      RegistrationId=registrationId;RegistrationEpoch=epoch;_csrDer=(byte[])csrDer.Clone();_csrHash=(byte[])csrHash.Clone();
      _spkiHash=(byte[])spkiHash.Clone();ProfileVersion=profile; }
    public Guid RequestId { get; } public Guid IssuanceId { get; } public Guid LeaseToken { get; }
    public Guid DeviceId { get; } public Guid DeviceGuid { get; } public Guid RegistrationId { get; }
    public long RegistrationEpoch { get; } public int ProfileVersion { get; }
    public byte[] GetCsrDer()=>(byte[])_csrDer.Clone(); public byte[] GetCsrSha256()=>(byte[])_csrHash.Clone();
    public byte[] GetSubjectPublicKeyInfoSha256()=>(byte[])_spkiHash.Clone();
}
public sealed record IssuanceClaimResult(IssuanceClaimOutcome Outcome,EnrollmentDiagnosticCode DiagnosticCode,IssuanceClaim? Claim);
public enum IssuanceMutationOutcome { Completed, AlreadyCompleted, Deferred, OutcomeUnknown, PermanentFailed, RecoveryRequired, Unauthorized, PermanentRejected, IdentityConflict, Unknown }
public sealed record IssuanceMutationResult(IssuanceMutationOutcome Outcome,EnrollmentDiagnosticCode DiagnosticCode,
    EnrollmentIdentity? Identity,PersistedIssuedCertificate? Certificate);

public sealed class DefinitiveIssuanceFailure
{
    private DefinitiveIssuanceFailure() { }
    internal static DefinitiveIssuanceFailure FromValidatedAdapterResult() => new();
}
