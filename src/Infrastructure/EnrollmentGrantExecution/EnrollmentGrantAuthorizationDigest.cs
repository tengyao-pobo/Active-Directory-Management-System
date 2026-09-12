using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ItManagement.EnrollmentGrantExecution;

public static class EnrollmentGrantAuthorizationDigest
{
    private static ReadOnlySpan<byte> Magic => "ADGRAUTH"u8;

    public static byte[] Compute(EnrollmentGrantExecutionOperation operation, PersistedEnrollmentGrantPermit permit)
    {
        ArgumentNullException.ThrowIfNull(permit);
        return Compute(operation, permit.PermitVersion, permit.PermitIssuedAt, permit.MintPermitNotAfter,
            permit.GetTokenSha256(), permit.GetRecipientKeyFingerprint(), permit.GetCiphertextSha256());
    }

    public static byte[] Compute(EnrollmentGrantExecutionOperation operation, int permitVersion,
        DateTimeOffset permitIssuedAt, DateTimeOffset mintPermitNotAfter, ReadOnlySpan<byte> tokenSha256,
        ReadOnlySpan<byte> recipientKeyFingerprint, ReadOnlySpan<byte> ciphertextSha256)
    {
        ArgumentNullException.ThrowIfNull(operation);
        if (!operation.IsValid() || permitVersion != 1 ||
            !EnrollmentGrantExecutionOperation.Canonical(permitIssuedAt) ||
            !EnrollmentGrantExecutionOperation.Canonical(mintPermitNotAfter) || mintPermitNotAfter <= permitIssuedAt ||
            mintPermitNotAfter - permitIssuedAt > TimeSpan.FromSeconds(60) ||
            permitIssuedAt < operation.QueuedAt || mintPermitNotAfter > operation.AuthorizationNotAfter || tokenSha256.Length != 32 ||
            recipientKeyFingerprint.Length != 32 || ciphertextSha256.Length != 32)
            throw new ArgumentException("InvalidEnrollmentGrantAuthorizationDigestInput");

        using var stream = new MemoryStream(1024);
        stream.Write(Magic);
        WriteUInt16(stream, 1);
        WriteGuid(stream, operation.EnvironmentId); WriteGuid(stream, operation.Id); WriteGuid(stream, operation.PlanId);
        WriteGuid(stream, operation.RequestId); WriteGuid(stream, operation.ApprovalId); WriteGuid(stream, operation.RequesterId);
        WriteGuid(stream, operation.ApproverId); WriteGuid(stream, operation.RequesterOperatorId);
        WriteGuid(stream, operation.ApproverOperatorId); WriteString(stream, operation.PlanHash);
        WriteGuid(stream, operation.DirectoryObjectId); WriteGuid(stream, operation.ServerDeviceId);
        WriteTime(stream, operation.MappingCreatedAt); WriteGuid(stream, operation.DirectoryGeneration);
        WriteInt64(stream, operation.EnvironmentVersion); WriteBytes(stream, operation.GetRecipientSpki());
        stream.Write(operation.GetRecipientKeyFingerprint()); WriteTime(stream, operation.QueuedAt);
        WriteTime(stream, operation.AuthorizationNotAfter); WriteUInt16(stream, checked((ushort)permitVersion));
        WriteTime(stream, permitIssuedAt); WriteTime(stream, mintPermitNotAfter); stream.Write(tokenSha256);
        stream.Write(recipientKeyFingerprint); stream.Write(ciphertextSha256);
        return SHA256.HashData(stream.GetBuffer().AsSpan(0, checked((int)stream.Length)));
    }

    private static void WriteGuid(Stream stream, Guid value) => stream.Write(Encoding.ASCII.GetBytes(value.ToString("D").ToLowerInvariant()));
    private static void WriteString(Stream stream, string value) => WriteBytes(stream, Encoding.UTF8.GetBytes(value));
    private static void WriteBytes(Stream stream, ReadOnlySpan<byte> value)
    {
        if (value.Length > ushort.MaxValue) throw new ArgumentException("InvalidEnrollmentGrantAuthorizationDigestInput");
        WriteUInt16(stream, checked((ushort)value.Length)); stream.Write(value);
    }
    private static void WriteTime(Stream stream, DateTimeOffset value) =>
        WriteInt64(stream, (value.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10);
    private static void WriteUInt16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); stream.Write(bytes);
    }
    private static void WriteInt64(Stream stream, long value)
    {
        Span<byte> bytes = stackalloc byte[8]; BinaryPrimitives.WriteInt64BigEndian(bytes, value); stream.Write(bytes);
    }
}
