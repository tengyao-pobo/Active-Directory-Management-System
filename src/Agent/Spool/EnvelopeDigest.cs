using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ItManagement.Agent.Spool;

public static class EnvelopeDigest
{
    // Version 2 replaces the predeployment JSON-framed digest. Existing development
    // spool files fail closed during validation; there is intentionally no migration.
    public const int HashVersion = 2;

    public static string Compute(SpoolEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return Compute(
            envelope.ProtocolVersion,
            envelope.DeviceGuid,
            envelope.RegistrationEpoch,
            envelope.Sequence,
            envelope.RequestId,
            envelope.ObservedAt,
            envelope.PayloadHash);
    }

    public static string Compute(
        int protocolVersion,
        Guid deviceGuid,
        long registrationEpoch,
        long sequence,
        Guid requestId,
        DateTimeOffset observedAt,
        string payloadHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payloadHash);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendInt32(hash, HashVersion);
        AppendInt32(hash, protocolVersion);
        AppendString(hash, deviceGuid.ToString("D"));
        AppendInt64(hash, registrationEpoch);
        AppendInt64(hash, sequence);
        AppendString(hash, requestId.ToString("D"));
        AppendInt64(hash, observedAt.UtcTicks);
        AppendString(hash, payloadHash);
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static void AppendString(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        AppendInt32(hash, bytes.Length);
        hash.AppendData(bytes);
    }

    private static void AppendInt32(IncrementalHash hash, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        hash.AppendData(bytes);
    }

    private static void AppendInt64(IncrementalHash hash, long value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(bytes, value);
        hash.AppendData(bytes);
    }
}
