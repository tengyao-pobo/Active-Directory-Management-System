using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace ItManagement.EnrollmentGrantDelivery;

public enum EnrollmentGrantDeliveryOutcome
{
    Available,
    Pending,
    Acknowledged,
    Unavailable,
    NotFound,
    OutcomeUnknown
}

public sealed class EnrollmentGrantDeliveryEnvelope
{
    private const int FingerprintLength = 32;
    private const int CiphertextLength = 384;
    private const int DigestLength = 32;
    private static readonly TimeSpan MaximumDeliveryWindow = TimeSpan.FromSeconds(15);

    private readonly byte[] _recipientKeyFingerprint;
    private readonly byte[] _ciphertext;
    private readonly byte[] _ciphertextSha256;

    private EnrollmentGrantDeliveryEnvelope(
        Guid environmentId,
        Guid operationId,
        byte[] recipientKeyFingerprint,
        byte[] ciphertext,
        byte[] ciphertextSha256,
        DateTimeOffset deliveryNotAfter,
        DateTimeOffset queriedAt)
    {
        EnvironmentId = environmentId;
        OperationId = operationId;
        _recipientKeyFingerprint = recipientKeyFingerprint;
        _ciphertext = ciphertext;
        _ciphertextSha256 = ciphertextSha256;
        DeliveryNotAfter = deliveryNotAfter;
        QueriedAt = queriedAt;
    }

    public short FormatVersion => 1;
    public Guid EnvironmentId { get; }
    public Guid OperationId { get; }
    public DateTimeOffset DeliveryNotAfter { get; }
    public DateTimeOffset QueriedAt { get; }

    public static EnrollmentGrantDeliveryEnvelope Create(
        Guid environmentId,
        Guid operationId,
        short formatVersion,
        byte[] recipientKeyFingerprint,
        byte[] ciphertext,
        byte[] ciphertextSha256,
        DateTimeOffset deliveryNotAfter,
        DateTimeOffset queriedAt)
    {
        if (environmentId == Guid.Empty || operationId == Guid.Empty || formatVersion != 1 ||
            recipientKeyFingerprint is not { Length: FingerprintLength } ||
            ciphertext is not { Length: CiphertextLength } ||
            ciphertextSha256 is not { Length: DigestLength } ||
            !CanonicalDatabaseTime(queriedAt) || !CanonicalDatabaseTime(deliveryNotAfter) ||
            deliveryNotAfter <= queriedAt || deliveryNotAfter - queriedAt > MaximumDeliveryWindow ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData(ciphertext), ciphertextSha256))
            throw Invalid();

        return new EnrollmentGrantDeliveryEnvelope(
            environmentId,
            operationId,
            recipientKeyFingerprint.ToArray(),
            ciphertext.ToArray(),
            ciphertextSha256.ToArray(),
            deliveryNotAfter,
            queriedAt);
    }

    public byte[] GetRecipientKeyFingerprint() => _recipientKeyFingerprint.ToArray();
    public byte[] GetCiphertext() => _ciphertext.ToArray();
    public byte[] GetCiphertextSha256() => _ciphertextSha256.ToArray();
    public override string ToString() => nameof(EnrollmentGrantDeliveryEnvelope);

    private static bool CanonicalDatabaseTime(DateTimeOffset value) =>
        value != DateTimeOffset.MinValue && value != DateTimeOffset.MaxValue &&
        value.Offset == TimeSpan.Zero && value.Ticks % 10 == 0;

    private static ArgumentException Invalid() => new("InvalidEnrollmentGrantDeliveryEnvelope");
}

public sealed class EnrollmentGrantDeliveryResponse
{
    internal EnrollmentGrantDeliveryResponse(
        EnrollmentGrantDeliveryOutcome outcome,
        EnrollmentGrantDeliveryDto? payload)
    {
        Outcome = outcome;
        Payload = payload;
    }

    public EnrollmentGrantDeliveryOutcome Outcome { get; }
    public EnrollmentGrantDeliveryDto? Payload { get; }
    public override string ToString() => nameof(EnrollmentGrantDeliveryResponse);
}

public static class EnrollmentGrantDeliveryResponseFactory
{
    public static EnrollmentGrantDeliveryResponse Create(
        Guid expectedEnvironmentId,
        Guid expectedOperationId,
        EnrollmentGrantDeliveryOutcome outcome,
        EnrollmentGrantDeliveryEnvelope? envelope)
    {
        if (expectedEnvironmentId == Guid.Empty || expectedOperationId == Guid.Empty ||
            !Enum.IsDefined(outcome) ||
            outcome == EnrollmentGrantDeliveryOutcome.Available != (envelope is not null) ||
            envelope is not null && (envelope.EnvironmentId != expectedEnvironmentId ||
                envelope.OperationId != expectedOperationId))
            return Unknown();

        return new EnrollmentGrantDeliveryResponse(
            outcome,
            envelope is null ? null : new EnrollmentGrantDeliveryDto(envelope));
    }

    private static EnrollmentGrantDeliveryResponse Unknown() =>
        new(EnrollmentGrantDeliveryOutcome.OutcomeUnknown, null);
}

public sealed class EnrollmentGrantDeliveryDto
{
    internal EnrollmentGrantDeliveryDto(EnrollmentGrantDeliveryEnvelope envelope)
    {
        FormatVersion = envelope.FormatVersion;
        OperationId = envelope.OperationId;
        RecipientKeyFingerprint = Base64Url.Encode(envelope.GetRecipientKeyFingerprint());
        Ciphertext = Base64Url.Encode(envelope.GetCiphertext());
        CiphertextSha256 = Base64Url.Encode(envelope.GetCiphertextSha256());
        DeliveryNotAfter = envelope.DeliveryNotAfter;
        QueriedAt = envelope.QueriedAt;
    }

    [JsonPropertyName("formatVersion")]
    public short FormatVersion { get; }

    [JsonPropertyName("operationId")]
    public Guid OperationId { get; }

    [JsonPropertyName("recipientKeyFingerprint")]
    public string RecipientKeyFingerprint { get; }

    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; }

    [JsonPropertyName("ciphertextSha256")]
    public string CiphertextSha256 { get; }

    [JsonPropertyName("deliveryNotAfter")]
    public DateTimeOffset DeliveryNotAfter { get; }

    [JsonPropertyName("queriedAt")]
    public DateTimeOffset QueriedAt { get; }

    public override string ToString() => nameof(EnrollmentGrantDeliveryDto);
}

internal static class Base64Url
{
    internal static string Encode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    internal static bool TryDecode32(string? value, out byte[] decoded)
    {
        decoded = [];
        if (value is not { Length: 43 }) return false;
        foreach (var character in value)
            if (!(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_'))
                return false;

        try
        {
            var candidate = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + "=");
            if (candidate.Length != 32 || !string.Equals(value, Encode(candidate), StringComparison.Ordinal))
                return false;
            decoded = candidate;
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
