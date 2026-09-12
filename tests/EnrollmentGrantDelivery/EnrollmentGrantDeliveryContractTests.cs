using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ItManagement.EnrollmentGrantDelivery;
using Xunit;

namespace EnrollmentGrantDelivery.Tests;

public sealed class EnrollmentGrantDeliveryContractTests
{
    private static readonly DateTimeOffset QueriedAt = new(2032, 1, 2, 3, 4, 5, TimeSpan.Zero);

    [Fact]
    public void AvailableResponseBindsIdentityAndSerializesOnlyThePublicEnvelope()
    {
        var environment = Guid.NewGuid();
        var operation = Guid.NewGuid();
        var envelope = Envelope(environment, operation);

        var response = EnrollmentGrantDeliveryResponseFactory.Create(
            environment, operation, EnrollmentGrantDeliveryOutcome.Available, envelope);
        var payload = Assert.IsType<EnrollmentGrantDeliveryDto>(response.Payload);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(payload));

        Assert.Equal(EnrollmentGrantDeliveryOutcome.Available, response.Outcome);
        Assert.Equal(
            ["ciphertext", "ciphertextSha256", "deliveryNotAfter", "formatVersion", "operationId", "queriedAt", "recipientKeyFingerprint"],
            json.RootElement.EnumerateObject().Select(property => property.Name).Order().ToArray());
        Assert.Equal(1, json.RootElement.GetProperty("formatVersion").GetInt16());
        Assert.Equal(operation, json.RootElement.GetProperty("operationId").GetGuid());
        Assert.DoesNotContain('=', json.RootElement.GetProperty("recipientKeyFingerprint").GetString()!);
        Assert.DoesNotContain('=', json.RootElement.GetProperty("ciphertext").GetString()!);
        Assert.DoesNotContain('=', json.RootElement.GetProperty("ciphertextSha256").GetString()!);
        Assert.Equal(TimeSpan.Zero, json.RootElement.GetProperty("deliveryNotAfter").GetDateTimeOffset().Offset);
        Assert.Equal(TimeSpan.Zero, json.RootElement.GetProperty("queriedAt").GetDateTimeOffset().Offset);
    }

    [Theory]
    [InlineData(EnrollmentGrantDeliveryOutcome.Pending)]
    [InlineData(EnrollmentGrantDeliveryOutcome.Acknowledged)]
    [InlineData(EnrollmentGrantDeliveryOutcome.Unavailable)]
    [InlineData(EnrollmentGrantDeliveryOutcome.NotFound)]
    [InlineData(EnrollmentGrantDeliveryOutcome.OutcomeUnknown)]
    public void KnownNonAvailableOutcomesHaveNoPayload(EnrollmentGrantDeliveryOutcome outcome)
    {
        var response = EnrollmentGrantDeliveryResponseFactory.Create(
            Guid.NewGuid(), Guid.NewGuid(), outcome, null);
        Assert.Equal(outcome, response.Outcome);
        Assert.Null(response.Payload);
    }

    [Fact]
    public void ResponseFactoryFailsClosedOnIdentityAndShapeMismatch()
    {
        var environment = Guid.NewGuid();
        var operation = Guid.NewGuid();
        var envelope = Envelope(environment, operation);

        AssertUnknown(EnrollmentGrantDeliveryResponseFactory.Create(
            Guid.NewGuid(), operation, EnrollmentGrantDeliveryOutcome.Available, envelope));
        AssertUnknown(EnrollmentGrantDeliveryResponseFactory.Create(
            environment, Guid.NewGuid(), EnrollmentGrantDeliveryOutcome.Available, envelope));
        AssertUnknown(EnrollmentGrantDeliveryResponseFactory.Create(
            environment, operation, EnrollmentGrantDeliveryOutcome.Available, null));
        AssertUnknown(EnrollmentGrantDeliveryResponseFactory.Create(
            environment, operation, EnrollmentGrantDeliveryOutcome.Pending, envelope));
        AssertUnknown(EnrollmentGrantDeliveryResponseFactory.Create(
            environment, operation, (EnrollmentGrantDeliveryOutcome)int.MaxValue, null));
        AssertUnknown(EnrollmentGrantDeliveryResponseFactory.Create(
            Guid.Empty, operation, EnrollmentGrantDeliveryOutcome.NotFound, null));
    }

    [Fact]
    public void EnvelopeDefensivelyCopiesEveryByteArray()
    {
        var fingerprint = Bytes(32, 1);
        var ciphertext = Bytes(384, 2);
        var digest = SHA256.HashData(ciphertext);
        var envelope = EnrollmentGrantDeliveryEnvelope.Create(
            Guid.NewGuid(), Guid.NewGuid(), 1, fingerprint, ciphertext, digest,
            QueriedAt.AddSeconds(15), QueriedAt);

        fingerprint[0] ^= 0xff;
        ciphertext[0] ^= 0xff;
        digest[0] ^= 0xff;
        var returnedFingerprint = envelope.GetRecipientKeyFingerprint();
        var returnedCiphertext = envelope.GetCiphertext();
        var returnedDigest = envelope.GetCiphertextSha256();
        returnedFingerprint[1] ^= 0xff;
        returnedCiphertext[1] ^= 0xff;
        returnedDigest[1] ^= 0xff;

        Assert.Equal(Bytes(32, 1), envelope.GetRecipientKeyFingerprint());
        Assert.Equal(Bytes(384, 2), envelope.GetCiphertext());
        Assert.Equal(SHA256.HashData(Bytes(384, 2)), envelope.GetCiphertextSha256());
    }

    [Fact]
    public void EnvelopeRejectsMalformedIdentityVersionLengthsAndDigest()
    {
        var environment = Guid.NewGuid();
        var operation = Guid.NewGuid();
        var fingerprint = Bytes(32, 1);
        var ciphertext = Bytes(384, 2);
        var digest = SHA256.HashData(ciphertext);

        AssertEnvelopeInvalid(Guid.Empty, operation, 1, fingerprint, ciphertext, digest, QueriedAt.AddSeconds(1), QueriedAt);
        AssertEnvelopeInvalid(environment, Guid.Empty, 1, fingerprint, ciphertext, digest, QueriedAt.AddSeconds(1), QueriedAt);
        AssertEnvelopeInvalid(environment, operation, 2, fingerprint, ciphertext, digest, QueriedAt.AddSeconds(1), QueriedAt);
        AssertEnvelopeInvalid(environment, operation, 1, Bytes(31, 1), ciphertext, digest, QueriedAt.AddSeconds(1), QueriedAt);
        AssertEnvelopeInvalid(environment, operation, 1, fingerprint, Bytes(383, 2), digest, QueriedAt.AddSeconds(1), QueriedAt);
        AssertEnvelopeInvalid(environment, operation, 1, fingerprint, ciphertext, Bytes(31, 3), QueriedAt.AddSeconds(1), QueriedAt);
        var wrongDigest = digest.ToArray();
        wrongDigest[0] ^= 0xff;
        AssertEnvelopeInvalid(environment, operation, 1, fingerprint, ciphertext, wrongDigest, QueriedAt.AddSeconds(1), QueriedAt);
    }

    [Fact]
    public void EnvelopeRejectsNonCanonicalAndOutOfWindowTimesWithoutOverflow()
    {
        var offset = QueriedAt.ToOffset(TimeSpan.FromHours(1));
        var subMicrosecond = QueriedAt.AddTicks(1);
        AssertTimeInvalid(QueriedAt, QueriedAt);
        AssertTimeInvalid(QueriedAt.AddSeconds(15).AddTicks(10), QueriedAt);
        AssertTimeInvalid(offset.AddSeconds(1), offset);
        AssertTimeInvalid(subMicrosecond.AddSeconds(1), subMicrosecond);
        AssertTimeInvalid(DateTimeOffset.MaxValue, QueriedAt);
        AssertTimeInvalid(QueriedAt.AddSeconds(1), DateTimeOffset.MinValue);

        _ = Envelope(Guid.NewGuid(), Guid.NewGuid(), QueriedAt.AddSeconds(15));
        var nearMaximum = DateTimeOffset.MaxValue.AddTicks(-9);
        var ciphertext = Bytes(384, 2);
        _ = EnrollmentGrantDeliveryEnvelope.Create(
            Guid.NewGuid(), Guid.NewGuid(), 1, Bytes(32, 1), ciphertext, SHA256.HashData(ciphertext),
            nearMaximum, nearMaximum.AddSeconds(-1));
    }

    [Fact]
    public void AcknowledgementParsesExactCanonicalJsonAndDefensivelyCopies()
    {
        var fingerprint = Bytes(32, 7);
        var digest = Bytes(32, 8);
        var json = AckJson(fingerprint, digest);

        Assert.True(EnrollmentGrantDeliveryAcknowledgement.TryParse(json, out var acknowledgement));
        Assert.NotNull(acknowledgement);
        var returnedFingerprint = acknowledgement.GetRecipientKeyFingerprint();
        var returnedDigest = acknowledgement.GetCiphertextSha256();
        returnedFingerprint[0] ^= 0xff;
        returnedDigest[0] ^= 0xff;

        Assert.Equal(1, acknowledgement.FormatVersion);
        Assert.Equal(fingerprint, acknowledgement.GetRecipientKeyFingerprint());
        Assert.Equal(digest, acknowledgement.GetCiphertextSha256());
    }

    public static TheoryData<string> InvalidAcknowledgements => new()
    {
        "{}",
        "[]",
        "null",
        "{\"formatVersion\":2,\"recipientKeyFingerprint\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"ciphertextSha256\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}",
        "{\"FormatVersion\":1,\"recipientKeyFingerprint\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"ciphertextSha256\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}",
        "{\"formatVersion\":1,\"formatVersion\":1,\"recipientKeyFingerprint\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"ciphertextSha256\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}",
        "{\"formatVersion\":1,\"recipientKeyFingerprint\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"ciphertextSha256\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"extra\":0}",
        "{\"formatVersion\":1,\"recipientKeyFingerprint\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"ciphertextSha256\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}",
        "{\"formatVersion\":1,\"recipientKeyFingerprint\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+\",\"ciphertextSha256\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}",
        "{\"formatVersion\":1,\"recipientKeyFingerprint\":\"short\",\"ciphertextSha256\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}",
        "{\"formatVersion\":1,\"recipientKeyFingerprint\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}"
    };

    [Theory]
    [MemberData(nameof(InvalidAcknowledgements))]
    public void AcknowledgementRejectsMalformedNonCanonicalOrOpenJson(string json)
    {
        Assert.False(EnrollmentGrantDeliveryAcknowledgement.TryParse(Encoding.UTF8.GetBytes(json), out var acknowledgement));
        Assert.Null(acknowledgement);
    }

    [Fact]
    public void AcknowledgementRejectsOversizedAndInvalidUtf8Json()
    {
        Assert.False(EnrollmentGrantDeliveryAcknowledgement.TryParse(new byte[1025], out _));
        Assert.False(EnrollmentGrantDeliveryAcknowledgement.TryParse([0xff, 0xfe], out _));
    }

    private static EnrollmentGrantDeliveryEnvelope Envelope(Guid environment, Guid operation) =>
        Envelope(environment, operation, QueriedAt.AddSeconds(10));

    private static EnrollmentGrantDeliveryEnvelope Envelope(
        Guid environment,
        Guid operation,
        DateTimeOffset deliveryNotAfter)
    {
        var ciphertext = Bytes(384, 2);
        return EnrollmentGrantDeliveryEnvelope.Create(
            environment, operation, 1, Bytes(32, 1), ciphertext, SHA256.HashData(ciphertext),
            deliveryNotAfter, QueriedAt);
    }

    private static byte[] AckJson(byte[] fingerprint, byte[] digest) => Encoding.UTF8.GetBytes(
        $"{{\"formatVersion\":1,\"recipientKeyFingerprint\":\"{Base64Url(fingerprint)}\",\"ciphertextSha256\":\"{Base64Url(digest)}\"}}");

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Bytes(int length, byte seed) =>
        Enumerable.Range(0, length).Select(index => (byte)(seed + index)).ToArray();

    private static void AssertUnknown(EnrollmentGrantDeliveryResponse response)
    {
        Assert.Equal(EnrollmentGrantDeliveryOutcome.OutcomeUnknown, response.Outcome);
        Assert.Null(response.Payload);
    }

    private static void AssertTimeInvalid(DateTimeOffset deliveryNotAfter, DateTimeOffset queriedAt)
    {
        var ciphertext = Bytes(384, 2);
        AssertEnvelopeInvalid(
            Guid.NewGuid(), Guid.NewGuid(), 1, Bytes(32, 1), ciphertext, SHA256.HashData(ciphertext),
            deliveryNotAfter, queriedAt);
    }

    private static void AssertEnvelopeInvalid(
        Guid environment,
        Guid operation,
        short version,
        byte[] fingerprint,
        byte[] ciphertext,
        byte[] digest,
        DateTimeOffset deliveryNotAfter,
        DateTimeOffset queriedAt)
    {
        var error = Assert.Throws<ArgumentException>(() => EnrollmentGrantDeliveryEnvelope.Create(
            environment, operation, version, fingerprint, ciphertext, digest, deliveryNotAfter, queriedAt));
        Assert.Equal("InvalidEnrollmentGrantDeliveryEnvelope", error.Message);
    }
}
