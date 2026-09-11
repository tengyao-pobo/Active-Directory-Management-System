using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ItManagement.AgentEnrollment.Crypto;

public sealed class SealedEnrollmentGrantException() : Exception("InvalidSealedGrant");

public sealed class SealedEnrollmentGrant
{
    public const int RecipientSubjectPublicKeyInfoMaximumBytes = 512;
    public const int TokenBytes = 32;
    internal const int PayloadBytes = 116;

    private static ReadOnlySpan<byte> Magic => "ADGRTOKN"u8;
    private readonly byte[] _ciphertext;
    private readonly byte[] _tokenSha256;
    private readonly byte[] _recipientSubjectPublicKeyInfoSha256;

    private SealedEnrollmentGrant(byte[] ciphertext, byte[] tokenSha256, byte[] recipientSubjectPublicKeyInfoSha256)
    {
        _ciphertext = (byte[])ciphertext.Clone();
        _tokenSha256 = (byte[])tokenSha256.Clone();
        _recipientSubjectPublicKeyInfoSha256 = (byte[])recipientSubjectPublicKeyInfoSha256.Clone();
    }

    public static SealedEnrollmentGrant Seal(
        ReadOnlySpan<byte> recipientSubjectPublicKeyInfoDer,
        Guid environmentId,
        Guid operationId)
        => Seal(EnrollmentGrantRecipientKey.Validate(recipientSubjectPublicKeyInfoDer), environmentId, operationId);

    public static SealedEnrollmentGrant Seal(
        EnrollmentGrantRecipientKey recipientKey,
        Guid environmentId,
        Guid operationId)
    {
        if (recipientKey is null || environmentId == Guid.Empty || operationId == Guid.Empty)
            throw new SealedEnrollmentGrantException();
        var token = new byte[TokenBytes];
        try
        {
            do
            {
                RandomNumberGenerator.Fill(token);
            }
            while (CryptographicOperations.FixedTimeEquals(token, new byte[TokenBytes]));

            return SealValidated(recipientKey, environmentId, operationId, token);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(token);
        }
    }

    public byte[] GetCiphertext() => (byte[])_ciphertext.Clone();

    public byte[] GetTokenSha256() => (byte[])_tokenSha256.Clone();

    public byte[] GetRecipientSubjectPublicKeyInfoSha256() =>
        (byte[])_recipientSubjectPublicKeyInfoSha256.Clone();

    internal static SealedEnrollmentGrant SealDeterministic(
        ReadOnlySpan<byte> recipientSubjectPublicKeyInfoDer,
        Guid environmentId,
        Guid operationId,
        ReadOnlySpan<byte> token)
        => SealValidated(EnrollmentGrantRecipientKey.Validate(recipientSubjectPublicKeyInfoDer), environmentId, operationId, token);

    private static SealedEnrollmentGrant SealValidated(
        EnrollmentGrantRecipientKey recipientKey,
        Guid environmentId,
        Guid operationId,
        ReadOnlySpan<byte> token)
    {
        byte[]? payload = null;
        byte[]? tokenCopy = null;
        try
        {
            ValidateIdentifiersAndToken(environmentId, operationId, token);
            using var recipient = recipientKey.Import();
            tokenCopy = token.ToArray();
            payload = SerializePayload(environmentId, operationId, tokenCopy);
            var ciphertext = recipient.Encrypt(payload, RSAEncryptionPadding.OaepSHA256);
            return new(
                ciphertext,
                SHA256.HashData(tokenCopy),
                recipientKey.GetFingerprintSha256());
        }
        catch (SealedEnrollmentGrantException)
        {
            throw;
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        {
            throw new SealedEnrollmentGrantException();
        }
        finally
        {
            if (payload is not null) CryptographicOperations.ZeroMemory(payload);
            if (tokenCopy is not null) CryptographicOperations.ZeroMemory(tokenCopy);
        }
    }

    internal static byte[] SerializePayload(Guid environmentId, Guid operationId, ReadOnlySpan<byte> token)
    {
        ValidateIdentifiersAndToken(environmentId, operationId, token);
        var payload = new byte[PayloadBytes];
        Magic.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(8, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(10, 2), 1);
        WriteGuid(environmentId, payload.AsSpan(12, 36));
        WriteGuid(operationId, payload.AsSpan(48, 36));
        token.CopyTo(payload.AsSpan(84, TokenBytes));
        return payload;
    }

    private static void ValidateIdentifiersAndToken(Guid environmentId, Guid operationId, ReadOnlySpan<byte> token)
    {
        if (environmentId == Guid.Empty || operationId == Guid.Empty || token.Length != TokenBytes || IsAllZero(token))
            throw new SealedEnrollmentGrantException();
    }

    private static bool IsAllZero(ReadOnlySpan<byte> value)
    {
        var aggregate = 0;
        foreach (var item in value) aggregate |= item;
        return aggregate == 0;
    }

    private static void WriteGuid(Guid value, Span<byte> destination)
    {
        if (!Encoding.ASCII.TryGetBytes(value.ToString("D").ToLowerInvariant(), destination, out var written) || written != 36)
            throw new SealedEnrollmentGrantException();
    }
}
