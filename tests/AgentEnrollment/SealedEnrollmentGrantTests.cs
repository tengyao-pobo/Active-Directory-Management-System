using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using ItManagement.AgentEnrollment.Crypto;

namespace ItManagement.AgentEnrollment.Tests;

public sealed class SealedEnrollmentGrantTests
{
    private static readonly Guid EnvironmentId = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
    private static readonly Guid OperationId = Guid.Parse("fedcba98-7654-3210-fedc-ba9876543210");

    [Fact]
    public void FixedPayloadVectorUsesVersionedCanonicalLayout()
    {
        var token = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();

        var payload = SealedEnrollmentGrant.SerializePayload(EnvironmentId, OperationId, token);

        Assert.Equal(
            "41444752544F4B4E0001000130303131323233332D343435352D363637372D383839392D616162626363646465656666" +
            "66656463626139382D373635342D333231302D666564632D626139383736353433323130" +
            "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            Convert.ToHexString(payload));
    }

    [Fact]
    public void OaepSha256RoundTripBindsContextAndReturnsOnlyDefensiveCopies()
    {
        using var recipient = RSA.Create(3072);
        var spki = recipient.ExportSubjectPublicKeyInfo();
        var token = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();

        var sealedGrant = SealedEnrollmentGrant.SealDeterministic(spki, EnvironmentId, OperationId, token);
        var plaintext = recipient.Decrypt(sealedGrant.GetCiphertext(), RSAEncryptionPadding.OaepSHA256);

        Assert.Equal(SealedEnrollmentGrant.SerializePayload(EnvironmentId, OperationId, token), plaintext);
        Assert.Equal(SHA256.HashData(token), sealedGrant.GetTokenSha256());
        Assert.Equal(SHA256.HashData(spki), sealedGrant.GetRecipientSubjectPublicKeyInfoSha256());
        Assert.Equal(384, sealedGrant.GetCiphertext().Length);

        var ciphertext = sealedGrant.GetCiphertext();
        var tokenHash = sealedGrant.GetTokenSha256();
        var fingerprint = sealedGrant.GetRecipientSubjectPublicKeyInfoSha256();
        ciphertext[0] ^= 1; tokenHash[0] ^= 1; fingerprint[0] ^= 1;
        Assert.NotEqual(ciphertext, sealedGrant.GetCiphertext());
        Assert.Equal(SHA256.HashData(token), sealedGrant.GetTokenSha256());
        Assert.Equal(SHA256.HashData(spki), sealedGrant.GetRecipientSubjectPublicKeyInfoSha256());

        Assert.Empty(typeof(SealedEnrollmentGrant).GetProperties());
        Assert.Equal(
            [nameof(SealedEnrollmentGrant.GetCiphertext), nameof(SealedEnrollmentGrant.GetRecipientSubjectPublicKeyInfoSha256),
                nameof(SealedEnrollmentGrant.GetTokenSha256), nameof(SealedEnrollmentGrant.Seal)],
            typeof(SealedEnrollmentGrant).GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static |
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.DeclaredOnly).Select(method => method.Name).Distinct().Order());
        var sealMethods = typeof(SealedEnrollmentGrant).GetMethods().Where(method => method.Name == nameof(SealedEnrollmentGrant.Seal)).ToArray();
        Assert.Equal(2, sealMethods.Length);
        Assert.Contains(sealMethods, method => method.GetParameters().Select(parameter => parameter.ParameterType)
            .SequenceEqual([typeof(ReadOnlySpan<byte>), typeof(Guid), typeof(Guid)]));
        Assert.Contains(sealMethods, method => method.GetParameters().Select(parameter => parameter.ParameterType)
            .SequenceEqual([typeof(EnrollmentGrantRecipientKey), typeof(Guid), typeof(Guid)]));
        Assert.Equal(typeof(object), typeof(SealedEnrollmentGrant).GetMethod(nameof(ToString), Type.EmptyTypes)!.DeclaringType);
    }

    [Fact]
    public void PublicSealGeneratesANonzeroTokenInsideTheSealedPayload()
    {
        using var recipient = RSA.Create(3072);
        var result = SealedEnrollmentGrant.Seal(recipient.ExportSubjectPublicKeyInfo(), EnvironmentId, OperationId);
        var payload = recipient.Decrypt(result.GetCiphertext(), RSAEncryptionPadding.OaepSHA256);

        Assert.Equal("ADGRTOKN", Encoding.ASCII.GetString(payload, 0, 8));
        Assert.NotEqual(new byte[32], payload[84..]);
        Assert.Equal(SHA256.HashData(payload[84..]), result.GetTokenSha256());
    }

    [Fact]
    public void WrongKeyTamperingSha1AndCrossContextDoNotRecoverTheExpectedGrant()
    {
        using var recipient = RSA.Create(3072);
        using var wrong = RSA.Create(3072);
        var token = RandomNumberGenerator.GetBytes(32);
        var result = SealedEnrollmentGrant.SealDeterministic(recipient.ExportSubjectPublicKeyInfo(), EnvironmentId, OperationId, token);
        var ciphertext = result.GetCiphertext();

        Assert.ThrowsAny<CryptographicException>(() => wrong.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256));
        Assert.ThrowsAny<CryptographicException>(() => recipient.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA1));
        ciphertext[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => recipient.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256));

        var plaintext = recipient.Decrypt(result.GetCiphertext(), RSAEncryptionPadding.OaepSHA256);
        Assert.NotEqual(SealedEnrollmentGrant.SerializePayload(Guid.NewGuid(), OperationId, token), plaintext);
        Assert.NotEqual(SealedEnrollmentGrant.SerializePayload(EnvironmentId, Guid.NewGuid(), token), plaintext);
    }

    [Fact]
    public void EmptyIdentifiersAndInvalidTokensReturnOnlyTheFixedDiagnostic()
    {
        using var recipient = RSA.Create(3072);
        var spki = recipient.ExportSubjectPublicKeyInfo();
        var validated = EnrollmentGrantRecipientKey.Validate(spki);
        foreach (var action in new Action[]
        {
            () => SealedEnrollmentGrant.Seal(spki, Guid.Empty, OperationId),
            () => SealedEnrollmentGrant.Seal(spki, EnvironmentId, Guid.Empty),
            () => SealedEnrollmentGrant.Seal(validated, Guid.Empty, OperationId),
            () => SealedEnrollmentGrant.Seal(validated, EnvironmentId, Guid.Empty),
            () => SealedEnrollmentGrant.SealDeterministic(spki, EnvironmentId, OperationId, new byte[32]),
            () => SealedEnrollmentGrant.SealDeterministic(spki, EnvironmentId, OperationId, new byte[31])
        })
        {
            var error = Assert.Throws<SealedEnrollmentGrantException>(action);
            Assert.Equal("InvalidSealedGrant", error.Message);
            Assert.Null(error.InnerException);
        }
    }

    [Fact]
    public void WeakWrongExponentMalformedTrailingAndOversizedRecipientsAreRejected()
    {
        using var weak = RSA.Create(2048);
        using var valid = RSA.Create(3072);
        var validSpki = valid.ExportSubjectPublicKeyInfo();
        var parameters = valid.ExportParameters(false);
        var wrongExponent = EncodeRsaSpki(parameters.Modulus!, [0x03]);
        var nonCanonicalProfile = EncodeRsaSpki(parameters.Modulus!, parameters.Exponent!, includeNull: false);
        var candidates = new[]
        {
            weak.ExportSubjectPublicKeyInfo(),
            wrongExponent,
            nonCanonicalProfile,
            new byte[] { 0x30, 0x01, 0x00 },
            validSpki.Concat(new byte[] { 0 }).ToArray(),
            new byte[SealedEnrollmentGrant.RecipientSubjectPublicKeyInfoMaximumBytes + 1]
        };

        foreach (var candidate in candidates)
        {
            var validationError = Assert.Throws<SealedEnrollmentGrantException>(() => EnrollmentGrantRecipientKey.Validate(candidate));
            Assert.Equal("InvalidSealedGrant", validationError.Message);
            Assert.Null(validationError.InnerException);
            var error = Assert.Throws<SealedEnrollmentGrantException>(() =>
                SealedEnrollmentGrant.Seal(candidate, EnvironmentId, OperationId));
            Assert.Equal("InvalidSealedGrant", error.Message);
            Assert.Null(error.InnerException);
        }
    }

    [Fact]
    public void ValidatedRecipientPreservesCanonicalSnapshotAcrossCallerMutationsAndSealing()
    {
        using var recipient = RSA.Create(3072);
        var canonical = recipient.ExportSubjectPublicKeyInfo();
        var input = (byte[])canonical.Clone();
        var key = EnrollmentGrantRecipientKey.Validate(input);
        Array.Clear(input);
        var exported = key.GetSubjectPublicKeyInfo();
        var fingerprint = key.GetFingerprintSha256();
        Array.Clear(exported); Array.Clear(fingerprint);

        Assert.Equal(canonical, key.GetSubjectPublicKeyInfo());
        Assert.Equal(SHA256.HashData(canonical), key.GetFingerprintSha256());
        var sealedGrant = SealedEnrollmentGrant.Seal(key, EnvironmentId, OperationId);
        var payload = recipient.Decrypt(sealedGrant.GetCiphertext(), RSAEncryptionPadding.OaepSHA256);
        Assert.Equal(SHA256.HashData(payload[84..]), sealedGrant.GetTokenSha256());
        Assert.Equal(key.GetFingerprintSha256(), sealedGrant.GetRecipientSubjectPublicKeyInfoSha256());
        Assert.Empty(typeof(EnrollmentGrantRecipientKey).GetConstructors());
        Assert.Empty(typeof(EnrollmentGrantRecipientKey).GetProperties());
        Assert.True(typeof(EnrollmentGrantRecipientKey).IsSealed);
    }

    [Fact]
    public void EmptyRecipientAndNullValidatedKeyReturnOnlyFixedDiagnostic()
    {
        foreach (var action in new Action[]
        {
            () => EnrollmentGrantRecipientKey.Validate([]),
            () => SealedEnrollmentGrant.Seal((EnrollmentGrantRecipientKey)null!, EnvironmentId, OperationId)
        })
        {
            var error = Assert.Throws<SealedEnrollmentGrantException>(action);
            Assert.Equal("InvalidSealedGrant", error.Message);
            Assert.Null(error.InnerException);
        }
    }

    private static byte[] EncodeRsaSpki(byte[] modulus, byte[] exponent, bool includeNull = true)
    {
        var keyWriter = new AsnWriter(AsnEncodingRules.DER);
        keyWriter.PushSequence();
        keyWriter.WriteIntegerUnsigned(modulus);
        keyWriter.WriteIntegerUnsigned(exponent);
        keyWriter.PopSequence();

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.1.1");
        if (includeNull) writer.WriteNull();
        writer.PopSequence();
        writer.WriteBitString(keyWriter.Encode());
        writer.PopSequence();
        return writer.Encode();
    }
}
