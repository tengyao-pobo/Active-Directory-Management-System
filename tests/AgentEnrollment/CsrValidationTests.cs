using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ItManagement.AgentEnrollment.Crypto;

namespace ItManagement.AgentEnrollment.Tests;

public sealed class CsrValidationTests
{
    [Fact]
    public void RsaSignatureAndImmutableHashesAreVerified()
    {
        using var key = RSA.Create(3072);
        var request = new CertificateRequest("CN=untrusted-name", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var der = request.CreateSigningRequest();
        var validated = EnrollmentCsrValidator.Validate(der);
        Assert.Equal("RSA", validated.KeyAlgorithm);
        Assert.Equal(3072, validated.KeySizeBits);
        Assert.Equal(SHA256.HashData(der), validated.GetCsrSha256());
        Assert.Equal(SHA256.HashData(key.ExportSubjectPublicKeyInfo()), validated.GetSubjectPublicKeyInfoSha256());
        var saved = validated.GetDer();
        der[0] ^= 1;
        var returned = validated.GetDer(); returned[0] ^= 1;
        Assert.Equal(saved, validated.GetDer());
    }

    [Theory]
    [InlineData("P256")]
    [InlineData("P384")]
    public void NamedCurveMatchingHashIsAcceptedAndRequestedIdentityIsNotExposed(string curve)
    {
        using var key = ECDsa.Create(curve == "P256" ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
        var request = new CertificateRequest("CN=not-server-authority", key,
            curve == "P256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384);
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("untrusted.invalid");
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var result = EnrollmentCsrValidator.Validate(request.CreateSigningRequest());
        Assert.Equal("ECDSA", result.KeyAlgorithm);
        Assert.Equal(curve == "P256" ? 256 : 384, result.KeySizeBits);
        Assert.DoesNotContain(typeof(ValidatedEnrollmentCsr).GetProperties(), p =>
            p.Name.Contains("SubjectName", StringComparison.Ordinal) || p.PropertyType == typeof(CertificateRequest));
    }

    [Fact]
    public void WeakKeyCorruptedSignatureAndTrailingDataAreRejected()
    {
        using var weak = RSA.Create(2048);
        var weakDer = new CertificateRequest("CN=weak", weak, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();
        Assert.Throws<EnrollmentCsrValidationException>(() => EnrollmentCsrValidator.Validate(weakDer));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var der = new CertificateRequest("CN=synthetic", key, HashAlgorithmName.SHA256).CreateSigningRequest();
        Assert.Throws<EnrollmentCsrValidationException>(() => EnrollmentCsrValidator.Validate([.. der, 0]));
        der[^1] ^= 1;
        Assert.Throws<EnrollmentCsrValidationException>(() => EnrollmentCsrValidator.Validate(der));
    }

    [Fact]
    public void CurveHashMismatchAndUnsupportedCurveAreRejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var wrongHash = new CertificateRequest("CN=synthetic", key, HashAlgorithmName.SHA384).CreateSigningRequest();
        Assert.Throws<EnrollmentCsrValidationException>(() => EnrollmentCsrValidator.Validate(wrongHash));
        using var unsupported = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var der = new CertificateRequest("CN=synthetic", unsupported, HashAlgorithmName.SHA512).CreateSigningRequest();
        Assert.Throws<EnrollmentCsrValidationException>(() => EnrollmentCsrValidator.Validate(der));
    }

    [Fact]
    public void InvalidSizeAndMalformedDerReturnOnlyFixedDiagnostic()
    {
        foreach (var input in new[] { Array.Empty<byte>(), new byte[EnrollmentCsrValidator.MaximumDerBytes + 1], new byte[] { 0x30, 1, 0 } })
        {
            var error = Assert.Throws<EnrollmentCsrValidationException>(() => EnrollmentCsrValidator.Validate(input));
            Assert.Equal("EnrollmentCsrRejected", error.Message);
            Assert.Null(error.InnerException);
        }
    }
}
