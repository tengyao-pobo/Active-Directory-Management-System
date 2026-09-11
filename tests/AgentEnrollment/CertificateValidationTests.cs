using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ItManagement.AgentEnrollment.Crypto;

namespace ItManagement.AgentEnrollment.Tests;

public sealed class CertificateValidationTests
{
    [Fact]
    public void ExactIntermediateChainIsAcceptedAndUnusedDuplicateOrWrongOrderIsRejected()
    {
        using var setup = new CertificateSetup();
        using var key1 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var key2 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var middle1 = Authority("middle1", key1, setup.Root, X509SignatureGenerator.CreateForECDsa(setup.RootSigningKey), setup.Now);
        using var leaf1 = setup.IssueThrough(middle1, X509SignatureGenerator.CreateForECDsa(key1));
        var material = EnrollmentCertificateValidator.Validate(leaf1.RawData, [middle1.RawData], [setup.Root], setup.Csr, setup.Identity, setup.Now);
        Assert.Equal(SHA256.HashData(middle1.RawData), material.GetIssuerSha256());
        Assert.Single(material.GetIntermediateDer());
        var copy = material.GetIntermediateDer(); copy[0][0] ^= 1;
        Assert.Equal(middle1.RawData, material.GetIntermediateDer()[0]);
        using var middle2 = Authority("middle2", key2, middle1, X509SignatureGenerator.CreateForECDsa(key1), setup.Now);
        using var leaf2 = setup.IssueThrough(middle2, X509SignatureGenerator.CreateForECDsa(key2));
        EnrollmentCertificateValidator.Validate(leaf2.RawData, [middle2.RawData, middle1.RawData], [setup.Root], setup.Csr, setup.Identity, setup.Now);
        Assert.Throws<EnrollmentCertificateValidationException>(() => EnrollmentCertificateValidator.Validate(
            leaf2.RawData, [middle1.RawData, middle2.RawData], [setup.Root], setup.Csr, setup.Identity, setup.Now));
        Assert.Throws<EnrollmentCertificateValidationException>(() => EnrollmentCertificateValidator.Validate(
            leaf1.RawData, [middle1.RawData, middle1.RawData], [setup.Root], setup.Csr, setup.Identity, setup.Now));
        Assert.Throws<EnrollmentCertificateValidationException>(() => EnrollmentCertificateValidator.Validate(
            leaf1.RawData, [middle1.RawData, middle2.RawData], [setup.Root], setup.Csr, setup.Identity, setup.Now));
    }

    [Fact]
    public void WeakOrNonCaIntermediateIsRejected()
    {
        using var setup = new CertificateSetup();
        using var weakKey = RSA.Create(2048);
        var weakRequest = new CertificateRequest("CN=weak", weakKey, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        weakRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        weakRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var weak = weakRequest.Create(setup.Root.SubjectName, X509SignatureGenerator.CreateForECDsa(setup.RootSigningKey), setup.Now.AddDays(-1), setup.Now.AddDays(100), [4, 5]);
        using var weakLeaf = setup.IssueThrough(weak, X509SignatureGenerator.CreateForRSA(weakKey, RSASignaturePadding.Pkcs1));
        Assert.Throws<EnrollmentCertificateValidationException>(() => EnrollmentCertificateValidator.Validate(
            weakLeaf.RawData, [weak.RawData], [setup.Root], setup.Csr, setup.Identity, setup.Now));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var nonCa = Authority("nonca", key, setup.Root, X509SignatureGenerator.CreateForECDsa(setup.RootSigningKey), setup.Now, ca: false);
        using var nonCaLeaf = setup.IssueThrough(nonCa, X509SignatureGenerator.CreateForECDsa(key));
        Assert.Throws<EnrollmentCertificateValidationException>(() => EnrollmentCertificateValidator.Validate(
            nonCaLeaf.RawData, [nonCa.RawData], [setup.Root], setup.Csr, setup.Identity, setup.Now));
    }

    [Fact]
    public void StrongRsaCsrLeafAndRootAreAccepted()
    {
        using var rootKey = RSA.Create(3072);
        using var key = RSA.Create(3072);
        var now = DateTimeOffset.UtcNow;
        var rootRequest = new CertificateRequest("CN=synthetic-rsa-root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(100));
        var csr = EnrollmentCsrValidator.Validate(new CertificateRequest("CN=untrusted", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest());
        var identity = new EnrollmentCertificateIdentity(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 2);
        var request = new CertificateRequest("CN=platform-device", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.2") }, false));
        var san = new SubjectAlternativeNameBuilder(); san.AddUri(new Uri(EnrollmentCertificateValidator.IdentityUri(identity)));
        request.CertificateExtensions.Add(san.Build());
        using var leaf = request.Create(root, now.AddMinutes(-1), now.AddDays(30), [6, 7]);
        Assert.Equal(identity, EnrollmentCertificateValidator.Validate(leaf.RawData, [], [root], csr, identity, now).Identity);
    }

    private static X509Certificate2 Authority(string name, ECDsa key, X509Certificate2 issuer,
        X509SignatureGenerator signer, DateTimeOffset now, bool ca = true)
    {
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA384);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.Create(issuer.SubjectName, signer, now.AddDays(-1), now.AddDays(100), RandomNumberGenerator.GetBytes(16));
    }

    [Fact]
    public void ExactIssuedMaterialHasExplicitUncheckedRevocationAndDefensiveCopies()
    {
        using var setup = new CertificateSetup();
        using var leaf = setup.Issue();
        var material = setup.Validate(leaf);
        Assert.Equal(setup.Identity, material.Identity);
        Assert.Equal(EnrollmentCertificateValidationScope.IssuanceMaterial, material.ValidationScope);
        Assert.Equal(EnrollmentCertificateRevocationStatus.NotChecked, material.RevocationStatus);
        Assert.Equal(EnrollmentIssuerOperationBindingStatus.NotChecked, material.IssuerOperationBindingStatus);
        Assert.Equal(SHA256.HashData(leaf.RawData), material.GetLeafSha256());
        var copy = material.GetLeafDer(); copy[0] ^= 1;
        Assert.Equal(leaf.RawData, material.GetLeafDer());
        Assert.Empty(material.GetIntermediateDer());
    }

    [Theory]
    [InlineData("otherIdentity")]
    [InlineData("extraSan")]
    [InlineData("serverEku")]
    [InlineData("ca")]
    [InlineData("usage")]
    [InlineData("longLifetime")]
    [InlineData("expired")]
    [InlineData("unknownCritical")]
    [InlineData("unknownNoncritical")]
    [InlineData("criticalSan")]
    [InlineData("noncriticalUsage")]
    public void IdentityAndCertificateProfileViolationsAreRejected(string violation)
    {
        using var setup = new CertificateSetup();
        using var leaf = setup.Issue(violation);
        var exception = Assert.Throws<EnrollmentCertificateValidationException>(() => setup.Validate(leaf));
        Assert.Equal("EnrollmentCertificateRejected", exception.Message);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void DifferentCsrKeyUnpinnedRootAndTrailingBytesAreRejected()
    {
        using var setup = new CertificateSetup();
        using var other = new CertificateSetup();
        using var leaf = setup.Issue();
        Assert.Throws<EnrollmentCertificateValidationException>(() => EnrollmentCertificateValidator.Validate(
            leaf.RawData, [], [setup.Root], other.Csr, setup.Identity, setup.Now));
        Assert.Throws<EnrollmentCertificateValidationException>(() => EnrollmentCertificateValidator.Validate(
            leaf.RawData, [], [other.Root], setup.Csr, setup.Identity, setup.Now));
        Assert.Throws<EnrollmentCertificateValidationException>(() => EnrollmentCertificateValidator.Validate(
            [.. leaf.RawData, 0], [], [setup.Root], setup.Csr, setup.Identity, setup.Now));
        Assert.Throws<EnrollmentCertificateValidationException>(() => EnrollmentCertificateValidator.Validate(
            leaf.RawData, [setup.Root.RawData], [setup.Root], setup.Csr, setup.Identity, setup.Now));
    }

    private sealed class CertificateSetup : IDisposable
    {
        private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public DateTimeOffset Now { get; } = DateTimeOffset.UtcNow;
        public EnrollmentCertificateIdentity Identity { get; } = new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 1);
        public X509Certificate2 Root { get; }
        public ECDsa RootSigningKey => _rootKey;
        public ValidatedEnrollmentCsr Csr { get; }
        public CertificateSetup()
        {
            var request = new CertificateRequest("CN=synthetic-ephemeral-root", _rootKey, HashAlgorithmName.SHA384);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            Root = request.CreateSelfSigned(Now.AddDays(-2), Now.AddDays(365));
            Csr = EnrollmentCsrValidator.Validate(new CertificateRequest("CN=untrusted-csr-name", _key, HashAlgorithmName.SHA256).CreateSigningRequest());
        }
        public X509Certificate2 Issue(string? violation = null)
        {
            return LeafRequest(violation).Create(Root, Now.AddDays(-1), violation == "expired" ? Now.AddHours(-1) : Now.AddDays(violation == "longLifetime" ? 94 : 30), [1, 2, 3, 4]);
        }
        public X509Certificate2 IssueThrough(X509Certificate2 issuer, X509SignatureGenerator generator) =>
            LeafRequest(null).Create(issuer.SubjectName, generator, Now.AddMinutes(-1), Now.AddDays(30), [7, 8]);
        private CertificateRequest LeafRequest(string? violation)
        {
            var request = new CertificateRequest("CN=platform-device", _key, HashAlgorithmName.SHA384);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(violation == "ca", false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(violation == "usage" ? X509KeyUsageFlags.KeyEncipherment : X509KeyUsageFlags.DigitalSignature, violation != "noncriticalUsage"));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
                { new(violation == "serverEku" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, false));
            var san = new SubjectAlternativeNameBuilder();
            san.AddUri(new Uri(EnrollmentCertificateValidator.IdentityUri(violation == "otherIdentity" ? Identity with { DeviceId = Guid.NewGuid() } : Identity)));
            if (violation == "extraSan") san.AddDnsName("unexpected.invalid");
            request.CertificateExtensions.Add(san.Build(violation == "criticalSan"));
            if (violation == "unknownCritical") request.CertificateExtensions.Add(new X509Extension("1.2.3.4", [0x05, 0x00], true));
            if (violation == "unknownNoncritical") request.CertificateExtensions.Add(new X509Extension("1.2.3.4", [0x05, 0x00], false));
            return request;
        }
        public ValidatedIssuedEnrollmentCertificate Validate(X509Certificate2 leaf) =>
            EnrollmentCertificateValidator.Validate(leaf.RawData, [], [Root], Csr, Identity, Now);
        public void Dispose() { Root.Dispose(); _key.Dispose(); _rootKey.Dispose(); }
    }
}
