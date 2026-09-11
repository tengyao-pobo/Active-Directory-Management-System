using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ItManagement.AgentEnrollment.Crypto;

public enum EnrollmentCertificateValidationScope { IssuanceMaterial }
public enum EnrollmentCertificateRevocationStatus { NotChecked }
public enum EnrollmentIssuerOperationBindingStatus { NotChecked }
public sealed record EnrollmentCertificateIdentity(Guid EnvironmentId, Guid DeviceId, Guid RegistrationId,
    Guid DeviceGuid, long RegistrationEpoch);
public sealed class EnrollmentCertificateValidationException() : Exception("EnrollmentCertificateRejected");

public sealed class ValidatedIssuedEnrollmentCertificate
{
    private readonly byte[] _leaf, _leafHash, _spkiHash, _serial, _issuerHash;
    private readonly byte[][] _intermediates;
    internal ValidatedIssuedEnrollmentCertificate(byte[] leaf, byte[][] intermediates, byte[] spkiHash,
        byte[] serial, byte[] issuerHash, DateTimeOffset notBefore, DateTimeOffset notAfter, EnrollmentCertificateIdentity identity)
    {
        _leaf = (byte[])leaf.Clone(); _leafHash = SHA256.HashData(leaf); _spkiHash = (byte[])spkiHash.Clone();
        _serial = (byte[])serial.Clone(); _issuerHash = (byte[])issuerHash.Clone();
        _intermediates = intermediates.Select(x => (byte[])x.Clone()).ToArray();
        NotBefore = notBefore; NotAfter = notAfter; Identity = identity;
    }
    public EnrollmentCertificateIdentity Identity { get; }
    public DateTimeOffset NotBefore { get; }
    public DateTimeOffset NotAfter { get; }
    public int ProfileVersion => 1;
    public EnrollmentCertificateValidationScope ValidationScope => EnrollmentCertificateValidationScope.IssuanceMaterial;
    public EnrollmentCertificateRevocationStatus RevocationStatus => EnrollmentCertificateRevocationStatus.NotChecked;
    public EnrollmentIssuerOperationBindingStatus IssuerOperationBindingStatus => EnrollmentIssuerOperationBindingStatus.NotChecked;
    public byte[] GetLeafDer() => (byte[])_leaf.Clone();
    public byte[] GetLeafSha256() => (byte[])_leafHash.Clone();
    public byte[] GetSubjectPublicKeyInfoSha256() => (byte[])_spkiHash.Clone();
    public byte[] GetSerialNumber() => (byte[])_serial.Clone();
    public byte[] GetIssuerSha256() => (byte[])_issuerHash.Clone();
    public byte[][] GetIntermediateDer() => _intermediates.Select(x => (byte[])x.Clone()).ToArray();
}

// Only the reviewed issuer adapter in this assembly may construct issuance material.
// This validator does not authenticate a TLS peer or establish current revocation state.
internal static class EnrollmentCertificateValidator
{
    internal static ValidatedIssuedEnrollmentCertificate Validate(ReadOnlySpan<byte> leafDer,
        IReadOnlyList<byte[]> intermediateDer, IReadOnlyList<X509Certificate2> configuredRoots,
        ValidatedEnrollmentCsr csr, EnrollmentCertificateIdentity expected, DateTimeOffset validationTime)
    {
        ArgumentNullException.ThrowIfNull(intermediateDer);
        ArgumentNullException.ThrowIfNull(configuredRoots);
        ArgumentNullException.ThrowIfNull(csr);
        ArgumentNullException.ThrowIfNull(expected);
        if (leafDer.Length is < 1 or > 32 * 1024 || intermediateDer.Count > 8 || configuredRoots.Count is < 1 or > 8 ||
            expected.EnvironmentId == Guid.Empty || expected.DeviceId == Guid.Empty || expected.RegistrationId == Guid.Empty ||
            expected.DeviceGuid == Guid.Empty || expected.RegistrationEpoch <= 0)
            throw new EnrollmentCertificateValidationException();
        var intermediates = new List<X509Certificate2>();
        try
        {
            var leafBytes = leafDer.ToArray();
            RequireSingleDer(leafBytes);
            using var leaf = X509CertificateLoader.LoadCertificate(leafBytes);
            RequireSha2Signature(leaf);
            var seen = new HashSet<string>(StringComparer.Ordinal) { Convert.ToHexString(SHA256.HashData(leafBytes)) };
            foreach (var root in configuredRoots)
            {
                if (root is null || root.RawData.Length > 32 * 1024 || !seen.Add(Convert.ToHexString(SHA256.HashData(root.RawData))))
                    throw new EnrollmentCertificateValidationException();
                ValidateAuthority(root);
            }
            var copies = new List<byte[]>();
            var aggregate = leafBytes.Length;
            foreach (var bytes in intermediateDer)
            {
                if (bytes is null || bytes.Length is < 1 or > 32 * 1024 || aggregate > 128 * 1024 - bytes.Length)
                    throw new EnrollmentCertificateValidationException();
                aggregate += bytes.Length;
                var copy = (byte[])bytes.Clone();
                RequireSingleDer(copy);
                if (!seen.Add(Convert.ToHexString(SHA256.HashData(copy)))) throw new EnrollmentCertificateValidationException();
                var intermediate = X509CertificateLoader.LoadCertificate(copy);
                intermediates.Add(intermediate);
                ValidateAuthority(intermediate);
                copies.Add(copy);
            }
            var before = new DateTimeOffset(leaf.NotBefore.ToUniversalTime());
            var after = new DateTimeOffset(leaf.NotAfter.ToUniversalTime());
            if (before > validationTime.AddMinutes(5) || after <= validationTime || after <= before || after - before > TimeSpan.FromDays(93))
                throw new EnrollmentCertificateValidationException();
            var spkiHash = SHA256.HashData(leaf.PublicKey.ExportSubjectPublicKeyInfo());
            if (!CryptographicOperations.FixedTimeEquals(spkiHash, csr.GetSubjectPublicKeyInfoSha256()))
                throw new EnrollmentCertificateValidationException();
            ValidateExtensions(leaf, expected);
            var serial = ReadPositiveSerial(leafBytes);

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(configuredRoots.ToArray());
            chain.ChainPolicy.ExtraStore.AddRange(intermediates.ToArray());
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = (before > validationTime ? before : validationTime).UtcDateTime;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
            if (!chain.Build(leaf) || chain.ChainElements.Count != intermediates.Count + 2)
                throw new EnrollmentCertificateValidationException();
            // Reject paths supplemented or reordered by platform caches: only the supplied exact intermediates and pinned root count.
            for (var index = 0; index < intermediates.Count; index++)
                if (!chain.ChainElements[index + 1].Certificate.RawData.AsSpan().SequenceEqual(copies[index]))
                    throw new EnrollmentCertificateValidationException();
            var rootBytes = chain.ChainElements[^1].Certificate.RawData;
            if (!configuredRoots.Any(root => root.RawData.AsSpan().SequenceEqual(rootBytes)))
                throw new EnrollmentCertificateValidationException();
            return new(leafBytes, copies.ToArray(), spkiHash, serial,
                SHA256.HashData(chain.ChainElements[1].Certificate.RawData), before, after, expected);
        }
        catch (Exception error) when (error is CryptographicException or AsnContentException or ArgumentException)
        { throw new EnrollmentCertificateValidationException(); }
        finally { foreach (var certificate in intermediates) certificate.Dispose(); }
    }

    internal static string IdentityUri(EnrollmentCertificateIdentity identity) =>
        FormattableString.Invariant($"urn:itmanagement:agent:v1:{identity.EnvironmentId:N}:{identity.DeviceId:N}:{identity.RegistrationId:N}:{identity.RegistrationEpoch}:{identity.DeviceGuid:N}");

    private static void ValidateExtensions(X509Certificate2 leaf, EnrollmentCertificateIdentity identity)
    {
        var extensions = new Dictionary<string, X509Extension>(StringComparer.Ordinal);
        foreach (var extension in leaf.Extensions)
        {
            var oid = extension.Oid?.Value;
            if (oid is not ("2.5.29.19" or "2.5.29.15" or "2.5.29.37" or "2.5.29.17" or "2.5.29.14" or "2.5.29.35") || !extensions.TryAdd(oid, extension) ||
                (extension.Critical && oid is not ("2.5.29.19" or "2.5.29.15" or "2.5.29.37" or "2.5.29.17")))
                throw new EnrollmentCertificateValidationException();
        }
        if (!extensions.TryGetValue("2.5.29.19", out var constraints) ||
            !extensions.TryGetValue("2.5.29.15", out var usage) ||
            !extensions.TryGetValue("2.5.29.37", out var eku) ||
            !extensions.TryGetValue("2.5.29.17", out var san)) throw new EnrollmentCertificateValidationException();
        var basic = new X509BasicConstraintsExtension(); basic.CopyFrom(constraints);
        var keyUsage = new X509KeyUsageExtension(); keyUsage.CopyFrom(usage);
        var enhanced = new X509EnhancedKeyUsageExtension(); enhanced.CopyFrom(eku);
        if (!constraints.Critical || !usage.Critical || eku.Critical || san.Critical ||
            basic.CertificateAuthority || basic.HasPathLengthConstraint || keyUsage.KeyUsages != X509KeyUsageFlags.DigitalSignature ||
            enhanced.EnhancedKeyUsages.Count != 1 || enhanced.EnhancedKeyUsages[0].Value != "1.3.6.1.5.5.7.3.2")
            throw new EnrollmentCertificateValidationException();
        var reader = new AsnReader(san.RawData, AsnEncodingRules.DER);
        var names = reader.ReadSequence(); reader.ThrowIfNotEmpty();
        var uri = names.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6));
        names.ThrowIfNotEmpty();
        if (!string.Equals(uri, IdentityUri(identity), StringComparison.Ordinal)) throw new EnrollmentCertificateValidationException();
    }

    private static byte[] ReadPositiveSerial(byte[] der)
    {
        var outer = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
        var tbs = outer.ReadSequence();
        if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0))) tbs.ReadEncodedValue();
        var raw = tbs.ReadIntegerBytes().Span;
        if ((raw[0] & 0x80) != 0) throw new EnrollmentCertificateValidationException();
        var serial = (raw[0] == 0 ? raw[1..] : raw).ToArray();
        if (serial.Length is < 1 or > 20 || !serial.Any(value => value != 0)) throw new EnrollmentCertificateValidationException();
        return serial;
    }

    private static void RequireSingleDer(byte[] bytes)
    {
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);
        reader.ReadSequence(); reader.ThrowIfNotEmpty();
    }

    private static void RequireSha2Signature(X509Certificate2 certificate)
    {
        if (certificate.SignatureAlgorithm.Value is not ("1.2.840.113549.1.1.11" or "1.2.840.113549.1.1.12" or
            "1.2.840.113549.1.1.13" or "1.2.840.10045.4.3.2" or "1.2.840.10045.4.3.3" or "1.2.840.10045.4.3.4"))
            throw new EnrollmentCertificateValidationException();
    }

    private static void ValidateAuthority(X509Certificate2 certificate)
    {
        RequireSha2Signature(certificate);
        if (certificate.Extensions.Select(extension => extension.Oid?.Value).Distinct(StringComparer.Ordinal).Count() != certificate.Extensions.Count)
            throw new EnrollmentCertificateValidationException();
        var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        if (constraints is not { CertificateAuthority: true } || usage is null ||
            (usage.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
            throw new EnrollmentCertificateValidationException();
        var spki = certificate.PublicKey.ExportSubjectPublicKeyInfo();
        if (certificate.PublicKey.Oid.Value == "1.2.840.113549.1.1.1")
        {
            using var rsa = RSA.Create(); rsa.ImportSubjectPublicKeyInfo(spki, out var consumed);
            var exponent = new System.Numerics.BigInteger(rsa.ExportParameters(false).Exponent!, isUnsigned: true, isBigEndian: true);
            if (consumed != spki.Length || rsa.KeySize is < 3072 or > 8192 || exponent < 65537 || exponent > uint.MaxValue || exponent.IsEven)
                throw new EnrollmentCertificateValidationException();
        }
        else if (certificate.PublicKey.Oid.Value == "1.2.840.10045.2.1")
        {
            var algorithm = new AsnReader(spki, AsnEncodingRules.DER).ReadSequence().ReadSequence();
            algorithm.ReadObjectIdentifier();
            if (algorithm.ReadObjectIdentifier() is not ("1.2.840.10045.3.1.7" or "1.3.132.0.34"))
                throw new EnrollmentCertificateValidationException();
            algorithm.ThrowIfNotEmpty();
            using var ec = ECDsa.Create(); ec.ImportSubjectPublicKeyInfo(spki, out var consumed);
            if (consumed != spki.Length || ec.KeySize is not (256 or 384)) throw new EnrollmentCertificateValidationException();
        }
        else throw new EnrollmentCertificateValidationException();
    }
}
