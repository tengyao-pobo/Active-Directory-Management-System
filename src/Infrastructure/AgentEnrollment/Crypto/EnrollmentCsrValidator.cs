using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ItManagement.AgentEnrollment.Crypto;

public sealed class EnrollmentCsrValidationException() : Exception("EnrollmentCsrRejected");

public sealed class ValidatedEnrollmentCsr
{
    private readonly byte[] _der;
    private readonly byte[] _csrHash;
    private readonly byte[] _spkiHash;
    private readonly byte[] _spki;
    internal ValidatedEnrollmentCsr(byte[] der, byte[] spki, string algorithm, int keySize, string? curveOid, string signatureOid)
    {
        _der = (byte[])der.Clone();
        _csrHash = SHA256.HashData(der);
        _spkiHash = SHA256.HashData(spki);
        _spki = (byte[])spki.Clone();
        KeyAlgorithm = algorithm; KeySize = keySize;
        CurveOid = curveOid; SignatureAlgorithmOid = signatureOid;
    }
    public int ProfileVersion => 1;
    public string KeyAlgorithm { get; }
    public int KeySize { get; }
    public int KeySizeBits => KeySize;
    public string? CurveOid { get; }
    public string SignatureAlgorithmOid { get; }
    public byte[] GetDer() => (byte[])_der.Clone();
    public byte[] GetCsrSha256() => (byte[])_csrHash.Clone();
    public byte[] GetSubjectPublicKeyInfoSha256() => (byte[])_spkiHash.Clone();
    public byte[] GetSubjectPublicKeyInfoDer() => (byte[])_spki.Clone();
}

public static class EnrollmentCsrValidator
{
    public const int MaximumDerBytes = 16 * 1024;
    private const string Rsa = "1.2.840.113549.1.1.1";
    private const string Ec = "1.2.840.10045.2.1";

    public static ValidatedEnrollmentCsr Validate(ReadOnlySpan<byte> csrDer)
    {
        if (csrDer.Length is < 1 or > MaximumDerBytes) throw new EnrollmentCsrValidationException();
        var der = csrDer.ToArray();
        try
        {
            // Inspect a bounded DER structure before invoking public-key signature verification.
            var reader = new AsnReader(der, AsnEncodingRules.DER);
            var request = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            var information = request.ReadSequence();
            if (information.ReadInteger() != 0) throw new EnrollmentCsrValidationException();
            information.ReadEncodedValue(); // Untrusted subject; never copied into an issued identity.
            var spki = information.ReadEncodedValue().ToArray();
            ValidateAttributes(information);
            var signature = request.ReadSequence();
            var signatureOid = signature.ReadObjectIdentifier();
            var isRsaSignature = signatureOid is "1.2.840.113549.1.1.11" or "1.2.840.113549.1.1.12" or "1.2.840.113549.1.1.13";
            var isEcSignature = signatureOid is "1.2.840.10045.4.3.2" or "1.2.840.10045.4.3.3" or "1.2.840.10045.4.3.4";
            if (!isRsaSignature && !isEcSignature) throw new EnrollmentCsrValidationException();
            if (isRsaSignature && signature.HasData) signature.ReadNull();
            signature.ThrowIfNotEmpty();
            request.ReadBitString(out var unused);
            if (unused != 0) throw new EnrollmentCsrValidationException();
            request.ThrowIfNotEmpty();

            var keyReader = new AsnReader(spki, AsnEncodingRules.DER);
            var keySequence = keyReader.ReadSequence();
            keyReader.ThrowIfNotEmpty();
            var keyAlgorithm = keySequence.ReadSequence();
            var oid = keyAlgorithm.ReadObjectIdentifier();
            byte[] canonicalSpki;
            int keySize;
            string algorithm;
            string? curveOid = null;
            if (oid == Rsa && isRsaSignature)
            {
                if (keyAlgorithm.HasData) keyAlgorithm.ReadNull();
                keyAlgorithm.ThrowIfNotEmpty();
                var rsaBytes = keySequence.ReadBitString(out unused);
                keySequence.ThrowIfNotEmpty();
                if (unused != 0) throw new EnrollmentCsrValidationException();
                var rsaReader = new AsnReader(rsaBytes, AsnEncodingRules.DER);
                var rsaSequence = rsaReader.ReadSequence();
                rsaReader.ThrowIfNotEmpty();
                var modulus = rsaSequence.ReadIntegerBytes().Span;
                var exponent = rsaSequence.ReadInteger();
                if (modulus.Length is < 384 or > 1025 || (modulus[0] & 0x80) != 0 ||
                    exponent < 65537 || exponent > uint.MaxValue || exponent.IsEven)
                    throw new EnrollmentCsrValidationException();
                rsaSequence.ThrowIfNotEmpty();
                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(spki, out var consumed);
                keySize = rsa.KeySize;
                if (consumed != spki.Length || keySize is < 3072 or > 8192) throw new EnrollmentCsrValidationException();
                canonicalSpki = rsa.ExportSubjectPublicKeyInfo();
                algorithm = "RSA";
            }
            else if (oid == Ec && isEcSignature)
            {
                var curve = keyAlgorithm.ReadObjectIdentifier();
                if (curve is not ("1.2.840.10045.3.1.7" or "1.3.132.0.34")) throw new EnrollmentCsrValidationException();
                if ((curve == "1.2.840.10045.3.1.7" && signatureOid != "1.2.840.10045.4.3.2") ||
                    (curve == "1.3.132.0.34" && signatureOid != "1.2.840.10045.4.3.3"))
                    throw new EnrollmentCsrValidationException();
                curveOid = curve;
                keyAlgorithm.ThrowIfNotEmpty();
                keySequence.ReadBitString(out unused);
                keySequence.ThrowIfNotEmpty();
                if (unused != 0) throw new EnrollmentCsrValidationException();
                using var ec = ECDsa.Create();
                ec.ImportSubjectPublicKeyInfo(spki, out var consumed);
                keySize = ec.KeySize;
                if (consumed != spki.Length || keySize is not (256 or 384)) throw new EnrollmentCsrValidationException();
                canonicalSpki = ec.ExportSubjectPublicKeyInfo();
                algorithm = "ECDSA";
            }
            else throw new EnrollmentCsrValidationException();

            // Default validates PKCS#10 proof; neither SkipSignatureValidation nor extension loading is enabled.
            var verified = CertificateRequest.LoadSigningRequest(der.AsSpan(), HashAlgorithmName.SHA256,
                out var bytesConsumed, CertificateRequestLoadOptions.Default, RSASignaturePadding.Pkcs1);
            if (bytesConsumed != der.Length ||
                !CryptographicOperations.FixedTimeEquals(verified.PublicKey.ExportSubjectPublicKeyInfo(), canonicalSpki))
                throw new EnrollmentCsrValidationException();
            return new(der, canonicalSpki, algorithm, keySize, curveOid, signatureOid);
        }
        catch (Exception error) when (error is AsnContentException or CryptographicException or ArgumentException)
        {
            // Do not expose attacker-controlled subject, extensions, parser diagnostics or key material.
            throw new EnrollmentCsrValidationException();
        }
    }

    private static void ValidateAttributes(AsnReader information)
    {
        var attributes = information.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));
        information.ThrowIfNotEmpty();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (attributes.HasData)
        {
            var attribute = attributes.ReadSequence();
            var oid = attribute.ReadObjectIdentifier();
            if (oid != "1.2.840.113549.1.9.14" || !seen.Add(oid)) throw new EnrollmentCsrValidationException();
            var values = attribute.ReadSetOf();
            attribute.ThrowIfNotEmpty();
            var extensions = values.ReadSequence();
            values.ThrowIfNotEmpty();
            var extensionOids = new HashSet<string>(StringComparer.Ordinal);
            while (extensions.HasData)
            {
                var extension = extensions.ReadSequence();
                if (!extensionOids.Add(extension.ReadObjectIdentifier())) throw new EnrollmentCsrValidationException();
                if (extension.HasData && extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean)) extension.ReadBoolean();
                extension.ReadOctetString(); // All requested extension values are ignored for issued identity.
                extension.ThrowIfNotEmpty();
            }
        }
    }
}
