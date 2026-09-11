using System.Security.Cryptography;

namespace ItManagement.AgentEnrollment.Crypto;

public sealed class EnrollmentGrantRecipientKey
{
    private readonly byte[] _subjectPublicKeyInfo;
    private readonly byte[] _fingerprint;

    private EnrollmentGrantRecipientKey(byte[] subjectPublicKeyInfo)
    {
        _subjectPublicKeyInfo = subjectPublicKeyInfo;
        _fingerprint = SHA256.HashData(subjectPublicKeyInfo);
    }

    public static EnrollmentGrantRecipientKey Validate(ReadOnlySpan<byte> subjectPublicKeyInfoDer)
    {
        if (subjectPublicKeyInfoDer.Length is < 1 or > SealedEnrollmentGrant.RecipientSubjectPublicKeyInfoMaximumBytes)
            throw new SealedEnrollmentGrantException();

        var snapshot = subjectPublicKeyInfoDer.ToArray();
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(snapshot, out var consumed);
            var parameters = rsa.ExportParameters(false);
            if (consumed != snapshot.Length || rsa.KeySize != 3072 ||
                parameters.Exponent is not [0x01, 0x00, 0x01] ||
                !CryptographicOperations.FixedTimeEquals(rsa.ExportSubjectPublicKeyInfo(), snapshot))
                throw new SealedEnrollmentGrantException();
            return new(snapshot);
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        {
            throw new SealedEnrollmentGrantException();
        }
    }

    public byte[] GetSubjectPublicKeyInfo() => (byte[])_subjectPublicKeyInfo.Clone();
    public byte[] GetFingerprintSha256() => (byte[])_fingerprint.Clone();

    internal RSA Import()
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportSubjectPublicKeyInfo(_subjectPublicKeyInfo, out _);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }
}
