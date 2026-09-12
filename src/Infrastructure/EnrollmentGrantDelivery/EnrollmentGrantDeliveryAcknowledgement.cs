using System.Text.Json;

namespace ItManagement.EnrollmentGrantDelivery;

public sealed class EnrollmentGrantDeliveryAcknowledgement
{
    private const int MaximumJsonBytes = 1_024;
    private readonly byte[] _recipientKeyFingerprint;
    private readonly byte[] _ciphertextSha256;

    private EnrollmentGrantDeliveryAcknowledgement(byte[] recipientKeyFingerprint, byte[] ciphertextSha256)
    {
        _recipientKeyFingerprint = recipientKeyFingerprint;
        _ciphertextSha256 = ciphertextSha256;
    }

    public short FormatVersion => 1;

    public static bool TryParse(
        ReadOnlySpan<byte> utf8Json,
        out EnrollmentGrantDeliveryAcknowledgement? acknowledgement)
    {
        acknowledgement = null;
        if (utf8Json.IsEmpty || utf8Json.Length > MaximumJsonBytes) return false;

        try
        {
            using var document = JsonDocument.Parse(utf8Json.ToArray());
            if (document.RootElement.ValueKind != JsonValueKind.Object) return false;

            var seen = 0;
            short version = 0;
            byte[]? fingerprint = null;
            byte[]? ciphertextSha256 = null;
            foreach (var property in document.RootElement.EnumerateObject())
            {
                switch (property.Name)
                {
                    case "formatVersion" when (seen & 1) == 0 &&
                        property.Value.ValueKind == JsonValueKind.Number &&
                        property.Value.TryGetInt16(out version):
                        seen |= 1;
                        break;
                    case "recipientKeyFingerprint" when (seen & 2) == 0 &&
                        property.Value.ValueKind == JsonValueKind.String &&
                        Base64Url.TryDecode32(property.Value.GetString(), out fingerprint):
                        seen |= 2;
                        break;
                    case "ciphertextSha256" when (seen & 4) == 0 &&
                        property.Value.ValueKind == JsonValueKind.String &&
                        Base64Url.TryDecode32(property.Value.GetString(), out ciphertextSha256):
                        seen |= 4;
                        break;
                    default:
                        return false;
                }
            }

            if (seen != 7 || version != 1 || fingerprint is null || ciphertextSha256 is null)
                return false;
            acknowledgement = new EnrollmentGrantDeliveryAcknowledgement(
                fingerprint.ToArray(),
                ciphertextSha256.ToArray());
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public byte[] GetRecipientKeyFingerprint() => _recipientKeyFingerprint.ToArray();
    public byte[] GetCiphertextSha256() => _ciphertextSha256.ToArray();
    public override string ToString() => nameof(EnrollmentGrantDeliveryAcknowledgement);
}
