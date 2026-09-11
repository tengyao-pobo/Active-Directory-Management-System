using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ItManagement.AgentEnrollment.Crypto;

const int maximumInputBytes = 4096;

try
{
    var inputBytes = new byte[maximumInputBytes + 1];
    var inputLength = 0;
    var input = Console.OpenStandardInput();
    while (inputLength < inputBytes.Length)
    {
        var read = await input.ReadAsync(inputBytes.AsMemory(inputLength, inputBytes.Length - inputLength));
        if (read == 0) break;
        inputLength += read;
    }

    if (inputLength == 0 || inputLength > maximumInputBytes || input.ReadByte() != -1)
        return Fail();

    var utf8 = new UTF8Encoding(false, true);
    var json = utf8.GetString(inputBytes, 0, inputLength);
    var options = new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    var request = JsonSerializer.Deserialize<SealRequest>(json, options);
    if (request is null || request.SubjectPublicKeyInfo is null || request.EnvironmentId == Guid.Empty ||
        request.OperationId == Guid.Empty)
        return Fail();

    var subjectPublicKeyInfo = DecodeBase64Url(request.SubjectPublicKeyInfo);
    var sealedGrant = SealedEnrollmentGrant.Seal(subjectPublicKeyInfo, request.EnvironmentId, request.OperationId);
    var response = new SealResponse(
        1,
        EncodeBase64Url(sealedGrant.GetRecipientSubjectPublicKeyInfoSha256()),
        EncodeBase64Url(sealedGrant.GetCiphertext()),
        EncodeBase64Url(sealedGrant.GetTokenSha256()));
    await Console.Out.WriteAsync(JsonSerializer.Serialize(response, options));
    return 0;
}
catch
{
    return Fail();
}

static int Fail()
{
    Console.Error.WriteLine("InvalidSealedGrant");
    return 1;
}

static byte[] DecodeBase64Url(string value)
{
    if (value.Length is < 1 or > 1024 || value.Any(character =>
            !(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
        throw new FormatException();
    var padded = value.Replace('-', '+').Replace('_', '/');
    padded += new string('=', (4 - padded.Length % 4) % 4);
    var decoded = Convert.FromBase64String(padded);
    if (!string.Equals(value, EncodeBase64Url(decoded), StringComparison.Ordinal)) throw new FormatException();
    return decoded;
}

static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
    Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

internal sealed record SealRequest(string? SubjectPublicKeyInfo, Guid EnvironmentId, Guid OperationId);
internal sealed record SealResponse(int FormatVersion, string RecipientKeyFingerprint, string Ciphertext, string TokenSha256);
