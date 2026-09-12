using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ItManagement.AgentEnrollment.Crypto;
using ItManagement.Core;

namespace ItManagement.AgentEnrollment.Plans;

/// <summary>Shared payload and request-digest validation. This does not grant execution authority.</summary>
public static class EnrollmentGrantPlanValidation
{
    private static readonly JsonSerializerOptions StrictJson = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static bool TryValidateStored(ChangePlan plan, EnrollmentGrantRecipientReservation reservation, out EnrollmentGrantPlanPayload payload)
    {
        payload = null!;
        try { payload = JsonSerializer.Deserialize<EnrollmentGrantPlanPayload>(plan.ImmutablePlanJson, StrictJson)!; }
        catch (JsonException) { return false; }
        if (payload is null || payload.SchemaVersion != EnrollmentGrantPlanContract.SchemaVersion || payload.Action != EnrollmentGrantPlanContract.Action ||
            plan.Action != payload.Action || payload.EnvironmentId != plan.EnvironmentId || payload.EnvironmentId != reservation.EnvironmentId ||
            payload.RequesterId != plan.RequesterId || payload.RequesterId != reservation.RequesterId || payload.RequestId != reservation.RequestId ||
            payload.DirectoryObjectId == Guid.Empty || payload.ServerDeviceId == Guid.Empty || payload.OperationId == Guid.Empty || payload.RequestId == Guid.Empty ||
            payload.DirectoryGeneration == Guid.Empty || payload.EnvironmentVersion <= 0 || plan.PolicyVersion != payload.EnvironmentVersion ||
            plan.State is not (ChangePlanState.PendingApproval or ChangePlanState.Approved or ChangePlanState.Rejected or ChangePlanState.Expired or ChangePlanState.Queued) ||
            plan.Items.Count != 1 || plan.Items.Single().EnvironmentId != plan.EnvironmentId || plan.Items.Single().PlanId != plan.Id ||
            plan.Items.Single().TargetId != plan.EnvironmentId.ToString() || plan.Items.Single().ExpectedVersion != payload.EnvironmentVersion ||
            payload.GrantTtlSeconds != EnrollmentGrantPlanContract.GrantTtlSeconds || plan.Reason != payload.Reason ||
            payload.RecipientSpki is null || payload.RecipientKeyFingerprint is null || payload.Reason is null ||
            payload.Reason.Length is < 5 or > 512 || payload.Reason.Any(char.IsControl) || payload.MappingCreatedAt.Offset != TimeSpan.Zero ||
            payload.MappingCreatedAt.Ticks % 10 != 0 || reservation.PlanId != plan.Id || reservation.Fingerprint.Length != 32 || reservation.RequestDigest.Length != 32)
            return false;
        if (reservation.CreatedAt.Offset != TimeSpan.Zero || reservation.CreatedAt.Ticks % 10 != 0 ||
            plan.ExpiresAt.Offset != TimeSpan.Zero || plan.ExpiresAt.Ticks % 10 != 0 ||
            plan.ExpiresAt != reservation.CreatedAt.AddSeconds(EnrollmentGrantPlanContract.GrantTtlSeconds)) return false;
        try
        {
            var spki = DecodeCanonicalBase64Url(payload.RecipientSpki);
            var key = EnrollmentGrantRecipientKey.Validate(spki);
            if (!FixedEquals(key.GetFingerprintSha256(), reservation.Fingerprint) ||
                payload.RecipientKeyFingerprint != EncodeBase64Url(reservation.Fingerprint) ||
                payload.RecipientSpki != EncodeBase64Url(key.GetSubjectPublicKeyInfo())) return false;
        }
        catch (Exception error) when (error is FormatException or SealedEnrollmentGrantException) { return false; }
        var digest = ComputeRequestDigest(payload.EnvironmentId, payload.RequesterId, payload.RequestId, payload.DirectoryObjectId,
            payload.ServerDeviceId, payload.MappingCreatedAt, payload.EnvironmentVersion, payload.DirectoryGeneration, payload.RecipientSpki, payload.Reason);
        return FixedEquals(digest, reservation.RequestDigest);
    }

    public static byte[] ComputeRequestDigest(Guid env, Guid requester, Guid request, Guid directory, Guid device,
        DateTimeOffset mappingCreatedAt, long environmentVersion, Guid generation, string spki, string reason)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("action", EnrollmentGrantPlanContract.Action);
            writer.WriteString("directoryObjectId", directory);
            writer.WriteNumber("environmentVersion", environmentVersion);
            writer.WriteString("environmentId", env);
            writer.WriteString("mappingCreatedAt", Canonical(mappingCreatedAt));
            writer.WriteString("reason", reason);
            writer.WriteString("recipientSpki", spki);
            writer.WriteString("requesterId", requester);
            writer.WriteString("requestId", request);
            writer.WriteString("serverDeviceId", device);
            writer.WriteString("directoryGeneration", generation);
            writer.WriteNumber("schemaVersion", EnrollmentGrantPlanContract.SchemaVersion);
            writer.WriteEndObject();
        }
        return SHA256.HashData(stream.ToArray());
    }

    private static string EncodeBase64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+','-').Replace('/','_');
    private static byte[] DecodeCanonicalBase64Url(string encoded)
    {
        if (encoded.Length > 684 || encoded.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))) throw new FormatException();
        var padded = encoded.Replace('-','+').Replace('_','/');
        padded = padded.PadRight((padded.Length + 3) / 4 * 4, '=');
        var bytes = Convert.FromBase64String(padded);
        if (EncodeBase64Url(bytes) != encoded) throw new FormatException();
        return bytes;
    }
    private static DateTimeOffset Canonical(DateTimeOffset value) => new(value.UtcTicks - value.UtcTicks % 10, TimeSpan.Zero);
    private static bool FixedEquals(byte[] left, byte[] right) => left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
