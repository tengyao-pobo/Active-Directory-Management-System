using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using ItManagement.AgentEnrollment.Plans;
using ItManagement.Core;

namespace ItManagement.EnrollmentGrantExecution;

internal enum EnrollmentGrantContextReadOutcome { Found, NotFound, OutcomeUnknown }

internal sealed record ValidatedEnrollmentGrantExecutionContext(
    EnrollmentGrantExecutionOperation Operation, string VerifiedPlanHash);

internal sealed record EnrollmentGrantContextReadResult(
    EnrollmentGrantContextReadOutcome Outcome, ValidatedEnrollmentGrantExecutionContext? Context);

internal static class PostgresExecutionContextCodec
{
    internal static IReadOnlyList<string> CanonicalColumnNames { get; } =
    [
        "contract_version", "outcome", "plan_environment_id", "plan_id", "plan_requester_id", "plan_action",
        "plan_immutable_json", "plan_hash", "plan_policy_version", "plan_expires_at", "plan_state", "plan_reason",
        "item_environment_id", "item_plan_id", "item_id", "item_target_id", "item_expected_version",
        "approval_environment_id", "approval_id", "approval_plan_id", "approval_plan_hash", "approval_approver_id",
        "approval_approved_at", "approval_expires_at", "reservation_fingerprint", "reservation_environment_id",
        "reservation_plan_id", "reservation_requester_id", "reservation_request_id", "reservation_request_digest",
        "reservation_created_at", "database_checked_at", "operation_binding_sha256"
    ];

    private static readonly Type[] CanonicalColumnTypes =
    [
        typeof(short), typeof(string), typeof(Guid), typeof(Guid), typeof(Guid), typeof(string), typeof(string),
        typeof(string), typeof(long), typeof(DateTime), typeof(int), typeof(string), typeof(Guid), typeof(Guid),
        typeof(Guid), typeof(string), typeof(long), typeof(Guid), typeof(Guid), typeof(Guid), typeof(string),
        typeof(Guid), typeof(DateTime), typeof(DateTime), typeof(byte[]), typeof(Guid), typeof(Guid), typeof(Guid),
        typeof(Guid), typeof(byte[]), typeof(DateTime), typeof(DateTime), typeof(byte[])
    ];

    internal static async Task<EnrollmentGrantContextReadResult> ReadAsync(DbDataReader reader,
        EnrollmentGrantExecutionOperation expectedOperation, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(expectedOperation);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!expectedOperation.IsValid() || !ValidMetadata(reader) ||
                !await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return Unknown();

            var values = new object?[CanonicalColumnNames.Count];
            for (var i = 0; i < values.Length; i++)
                values[i] = await reader.IsDBNullAsync(i, cancellationToken).ConfigureAwait(false)
                    ? null
                    : reader.GetValue(i);

            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return Unknown();
            return Decode(values, expectedOperation);
        }
        catch (OperationCanceledException) { throw; }
        catch { return Unknown(); }
    }

    private static bool ValidMetadata(DbDataReader reader)
    {
        if (reader.FieldCount != CanonicalColumnNames.Count) return false;
        for (var i = 0; i < CanonicalColumnNames.Count; i++)
            if (!string.Equals(reader.GetName(i), CanonicalColumnNames[i], StringComparison.Ordinal) ||
                reader.GetFieldType(i) != CanonicalColumnTypes[i]) return false;
        return true;
    }

    private static EnrollmentGrantContextReadResult Decode(object?[] row,
        EnrollmentGrantExecutionOperation expectedOperation)
    {
        if (!Is<short>(row[0], out var contractVersion) || contractVersion != 1 ||
            !Is<string>(row[1], out var outcome)) return Unknown();

        if (outcome == "NotFound")
            return row.Skip(2).All(value => value is null)
                ? new(EnrollmentGrantContextReadOutcome.NotFound, null)
                : Unknown();
        if (outcome != "Found" || row.Skip(2).Any(value => value is null)) return Unknown();

        if (!Is<byte[]>(row[32], out var operationBinding) || operationBinding.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(operationBinding, ComputeOperationBinding(expectedOperation)))
            return Unknown();

        if (!RequiredPlan(row, out var plan) || !RequiredApproval(row, out var approval) ||
            !RequiredReservation(row, out var reservation) || !Time(row[31], out var databaseCheckedAt)) return Unknown();

        plan.Items.Add(new ChangePlanItem
        {
            EnvironmentId = (Guid)row[12]!,
            PlanId = (Guid)row[13]!,
            Id = (Guid)row[14]!,
            TargetId = (string)row[15]!,
            ExpectedVersion = (long)row[16]!
        });

        if (!ValidIdentifiers(plan, plan.Items.Single(), approval, reservation) ||
            plan.State != ChangePlanState.Queued ||
            !EnrollmentGrantPlanValidation.TryValidateStored(plan, reservation, out var payload)) return Unknown();

        string computedHash;
        try { computedHash = new ChangePlanService().ComputeHash(plan); }
        catch { return Unknown(); }
        if (!FixedEquals(plan.PlanHash, computedHash) || !FixedEquals(approval.PlanHash, computedHash)) return Unknown();

        if (plan.EnvironmentId != expectedOperation.EnvironmentId || plan.Id != expectedOperation.PlanId ||
            plan.RequesterId != expectedOperation.RequesterId || plan.PolicyVersion != expectedOperation.EnvironmentVersion ||
            !FixedEquals(plan.PlanHash, expectedOperation.PlanHash) ||
            approval.EnvironmentId != expectedOperation.EnvironmentId || approval.PlanId != expectedOperation.PlanId ||
            approval.Id != expectedOperation.ApprovalId || approval.ApproverId != expectedOperation.ApproverId ||
            reservation.EnvironmentId != expectedOperation.EnvironmentId || reservation.PlanId != expectedOperation.PlanId ||
            reservation.RequesterId != expectedOperation.RequesterId || reservation.RequestId != expectedOperation.RequestId ||
            approval.ApprovedAt > expectedOperation.QueuedAt || expectedOperation.AuthorizationNotAfter > approval.ExpiresAt ||
            expectedOperation.AuthorizationNotAfter > plan.ExpiresAt || reservation.CreatedAt > approval.ApprovedAt ||
            expectedOperation.QueuedAt > databaseCheckedAt ||
            !PayloadMatches(payload, expectedOperation, reservation.Fingerprint)) return Unknown();

        return new(EnrollmentGrantContextReadOutcome.Found,
            new ValidatedEnrollmentGrantExecutionContext(expectedOperation, computedHash));
    }

    // A synthetic fixed permit commits every immutable operation field. This digest is
    // context integrity evidence only: it is never stored as a mint permit or used to issue.
    internal static byte[] ComputeOperationBinding(EnrollmentGrantExecutionOperation operation) =>
        SHA256.HashData([.. Encoding.UTF8.GetBytes("ITM-ENROLLMENT-CONTEXT-V1"),
            .. EnrollmentGrantAuthorizationDigest.Compute(operation, 1, operation.QueuedAt,
            operation.AuthorizationNotAfter < operation.QueuedAt.AddSeconds(60)
                ? operation.AuthorizationNotAfter : operation.QueuedAt.AddSeconds(60),
            new byte[32], operation.GetRecipientKeyFingerprint(), new byte[32])]);

    private static bool RequiredPlan(object?[] row, out ChangePlan plan)
    {
        plan = null!;
        if (!Is<Guid>(row[2], out var environmentId) || !Is<Guid>(row[3], out var id) ||
            !Is<Guid>(row[4], out var requesterId) || !Is<string>(row[5], out var action) ||
            !Is<string>(row[6], out var immutableJson) || !Is<string>(row[7], out var hash) ||
            !Is<long>(row[8], out var policyVersion) || !Time(row[9], out var expiresAt) ||
            !Is<int>(row[10], out var state) || !Enum.IsDefined(typeof(ChangePlanState), state) ||
            !Is<string>(row[11], out var reason)) return false;
        plan = new ChangePlan
        {
            EnvironmentId = environmentId, Id = id, RequesterId = requesterId, Action = action,
            ImmutablePlanJson = immutableJson, PlanHash = hash, PolicyVersion = policyVersion,
            ExpiresAt = expiresAt, State = (ChangePlanState)state, Reason = reason
        };
        return true;
    }

    private static bool RequiredApproval(object?[] row, out ChangeApproval approval)
    {
        approval = null!;
        if (!Is<Guid>(row[17], out var environmentId) || !Is<Guid>(row[18], out var id) ||
            !Is<Guid>(row[19], out var planId) || !Is<string>(row[20], out var hash) ||
            !Is<Guid>(row[21], out var approverId) || !Time(row[22], out var approvedAt) ||
            !Time(row[23], out var expiresAt)) return false;
        approval = new ChangeApproval
        {
            EnvironmentId = environmentId, Id = id, PlanId = planId, PlanHash = hash,
            ApproverId = approverId, ApprovedAt = approvedAt, ExpiresAt = expiresAt
        };
        return true;
    }

    private static bool RequiredReservation(object?[] row, out EnrollmentGrantRecipientReservation reservation)
    {
        reservation = null!;
        if (row[24] is not byte[] fingerprint || !Is<Guid>(row[25], out var environmentId) ||
            !Is<Guid>(row[26], out var planId) || !Is<Guid>(row[27], out var requesterId) ||
            !Is<Guid>(row[28], out var requestId) || row[29] is not byte[] digest ||
            !Time(row[30], out var createdAt)) return false;
        reservation = new EnrollmentGrantRecipientReservation
        {
            Fingerprint = fingerprint.ToArray(), EnvironmentId = environmentId, PlanId = planId,
            RequesterId = requesterId, RequestId = requestId, RequestDigest = digest.ToArray(), CreatedAt = createdAt
        };
        return true;
    }

    private static bool ValidIdentifiers(ChangePlan plan, ChangePlanItem item, ChangeApproval approval,
        EnrollmentGrantRecipientReservation reservation) =>
        plan.EnvironmentId != Guid.Empty && plan.Id != Guid.Empty && plan.RequesterId != Guid.Empty &&
        item.EnvironmentId != Guid.Empty && item.PlanId != Guid.Empty && item.Id != Guid.Empty &&
        approval.EnvironmentId != Guid.Empty && approval.Id != Guid.Empty && approval.PlanId != Guid.Empty &&
        approval.ApproverId != Guid.Empty && reservation.EnvironmentId != Guid.Empty &&
        reservation.PlanId != Guid.Empty && reservation.RequesterId != Guid.Empty && reservation.RequestId != Guid.Empty;

    private static bool PayloadMatches(EnrollmentGrantPlanPayload payload,
        EnrollmentGrantExecutionOperation operation, byte[] reservationFingerprint)
    {
        byte[] payloadSpki;
        byte[] payloadFingerprint;
        try
        {
            payloadSpki = DecodeCanonicalBase64Url(payload.RecipientSpki);
            payloadFingerprint = DecodeCanonicalBase64Url(payload.RecipientKeyFingerprint);
        }
        catch (FormatException) { return false; }

        return payload.EnvironmentId == operation.EnvironmentId && payload.OperationId == operation.Id &&
            payload.RequestId == operation.RequestId && payload.RequesterId == operation.RequesterId &&
            payload.DirectoryObjectId == operation.DirectoryObjectId && payload.ServerDeviceId == operation.ServerDeviceId &&
            payload.MappingCreatedAt == operation.MappingCreatedAt && payload.DirectoryGeneration == operation.DirectoryGeneration &&
            payload.EnvironmentVersion == operation.EnvironmentVersion &&
            FixedEquals(payloadSpki, operation.GetRecipientSpki()) &&
            FixedEquals(payloadFingerprint, operation.GetRecipientKeyFingerprint()) &&
            FixedEquals(payloadFingerprint, reservationFingerprint);
    }

    private static byte[] DecodeCanonicalBase64Url(string value)
    {
        if (value.Length > 684 || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            throw new FormatException();
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight((padded.Length + 3) / 4 * 4, '=');
        var decoded = Convert.FromBase64String(padded);
        if (EncodeBase64Url(decoded) != value) throw new FormatException();
        return decoded;
    }

    private static string EncodeBase64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool Time(object? value, out DateTimeOffset result)
    {
        result = default;
        if (value is not DateTime time || time.Kind != DateTimeKind.Utc || time.Ticks % 10 != 0 ||
            time == DateTime.MinValue || time == DateTime.MaxValue) return false;
        result = new DateTimeOffset(time, TimeSpan.Zero);
        return true;
    }

    private static bool FixedEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private static bool FixedEquals(byte[] left, byte[] right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static bool Is<T>(object? value, out T result)
    {
        if (value is T typed) { result = typed; return true; }
        result = default!; return false;
    }

    private static EnrollmentGrantContextReadResult Unknown() =>
        new(EnrollmentGrantContextReadOutcome.OutcomeUnknown, null);
}
