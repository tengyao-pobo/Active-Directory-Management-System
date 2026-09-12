using System.Data.Common;
using ItManagement.AgentPlatformGrants;

namespace ItManagement.EnrollmentGrantDelivery;

internal static class PostgresEnrollmentDeliveryCodec
{
    internal static EnrollmentGrantStatusReceiptResult UnknownReceipt() => new(EnrollmentGrantStatusReceiptOutcome.OutcomeUnknown, null);
    internal static EnrollmentGrantDeliveryResponse UnknownDelivery() => new(EnrollmentGrantDeliveryOutcome.OutcomeUnknown, null);

    internal static async Task<EnrollmentGrantStatusReceiptResult> ReadReceiptAsync(DbDataReader reader,
        Guid environment, Guid operation, CancellationToken ct)
    {
        if (reader.FieldCount != 14 || !await reader.ReadAsync(ct).ConfigureAwait(false) || reader.IsDBNull(0) || reader.GetInt16(0) != 1)
            return UnknownReceipt();
        EnrollmentGrantStatusReceiptResult result;
        if (!reader.IsDBNull(1) && reader.GetString(1) == "NotFound" && AllNull(reader, 2, 14))
            result = new(EnrollmentGrantStatusReceiptOutcome.NotFound, null);
        else if (!reader.IsDBNull(1) && reader.GetString(1) == "Found" && AllPresent(reader, 2, 14))
        {
            var receipt = new PlatformGrantReceipt(reader.GetGuid(2), reader.GetGuid(3), reader.GetGuid(4), reader.GetGuid(5),
                reader.GetGuid(6), Time(reader, 7), Time(reader, 8), Time(reader, 9), reader.GetInt16(10), Time(reader, 11),
                reader.GetFieldValue<byte[]>(12), reader.GetFieldValue<byte[]>(13));
            result = receipt.EnvironmentId == environment && receipt.OperationId == operation && ValidReceipt(receipt)
                ? new(EnrollmentGrantStatusReceiptOutcome.Found, receipt) : UnknownReceipt();
        }
        else result = UnknownReceipt();
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? UnknownReceipt() : result;
    }

    internal static bool ValidReceipt(PlatformGrantReceipt receipt) => receipt.EnvironmentId != Guid.Empty &&
        receipt.OperationId != Guid.Empty && receipt.GrantId != Guid.Empty && receipt.DirectoryObjectId != Guid.Empty && receipt.DeviceId != Guid.Empty &&
        EnrollmentGrantStatusObservationCandidate.CanonicalTime(receipt.MappingCreatedAt) &&
        EnrollmentGrantStatusObservationCandidate.CanonicalTime(receipt.CreatedAt) &&
        EnrollmentGrantStatusObservationCandidate.CanonicalTime(receipt.ExpiresAt) &&
        receipt.MappingCreatedAt <= receipt.CreatedAt && receipt.ExpiresAt - receipt.CreatedAt == TimeSpan.FromSeconds(600) &&
        receipt.IssueContractVersion == 2 && receipt.MintPermitNotAfter is { } deadline &&
        EnrollmentGrantStatusObservationCandidate.CanonicalTime(deadline) && deadline > receipt.CreatedAt &&
        deadline - receipt.CreatedAt <= TimeSpan.FromSeconds(60) && receipt.GetTokenSha256().Length == 32 && receipt.GetAuthorizationDigest().Length == 32;

    internal static async Task<EnrollmentGrantStatusObservationWriteResult> ReadObservationAsync(DbDataReader reader,
        EnrollmentGrantStatusObservationCandidate expected, CancellationToken ct)
    {
        if (reader.FieldCount != 12 || !await reader.ReadAsync(ct).ConfigureAwait(false) || reader.IsDBNull(0))
            return EnrollmentGrantStatusObservationWriteResult.Unknown();
        var result = EnrollmentGrantStatusObservationWriteResult.Normalize(expected, reader.GetInt16(0),
            NullableString(reader, 1), NullableGuid(reader, 2), NullableGuid(reader, 3), NullableGuid(reader, 4),
            reader.IsDBNull(5) ? null : reader.GetInt64(5), NullableString(reader, 6), NullableString(reader, 7),
            NullableTime(reader, 8), NullableTime(reader, 9), NullableTime(reader, 10), NullableTime(reader, 11));
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? EnrollmentGrantStatusObservationWriteResult.Unknown() : result;
    }

    internal static async Task<EnrollmentGrantDeliveryResponse> ReadDeliveryAsync(DbDataReader reader,
        Guid environment, Guid operation, CancellationToken ct)
    {
        if (reader.FieldCount != 10 || !await reader.ReadAsync(ct).ConfigureAwait(false) || reader.IsDBNull(0) || reader.GetInt16(0) != 1)
            return UnknownDelivery();
        var state = NullableString(reader, 1);
        EnrollmentGrantDeliveryResponse result;
        if (state == "Available" && AllPresent(reader, 2, 10))
        {
            var envelope = EnrollmentGrantDeliveryEnvelope.Create(reader.GetGuid(2), reader.GetGuid(3), reader.GetInt16(4),
                reader.GetFieldValue<byte[]>(5), reader.GetFieldValue<byte[]>(6), reader.GetFieldValue<byte[]>(7), Time(reader, 8), Time(reader, 9));
            result = EnrollmentGrantDeliveryResponseFactory.Create(environment, operation, EnrollmentGrantDeliveryOutcome.Available, envelope);
        }
        else
        {
            var outcome = state switch
            {
                "Pending" => EnrollmentGrantDeliveryOutcome.Pending,
                "Acknowledged" => EnrollmentGrantDeliveryOutcome.Acknowledged,
                "Unavailable" => EnrollmentGrantDeliveryOutcome.Unavailable,
                "NotFound" => EnrollmentGrantDeliveryOutcome.NotFound,
                _ => EnrollmentGrantDeliveryOutcome.OutcomeUnknown
            };
            result = AllNull(reader, 2, 10) ? EnrollmentGrantDeliveryResponseFactory.Create(environment, operation, outcome, null) : UnknownDelivery();
        }
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? UnknownDelivery() : result;
    }

    internal static async Task<EnrollmentGrantAcknowledgementOutcome> ReadAcknowledgementAsync(DbDataReader reader, CancellationToken ct)
    {
        if (reader.FieldCount != 2 || !await reader.ReadAsync(ct).ConfigureAwait(false) || reader.IsDBNull(0) || reader.GetInt16(0) != 1)
            return EnrollmentGrantAcknowledgementOutcome.OutcomeUnknown;
        var result = NullableString(reader, 1) switch
        {
            "Acknowledged" => EnrollmentGrantAcknowledgementOutcome.Acknowledged,
            "AlreadyAcknowledged" => EnrollmentGrantAcknowledgementOutcome.AlreadyAcknowledged,
            "NotFound" => EnrollmentGrantAcknowledgementOutcome.NotFound,
            "Conflict" => EnrollmentGrantAcknowledgementOutcome.Conflict,
            _ => EnrollmentGrantAcknowledgementOutcome.OutcomeUnknown
        };
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? EnrollmentGrantAcknowledgementOutcome.OutcomeUnknown : result;
    }

    private static bool AllNull(DbDataReader reader, int from, int end) => Enumerable.Range(from, end - from).All(reader.IsDBNull);
    private static bool AllPresent(DbDataReader reader, int from, int end) => Enumerable.Range(from, end - from).All(i => !reader.IsDBNull(i));
    private static DateTimeOffset Time(DbDataReader reader, int index) => reader.GetFieldValue<DateTimeOffset>(index);
    private static DateTimeOffset? NullableTime(DbDataReader reader, int index) => reader.IsDBNull(index) ? null : Time(reader, index);
    private static Guid? NullableGuid(DbDataReader reader, int index) => reader.IsDBNull(index) ? null : reader.GetGuid(index);
    private static string? NullableString(DbDataReader reader, int index) => reader.IsDBNull(index) ? null : reader.GetString(index);
}
