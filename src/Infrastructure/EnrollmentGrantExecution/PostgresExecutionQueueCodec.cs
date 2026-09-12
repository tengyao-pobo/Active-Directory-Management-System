using System.Data.Common;

namespace ItManagement.EnrollmentGrantExecution;

public static class PostgresExecutionQueueCodec
{
    public static readonly TimeSpan LeaseDuration = TimeSpan.FromSeconds(120);
    private static readonly (string Name, Type Type)[] ClaimColumns =
    [
        ("contract_version", typeof(short)), ("outcome", typeof(string)), ("queried_at", typeof(DateTime)),
        ("environment_id", typeof(Guid)), ("operation_id", typeof(Guid)), ("claim_token", typeof(Guid)),
        ("attempt", typeof(int)), ("claimed_at", typeof(DateTime)), ("lease_until", typeof(DateTime))
    ];
    private static readonly (string Name, Type Type)[] TransitionColumns =
    [
        ("contract_version", typeof(short)), ("outcome", typeof(string)),
        ("queried_at", typeof(DateTime)), ("next_attempt_at", typeof(DateTime))
    ];

    public static async Task<EnrollmentWorkClaimResult> ReadClaimAsync(DbDataReader reader,
        Guid expectedEnvironment, Guid expectedToken, CancellationToken cancellationToken)
    {
        try
        {
            if (expectedEnvironment == Guid.Empty || expectedToken == Guid.Empty ||
                !ColumnsMatch(reader, ClaimColumns) || !await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
                reader.GetInt16(0) != 1 || !TryExact(reader.GetString(1), out EnrollmentWorkClaimOutcome outcome) ||
                outcome == EnrollmentWorkClaimOutcome.OutcomeUnknown || !TryTime(reader, 2, out var queriedAt))
                return UnknownClaim();

            EnrollmentWorkClaim? claim = null;
            if (outcome is EnrollmentWorkClaimOutcome.Claimed or EnrollmentWorkClaimOutcome.Existing)
            {
                if (Enumerable.Range(3, 6).Any(reader.IsDBNull) || !TryTime(reader, 7, out var claimedAt) ||
                    !TryTime(reader, 8, out var leaseUntil)) return UnknownClaim();
                claim = new(reader.GetGuid(3), reader.GetGuid(4), reader.GetGuid(5), reader.GetInt32(6), claimedAt, leaseUntil);
                if (!ValidClaim(claim, expectedEnvironment, expectedToken) || queriedAt < claimedAt || queriedAt >= leaseUntil)
                    return UnknownClaim();
            }
            else if (Enumerable.Range(3, 6).Any(index => !reader.IsDBNull(index))) return UnknownClaim();

            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return UnknownClaim();
            return new(outcome, queriedAt, claim);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return UnknownClaim(); }
    }

    public static async Task<EnrollmentWorkTransitionResult> ReadTransitionAsync(DbDataReader reader,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!ColumnsMatch(reader, TransitionColumns) || !await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
                reader.GetInt16(0) != 1 || !TryExact(reader.GetString(1), out EnrollmentWorkTransitionOutcome outcome) ||
                outcome == EnrollmentWorkTransitionOutcome.OutcomeUnknown || !TryTime(reader, 2, out var queriedAt))
                return UnknownTransition();
            DateTimeOffset? nextAttemptAt = null;
            if (outcome is EnrollmentWorkTransitionOutcome.Deferred or EnrollmentWorkTransitionOutcome.AlreadyDeferred)
            {
                if (!TryTime(reader, 3, out var next)) return UnknownTransition();
                // Exact replay can observe a previously stored retry time that is now in the past.
                if (next - queriedAt > TimeSpan.FromSeconds(300) ||
                    outcome == EnrollmentWorkTransitionOutcome.Deferred && next <= queriedAt)
                    return UnknownTransition();
                nextAttemptAt = next;
            }
            else if (!reader.IsDBNull(3)) return UnknownTransition();
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return UnknownTransition();
            return new(outcome, queriedAt, nextAttemptAt);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return UnknownTransition(); }
    }

    internal static bool ValidClaim(EnrollmentWorkClaim claim, Guid environment, Guid token) =>
        environment != Guid.Empty && token != Guid.Empty && claim.EnvironmentId == environment && claim.ClaimToken == token &&
        claim.OperationId != Guid.Empty && claim.Attempt > 0 && Canonical(claim.ClaimedAt) && Canonical(claim.LeaseUntil) &&
        claim.LeaseUntil - claim.ClaimedAt == LeaseDuration;

    private static bool ColumnsMatch(DbDataReader reader, (string Name, Type Type)[] columns) =>
        reader.FieldCount == columns.Length && columns.Select((column, index) =>
            reader.GetName(index) == column.Name && reader.GetFieldType(index) == column.Type).All(value => value);

    private static bool TryExact<T>(string value, out T result) where T : struct, Enum =>
        Enum.TryParse(value, ignoreCase: false, out result) && Enum.IsDefined(result) && result.ToString() == value;

    private static bool TryTime(DbDataReader reader, int index, out DateTimeOffset value)
    {
        value = default;
        if (reader.IsDBNull(index)) return false;
        var timestamp = reader.GetDateTime(index);
        if (timestamp.Kind != DateTimeKind.Utc || timestamp.Ticks % 10 != 0 ||
            timestamp == DateTime.MinValue || timestamp == DateTime.MaxValue) return false;
        value = new(timestamp);
        return true;
    }

    internal static bool Canonical(DateTimeOffset value) => value.Offset == TimeSpan.Zero && value.Ticks % 10 == 0 &&
        value != DateTimeOffset.MinValue && value != DateTimeOffset.MaxValue;
    private static EnrollmentWorkClaimResult UnknownClaim() => new(EnrollmentWorkClaimOutcome.OutcomeUnknown);
    private static EnrollmentWorkTransitionResult UnknownTransition() => new(EnrollmentWorkTransitionOutcome.OutcomeUnknown);
}
