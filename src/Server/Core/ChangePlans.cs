using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ItManagement.Core;

public enum ChangePlanState
{
    PendingApproval = 0,
    Approved = 1,
    Executed = 2,
    Rejected = 3,
    Expired = 4,
    Queued = 5,
}

public sealed class ChangePlan
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public Guid RequesterId { get; set; }
    public string Action { get; set; } = string.Empty;
    public string ImmutablePlanJson { get; set; } = string.Empty;
    public string PlanHash { get; set; } = string.Empty;
    public long PolicyVersion { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public ChangePlanState State { get; set; }
    public string? Reason { get; set; }
    public ICollection<ChangePlanItem> Items { get; set; } = new List<ChangePlanItem>();
}

public sealed class ChangePlanItem
{
    public Guid EnvironmentId { get; set; }
    public Guid PlanId { get; set; }
    public Guid Id { get; set; }
    public string TargetId { get; set; } = string.Empty;
    public long ExpectedVersion { get; set; }
}

public sealed class ChangeApproval
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public Guid PlanId { get; set; }
    public string PlanHash { get; set; } = string.Empty;
    public Guid ApproverId { get; set; }
    public DateTimeOffset ApprovedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

public enum ChangePlanValidationFailure
{
    None = 0,
    PlanNotApproved,
    ApprovalDoesNotMatchPlan,
    SelfApproval,
    Expired,
    PolicyVersionDrift,
    TargetVersionDrift,
}

public sealed record ChangePlanValidationResult(bool IsValid, ChangePlanValidationFailure Failure)
{
    public static ChangePlanValidationResult Valid { get; } = new(true, ChangePlanValidationFailure.None);
}

public sealed class ChangePlanService
{
    public ChangePlan Create(
        Guid environmentId,
        Guid planId,
        Guid requesterId,
        string action,
        string immutablePlanJson,
        long policyVersion,
        DateTimeOffset expiresAt,
        IEnumerable<ChangePlanItem>? items = null,
        string? reason = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        ArgumentException.ThrowIfNullOrWhiteSpace(immutablePlanJson);

        using var _ = JsonDocument.Parse(immutablePlanJson);
        var plan = new ChangePlan
        {
            EnvironmentId = environmentId,
            Id = planId,
            RequesterId = requesterId,
            Action = action,
            ImmutablePlanJson = immutablePlanJson,
            PolicyVersion = policyVersion,
            ExpiresAt = NormalizeToPostgreSqlPrecision(expiresAt),
            State = ChangePlanState.PendingApproval,
            Reason = reason,
            Items = items?.Select(CopyItem).ToList() ?? new List<ChangePlanItem>(),
        };

        foreach (var item in plan.Items)
        {
            item.EnvironmentId = environmentId;
            item.PlanId = planId;
        }

        plan.PlanHash = ComputeHash(plan);
        return plan;
    }

    public ChangeApproval Approve(
        ChangePlan plan,
        Guid approvalId,
        Guid approverId,
        string approvedPlanHash,
        DateTimeOffset approvedAt,
        DateTimeOffset approvalExpiresAt)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentException.ThrowIfNullOrWhiteSpace(approvedPlanHash);

        approvedAt = NormalizeToPostgreSqlPrecision(approvedAt);
        approvalExpiresAt = NormalizeToPostgreSqlPrecision(approvalExpiresAt);

        if (plan.State != ChangePlanState.PendingApproval)
        {
            throw new InvalidOperationException("Only a pending plan can be approved.");
        }

        if (approverId == plan.RequesterId)
        {
            throw new InvalidOperationException("The requester cannot approve their own plan.");
        }

        if (approvedAt >= plan.ExpiresAt || approvalExpiresAt <= approvedAt || approvalExpiresAt > plan.ExpiresAt)
        {
            throw new InvalidOperationException("The plan or approval expiry is invalid.");
        }

        var currentHash = ComputeHash(plan);
        if (!FixedTimeEquals(currentHash, plan.PlanHash) || !FixedTimeEquals(currentHash, approvedPlanHash))
        {
            throw new InvalidOperationException("Approval must match the exact current plan hash.");
        }

        plan.State = ChangePlanState.Approved;
        return new ChangeApproval
        {
            EnvironmentId = plan.EnvironmentId,
            Id = approvalId,
            PlanId = plan.Id,
            PlanHash = currentHash,
            ApproverId = approverId,
            ApprovedAt = approvedAt,
            ExpiresAt = approvalExpiresAt,
        };
    }

    public ChangePlanValidationResult ValidateForExecution(
        ChangePlan plan,
        ChangeApproval? approval,
        long currentPolicyVersion,
        IReadOnlyDictionary<string, long> currentTargetVersions,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(currentTargetVersions);

        if (plan.State != ChangePlanState.Approved)
        {
            return Invalid(ChangePlanValidationFailure.PlanNotApproved);
        }

        if (approval is null ||
            approval.EnvironmentId != plan.EnvironmentId ||
            approval.PlanId != plan.Id ||
            !FixedTimeEquals(approval.PlanHash, plan.PlanHash) ||
            !FixedTimeEquals(ComputeHash(plan), plan.PlanHash))
        {
            return Invalid(ChangePlanValidationFailure.ApprovalDoesNotMatchPlan);
        }

        if (approval.ApproverId == plan.RequesterId)
        {
            return Invalid(ChangePlanValidationFailure.SelfApproval);
        }

        if (now >= plan.ExpiresAt || now >= approval.ExpiresAt)
        {
            return Invalid(ChangePlanValidationFailure.Expired);
        }

        if (currentPolicyVersion != plan.PolicyVersion)
        {
            return Invalid(ChangePlanValidationFailure.PolicyVersionDrift);
        }

        foreach (var item in plan.Items)
        {
            if (!currentTargetVersions.TryGetValue(item.TargetId, out var currentVersion) ||
                currentVersion != item.ExpectedVersion)
            {
                return Invalid(ChangePlanValidationFailure.TargetVersionDrift);
            }
        }

        return ChangePlanValidationResult.Valid;
    }

    public string ComputeHash(ChangePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        using var document = JsonDocument.Parse(plan.ImmutablePlanJson);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writer.WriteString("action", plan.Action);
            writer.WriteString("environmentId", plan.EnvironmentId);
            writer.WriteString("expiresAt", NormalizeToPostgreSqlPrecision(plan.ExpiresAt));
            writer.WriteString("id", plan.Id);
            writer.WritePropertyName("items");
            writer.WriteStartArray();
            foreach (var item in plan.Items.OrderBy(item => item.TargetId, StringComparer.Ordinal).ThenBy(item => item.Id))
            {
                writer.WriteStartObject();
                writer.WriteNumber("expectedVersion", item.ExpectedVersion);
                writer.WriteString("id", item.Id);
                writer.WriteString("targetId", item.TargetId);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WritePropertyName("plan");
            WriteCanonicalJson(writer, document.RootElement);
            writer.WriteNumber("policyVersion", plan.PolicyVersion);
            writer.WriteString("reason", plan.Reason);
            writer.WriteString("requesterId", plan.RequesterId);
            writer.WriteEndObject();
        }

        return Convert.ToHexStringLower(SHA256.HashData(stream.ToArray()));
    }

    private static ChangePlanItem CopyItem(ChangePlanItem item) => new()
    {
        Id = item.Id,
        TargetId = item.TargetId,
        ExpectedVersion = item.ExpectedVersion,
    };

    private static ChangePlanValidationResult Invalid(ChangePlanValidationFailure failure) => new(false, failure);

    private static DateTimeOffset NormalizeToPostgreSqlPrecision(DateTimeOffset value)
    {
        var utcTicks = value.ToUniversalTime().Ticks;
        return new DateTimeOffset(utcTicks - (utcTicks % 10), TimeSpan.Zero);
    }

    private static bool FixedTimeEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private static void WriteCanonicalJson(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject().OrderBy(property => property.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonicalJson(writer, property.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteCanonicalJson(writer, item);
                }
                writer.WriteEndArray();
                break;
            default:
                element.WriteTo(writer);
                break;
        }
    }
}
