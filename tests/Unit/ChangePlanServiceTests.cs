using ItManagement.Core;

namespace ItManagement.UnitTests;

public sealed class ChangePlanServiceTests
{
    private readonly ChangePlanService _service = new();
    private readonly DateTimeOffset _now = new(2026, 9, 11, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CanonicalHashIgnoresJsonObjectPropertyOrder()
    {
        var first = CreatePlan("{\"b\":2,\"a\":1}");
        var second = _service.Create(
            first.EnvironmentId,
            first.Id,
            first.RequesterId,
            first.Action,
            "{ \"a\" : 1, \"b\" : 2 }",
            first.PolicyVersion,
            first.ExpiresAt,
            first.Items,
            first.Reason);

        Assert.Equal(first.PlanHash, second.PlanHash);
    }

    [Fact]
    public void CanonicalHashSurvivesPostgreSqlMicrosecondTruncation()
    {
        var subMicrosecondExpiry = _now.AddMinutes(10).AddTicks(7);
        var plan = new ChangePlan
        {
            EnvironmentId = Guid.NewGuid(),
            Id = Guid.NewGuid(),
            RequesterId = Guid.NewGuid(),
            Action = "User.Update",
            ImmutablePlanJson = "{\"value\":\"new\"}",
            PolicyVersion = 12,
            ExpiresAt = subMicrosecondExpiry,
            Reason = "Approved maintenance",
        };
        var beforeRoundTrip = _service.ComputeHash(plan);

        plan.ExpiresAt = new DateTimeOffset(
            subMicrosecondExpiry.UtcTicks - (subMicrosecondExpiry.UtcTicks % 10),
            TimeSpan.Zero);

        Assert.Equal(beforeRoundTrip, _service.ComputeHash(plan));
    }

    [Fact]
    public void CreateNormalizesExpirationToUtcMicroseconds()
    {
        var plan = _service.Create(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            "User.Update",
            "{}",
            1,
            _now.ToOffset(TimeSpan.FromHours(8)).AddTicks(7));

        Assert.Equal(TimeSpan.Zero, plan.ExpiresAt.Offset);
        Assert.Equal(0, plan.ExpiresAt.Ticks % 10);
    }

    [Fact]
    public void RequesterCannotApproveOwnPlan()
    {
        var plan = CreatePlan();

        var error = Assert.Throws<InvalidOperationException>(() => _service.Approve(
            plan,
            Guid.NewGuid(),
            plan.RequesterId,
            plan.PlanHash,
            _now,
            _now.AddMinutes(5)));

        Assert.Contains("own plan", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ApprovalMustUseExactUntamperedHash()
    {
        var plan = CreatePlan();
        plan.ImmutablePlanJson = "{\"value\":\"tampered\"}";

        Assert.Throws<InvalidOperationException>(() => _service.Approve(
            plan,
            Guid.NewGuid(),
            Guid.NewGuid(),
            plan.PlanHash,
            _now,
            _now.AddMinutes(5)));
    }

    [Fact]
    public void ExpiredApprovalCannotExecute()
    {
        var plan = CreatePlan();
        var approval = Approve(plan, approvalExpiry: _now.AddMinutes(1));

        var result = _service.ValidateForExecution(
            plan,
            approval,
            plan.PolicyVersion,
            CurrentVersions(plan),
            _now.AddMinutes(1));

        Assert.Equal(ChangePlanValidationFailure.Expired, result.Failure);
    }

    [Fact]
    public void ApprovalIsExpiredAtExactStoredBoundary()
    {
        var plan = CreatePlan();
        var approval = Approve(plan, approvalExpiry: _now.AddMinutes(1).AddTicks(7));

        var result = _service.ValidateForExecution(
            plan,
            approval,
            plan.PolicyVersion,
            CurrentVersions(plan),
            approval.ExpiresAt);

        Assert.Equal(0, approval.ExpiresAt.Ticks % 10);
        Assert.Equal(ChangePlanValidationFailure.Expired, result.Failure);
    }

    [Fact]
    public void PolicyVersionDriftCannotExecute()
    {
        var plan = CreatePlan();
        var approval = Approve(plan);

        var result = _service.ValidateForExecution(
            plan,
            approval,
            plan.PolicyVersion + 1,
            CurrentVersions(plan),
            _now);

        Assert.Equal(ChangePlanValidationFailure.PolicyVersionDrift, result.Failure);
    }

    [Fact]
    public void TargetVersionDriftCannotExecute()
    {
        var plan = CreatePlan();
        var approval = Approve(plan);
        var versions = CurrentVersions(plan);
        versions[plan.Items.Single().TargetId]++;

        var result = _service.ValidateForExecution(
            plan,
            approval,
            plan.PolicyVersion,
            versions,
            _now);

        Assert.Equal(ChangePlanValidationFailure.TargetVersionDrift, result.Failure);
    }

    [Fact]
    public void MatchingApprovalAndVersionsCanExecute()
    {
        var plan = CreatePlan();
        var approval = Approve(plan);

        var result = _service.ValidateForExecution(
            plan,
            approval,
            plan.PolicyVersion,
            CurrentVersions(plan),
            _now);

        Assert.True(result.IsValid);
        Assert.Equal(ChangePlanValidationFailure.None, result.Failure);
    }

    private ChangePlan CreatePlan(string json = "{\"value\":\"new\"}") => _service.Create(
        Guid.NewGuid(),
        Guid.NewGuid(),
        Guid.NewGuid(),
        "User.Update",
        json,
        12,
        _now.AddMinutes(10),
        [new ChangePlanItem { Id = Guid.NewGuid(), TargetId = "user-1", ExpectedVersion = 7 }],
        "Approved maintenance");

    private ChangeApproval Approve(ChangePlan plan, DateTimeOffset? approvalExpiry = null) => _service.Approve(
        plan,
        Guid.NewGuid(),
        Guid.NewGuid(),
        plan.PlanHash,
        _now,
        approvalExpiry ?? _now.AddMinutes(5));

    private static Dictionary<string, long> CurrentVersions(ChangePlan plan) =>
        plan.Items.ToDictionary(item => item.TargetId, item => item.ExpectedVersion, StringComparer.Ordinal);
}
