using ItManagement.Core;

namespace ItManagement.UnitTests;

public sealed class DirectoryChangeTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-11T13:00:00Z");
    private static DirectoryChangeEvidence Evidence() => new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "User",
        "CN=Test,OU=People,DC=example,DC=test", 42, new string('A', 64), 1, false, true, true, Now, true, "IT");
    [Fact]
    public void Preview_is_read_only_and_remote_or_policy_drift_invalidates_it()
    {
        var before = Evidence();
        var plan = DirectoryChangePlanner.Preview(before, new(DirectoryChangeKind.DisableUser), Now);
        Assert.True(DirectoryChangePlanner.MatchesForExecution(plan, before with { ObservedAt = Now.AddSeconds(1) }, Now.AddSeconds(1)));
        Assert.False(DirectoryChangePlanner.MatchesForExecution(plan, before with { UsnChanged = 43 }, Now));
        Assert.False(DirectoryChangePlanner.MatchesForExecution(plan, before with { PolicyVersion = 2 }, Now));
        Assert.False(DirectoryChangePlanner.MatchesForExecution(plan, before with { DomainId = Guid.NewGuid() }, Now));
        Assert.False(DirectoryChangePlanner.MatchesForExecution(plan, before with { DistinguishedName = "CN=Moved,DC=example,DC=test" }, Now));
        Assert.False(DirectoryChangePlanner.MatchesForExecution(plan with { Desired = new(DirectoryChangeKind.SetUserDepartment, "HR") }, before, Now));
    }
    [Fact]
    public void Unknown_or_protected_or_stale_evidence_fails_closed()
    {
        var before = Evidence();
        foreach (var evidence in new[] { before with { ProtectionKnown = false }, before with { IsProtected = true },
            before with { ScopeKnown = false }, before with { ObservedAt = Now.AddMinutes(-3) } })
            Assert.Throws<ArgumentException>(() => DirectoryChangePlanner.Preview(evidence, new(DirectoryChangeKind.DisableUser), Now));
    }
    [Fact]
    public async Task Live_mutations_are_explicitly_unavailable()
    {
        var plan = DirectoryChangePlanner.Preview(Evidence(), new(DirectoryChangeKind.DisableUser), Now);
        var result = await new UnavailableDirectoryMutationAdapter().ExecuteAsync(plan, CancellationToken.None);
        Assert.Equal(DirectoryMutationOutcome.Unavailable, result.Outcome);
    }
}
