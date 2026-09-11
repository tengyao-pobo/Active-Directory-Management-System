using ItManagement.ConnectorHost;
using ItManagement.DirectoryConnector;

namespace ItManagement.IntegrationTests;

public sealed class DirectoryTargetEvidenceTests
{
    private static readonly DirectorySourceIdentity Source = new("dc01.example.test", "CN=NTDS Settings,CN=DC01,CN=Configuration,DC=example,DC=test", Guid.NewGuid(), Guid.NewGuid());
    private static readonly Guid Domain = Guid.NewGuid();
    private static DirectoryTargetSnapshot Target() => new(Domain, new string('A',64), Source, DateTimeOffset.UtcNow.AddSeconds(-1), DateTimeOffset.UtcNow,
        new(Guid.NewGuid(), DirectoryObjectKind.User, "CN=User,DC=example,DC=test", "User", "user", "IT", null, 42, false, false, "DC=example,DC=test") { Enabled=true });
    private static DirectoryEvidenceBinding Binding(DirectoryTargetSnapshot target) => new(Guid.NewGuid(), Domain, target.Entry.ObjectId, Guid.NewGuid(),
        PermissionCatalog.UserDisable, 1, target.ConfigurationHash, new(Source.DnsHostName, Source.ServiceDn, Source.DsaObjectId, Source.InvocationId),new string('C',64));
    [Fact]
    public async Task Real_default_classifier_keeps_direct_reads_unusable_for_approval()
    {
        var target=Target(); var reader=new Reader(target); var scope=new ScopeAssessor();
        var service=new DirectoryTargetEvidenceService(reader,scope,new UnknownDirectoryProtectionAssessor(TimeProvider.System),TimeProvider.System);
        var result=await service.ReadAsync(Binding(target),DirectoryChangeKind.DisableUser,default);
        Assert.Equal(DirectoryEvidenceFailure.ProtectionUnknown,result.Failure); Assert.Null(result.Receipt); Assert.Equal(1,scope.Calls);
    }
    [Fact]
    public async Task Synthetic_assessments_preserve_source_and_all_context_in_receipt()
    {
        var target=Target(); var binding=Binding(target);
        var service=new DirectoryTargetEvidenceService(new Reader(target),new ScopeAssessor(),new SyntheticProtection(),TimeProvider.System);
        var result=await service.ReadAsync(binding,DirectoryChangeKind.DisableUser,default);
        Assert.Equal(DirectoryEvidenceFailure.None,result.Failure); Assert.Equal(binding,result.Receipt!.Binding);
        Assert.Equal(Source.InvocationId,result.Receipt.Binding.Server.InvocationId);
        Assert.Equal(target.ReadStartedAt,result.Receipt.Evidence.ObservedAt);
    }
    [Fact]
    public async Task Source_config_or_target_mismatch_never_reaches_assessors()
    {
        var target=Target(); var binding=Binding(target);
        foreach(var wrong in new[] { target with { Source=Source with { InvocationId=Guid.NewGuid() } }, target with { ConfigurationHash=new string('B',64) },
            target with { VerifiedDomainId=Guid.NewGuid() }, target with { Entry=target.Entry with { ObjectId=Guid.NewGuid() } } })
        {
            var scope=new ScopeAssessor(); var service=new DirectoryTargetEvidenceService(new Reader(wrong),scope,new SyntheticProtection(),TimeProvider.System);
            Assert.Equal(DirectoryEvidenceFailure.ObjectMismatch,(await service.ReadAsync(binding,DirectoryChangeKind.DisableUser,default)).Failure);
            Assert.Equal(0,scope.Calls);
        }
    }
    [Fact]
    public async Task A_classifier_cannot_rebind_the_actor_or_mark_an_old_read_fresh()
    {
        var target=Target(); var binding=Binding(target);
        var service=new DirectoryTargetEvidenceService(new Reader(target),new ScopeAssessor(),new SyntheticProtection(true),TimeProvider.System);
        Assert.Equal(DirectoryEvidenceFailure.BindingMismatch,(await service.ReadAsync(binding,DirectoryChangeKind.DisableUser,default)).Failure);
        service=new DirectoryTargetEvidenceService(new Reader(target with { ReadStartedAt=DateTimeOffset.UtcNow.AddMinutes(-3) }),new ScopeAssessor(),new SyntheticProtection(),TimeProvider.System);
        Assert.Equal(DirectoryEvidenceFailure.StaleObservation,(await service.ReadAsync(binding,DirectoryChangeKind.DisableUser,default)).Failure);
    }
    private sealed class Reader(DirectoryTargetSnapshot target) : IDirectoryTargetReader
    { public int Calls {get;private set;} public Task<DirectoryTargetSnapshot> ReadUserAsync(Guid id,CancellationToken ct) { Calls++;ct.ThrowIfCancellationRequested(); return Task.FromResult(target); } }
    [Fact]
    public async Task Invalid_policy_binding_is_rejected_before_ldap_io()
    {
        var target=Target();var reader=new Reader(target);
        var service=new DirectoryTargetEvidenceService(reader,new ScopeAssessor(),new SyntheticProtection(),TimeProvider.System);
        var result=await service.ReadAsync(Binding(target) with{ProtectionPolicyHash="invalid"},DirectoryChangeKind.DisableUser,default);
        Assert.Equal(DirectoryEvidenceFailure.InvalidBinding,result.Failure);Assert.Equal(0,reader.Calls);
    }
    private sealed class ScopeAssessor : IDirectoryScopeAssessor
    {
        public int Calls {get;private set;}
        public Task<DirectoryScopeObservation> AssessAsync(DirectoryObjectObservation o,CancellationToken ct)
        { Calls++; return Task.FromResult(new DirectoryScopeObservation(o.Binding,o.Object.UsnChanged,o.Object.DistinguishedName,true,DateTimeOffset.UtcNow)); }
    }
    private sealed class SyntheticProtection(bool wrongActor=false) : IDirectoryProtectionAssessor
    {
        public Task<DirectoryProtectionObservation> AssessAsync(DirectoryObjectObservation o,CancellationToken ct) =>
            Task.FromResult(new DirectoryProtectionObservation(wrongActor ? o.Binding with { ActorId=Guid.NewGuid() } : o.Binding,
                o.Object.UsnChanged,o.Object.DistinguishedName,DirectoryProtectionDecision.Unprotected,DateTimeOffset.UtcNow)
                {FactsHash=new string('D',64),FactsReadStartedAt=o.ReadCompletedAt,FactsReadCompletedAt=o.ReadCompletedAt});
    }
}
