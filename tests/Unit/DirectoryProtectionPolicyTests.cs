using ItManagement.Core;

namespace ItManagement.UnitTests;

public sealed class DirectoryProtectionPolicyTests
{
    private static readonly Guid Env=Guid.Parse("11111111-1111-1111-1111-111111111111"), Domain=Guid.Parse("22222222-2222-2222-2222-222222222222"), Target=Guid.NewGuid();
    private static readonly DateTimeOffset Now=DateTimeOffset.Parse("2026-09-11T16:00:00Z");
    private const string Sid="S-1-5-21-10-20-30", Forest="S-1-5-21-40-50-60";
    private static DirectoryProtectionPolicy Policy(IEnumerable<Guid>? ids=null,IEnumerable<string>? sids=null,IEnumerable<string>? groups=null,long version=1) =>
        DirectoryProtectionPolicy.Create(Env,Domain,version,Sid,Forest,ids??[],sids??[],groups??[]);
    private static DirectoryObjectObservation Observation(DirectoryProtectionPolicy policy)
    {
        var binding=new DirectoryEvidenceBinding(Env,Domain,Target,Guid.NewGuid(),PermissionCatalog.UserEdit,policy.Version,new string('A',64),
            new("dc.example.test","CN=NTDS Settings,CN=Configuration,DC=example,DC=test",Guid.NewGuid(),Guid.NewGuid()),policy.Hash);
        return new(binding,new(Env,Domain,Target,"User","CN=User,DC=example,DC=test",42,binding.ConfigurationHash,policy.Version,false,false,false,Now.AddSeconds(-2),true,"IT"),
            DirectoryObservationSource.DirectDirectoryRead,Now.AddSeconds(-2),Now.AddSeconds(-1));
    }
    private static DirectoryProtectionFacts Facts(DirectoryObjectObservation o) => new(o,Now.AddSeconds(-1),Now,Sid+"-1001",[],[],true,true,true,false,false,false)
    {ReadObjectId=o.Binding.ObjectId,ReadServer=o.Binding.Server};
    private static Task<DirectoryProtectionObservation> Assess(DirectoryProtectionPolicy p,DirectoryObjectObservation o,DirectoryProtectionFacts? facts) =>
        new PolicyDirectoryProtectionAssessor(p,new Provider(facts),new Clock()).AssessAsync(o,default);
    [Fact]
    public void Policy_is_frozen_and_hash_is_order_independent_but_content_sensitive()
    {
        Assert.Equal("C7FDA3A3684259FC090F69EAD18ED932BE6E1FE0043111E2711D42F8530AB7FB",Policy().Hash);
        var a=Guid.NewGuid();var b=Guid.NewGuid();var ids=new List<Guid>{a,b};var p=Policy(ids,[Sid+"-1001",Sid+"-1002"]);
        ids.Clear();Assert.Equal(2,p.ProtectedObjects.Count);
        Assert.Equal(p.Hash,Policy([b,a],[Sid+"-1002",Sid+"-1001"]).Hash);
        Assert.NotEqual(p.Hash,Policy([b,a],[Sid+"-1003",Sid+"-1001"]).Hash);
        Assert.NotEqual(p.Hash,Policy([a,b],[Sid+"-1001",Sid+"-1002"],version:2).Hash);
        Assert.Contains(Sid+"-500",p.ProtectedSids.AsEnumerable());Assert.Contains(Sid+"-502",p.ProtectedSids.AsEnumerable());
        Assert.Contains(Forest+"-519",p.ProtectedGroups.AsEnumerable());Assert.DoesNotContain(Sid+"-519",p.ProtectedGroups.AsEnumerable());
        Assert.Contains("S-1-5-32-544",p.ProtectedGroups.AsEnumerable());
    }
    [Theory] [InlineData("S-1-5-21-01-2-3")] [InlineData("S-1-5-21-1-2")] [InlineData("domain.test")]
    public void Invalid_domain_sid_is_rejected(string sid) => Assert.Throws<ArgumentException>(()=>DirectoryProtectionPolicy.Create(Env,Domain,1,sid,Forest,[],[],[]));
    [Theory] [InlineData("S-1-5-021-1")] [InlineData("s-1-5-21-1")] [InlineData("S-1-5-21-4294967296")] [InlineData("Administrator")]
    public void Noncanonical_sids_are_rejected(string sid) => Assert.Throws<ArgumentException>(()=>Policy(sids:[sid]));
    [Fact]
    public async Task Explicit_guid_is_protected_when_facts_are_unavailable()
    { var p=Policy([Target]);var o=Observation(p);Assert.Equal(DirectoryProtectionDecision.Protected,(await Assess(p,o,null)).Decision); }
    [Fact]
    public async Task Missing_facts_remain_unknown_and_complete_negatives_can_be_unprotected()
    {
        var p=Policy();var o=Observation(p);
        Assert.Equal(DirectoryProtectionDecision.Unknown,(await Assess(p,o,null)).Decision);
        Assert.Equal(DirectoryProtectionDecision.Unprotected,(await Assess(p,o,Facts(o))).Decision);
    }
    [Theory] [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public async Task Every_incomplete_negative_dimension_stays_unknown(int field)
    {
        var p=Policy();var o=Observation(p);var facts=Facts(o);
        facts=field switch{0=>facts with{ObjectSidComplete=false},1=>facts with{SidHistoryComplete=false},2=>facts with{GroupsComplete=false},
            3=>facts with{IsServiceAccount=null},4=>facts with{IsVip=null},_=>facts with{IsPrivileged=null}};
        Assert.Equal(DirectoryProtectionDecision.Unknown,(await Assess(p,o,facts)).Decision);
    }
    [Theory] [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public async Task Positive_protection_survives_other_incomplete_dimensions(int field)
    {
        var p=Policy();var o=Observation(p);var facts=Facts(o) with { GroupsComplete=false,SidHistoryComplete=false };
        facts=field switch{0=>facts with{ObjectSid=Sid+"-500"},1=>facts with{SidHistory=[Sid+"-502"]},2=>facts with{GroupSids=[Forest+"-519"]},
            3=>facts with{IsServiceAccount=true},4=>facts with{IsVip=true},_=>facts with{IsPrivileged=true}};
        Assert.Equal(DirectoryProtectionDecision.Protected,(await Assess(p,o,facts)).Decision);
    }
    [Fact]
    public async Task Policy_hash_drift_and_receipt_drift_or_stale_facts_fail_closed()
    {
        var p=Policy();var o=Observation(p);var facts=Facts(o);
        var changed=o with{Binding=o.Binding with{ProtectionPolicyHash=new string('B',64)}};
        Assert.Equal("PolicyMismatch",(await Assess(p,changed,facts)).Reason);
        foreach(var bad in new[]{facts with{Observation=o with{Binding=o.Binding with{ActorId=Guid.NewGuid()}}},
            facts with{ReadStartedAt=Now.AddMinutes(-3)},facts with{ReadCompletedAt=Now.AddTicks(1)},facts with{ReadStartedAt=Now.AddSeconds(-2)}})
            Assert.Equal(DirectoryProtectionDecision.Unknown,(await Assess(p,o,bad)).Decision);
    }
    [Fact]
    public async Task Renamed_accounts_are_matched_by_sid_and_names_never_supply_protection()
    {
        var p=Policy();var o=Observation(p) with{Object=Observation(p).Object with{DistinguishedName="CN=Renamed,DC=example,DC=test"}};
        Assert.Equal(DirectoryProtectionDecision.Protected,(await Assess(p,o,Facts(o) with{ObjectSid=Sid+"-500"})).Decision);
        Assert.Equal(DirectoryProtectionDecision.Unknown,(await Assess(p,o,Facts(o) with{ObjectSid="Administrator"})).Decision);
    }
    [Fact]
    public async Task Classification_rejects_incoherent_object_and_missing_actual_read_identity()
    {
        var p=Policy();var o=Observation(p);
        foreach(var bad in new[]{o with{Binding=o.Binding with{ObjectId=Guid.Empty}},o with{Object=o.Object with{DomainId=Guid.NewGuid()}},
            o with{Source=DirectoryObservationSource.CachedProjection},o with{ReadStartedAt=Now.AddMinutes(-3)}})
            Assert.Equal(DirectoryProtectionDecision.Unknown,(await Assess(p,bad,Facts(bad))).Decision);
        Assert.Equal(DirectoryProtectionDecision.Unknown,(await Assess(p,o,Facts(o) with{ReadServer=null})).Decision);
        Assert.Equal(DirectoryProtectionDecision.Unknown,(await Assess(p,o,Facts(o) with{ReadObjectId=Guid.NewGuid()})).Decision);
    }
    [Fact]
    public async Task Malformed_other_facts_cannot_hide_positive_protection()
    {
        var p=Policy();var o=Observation(p);
        Assert.Equal(DirectoryProtectionDecision.Protected,(await Assess(p,o,Facts(o) with{IsVip=true,GroupSids=["bad"]})).Decision);
        Assert.Equal(DirectoryProtectionDecision.Protected,(await Assess(p,o,Facts(o) with{ObjectSid=Sid+"-500",SidHistory=["bad"]})).Decision);
        Assert.Equal(DirectoryProtectionDecision.Unknown,(await Assess(p,o,Facts(o) with{GroupSids=default})).Decision);
    }
    [Fact]
    public async Task Complete_negative_receipt_retains_reproducible_facts_digest_and_window()
    {
        var p=Policy();var o=Observation(p);var facts=Facts(o);var assessment=await Assess(p,o,facts);
        Assert.Equal(64,assessment.FactsHash!.Length);Assert.Equal(facts.ReadStartedAt,assessment.FactsReadStartedAt);
        var scope=new DirectoryScopeObservation(o.Binding,o.Object.UsnChanged,o.Object.DistinguishedName,true,Now);
        var result=DirectoryEvidenceAssembler.Assemble(o.Binding,DirectoryChangeKind.SetUserDepartment,o,scope,assessment,Now);
        Assert.Equal(DirectoryEvidenceFailure.None,result.Failure);Assert.Equal(assessment.FactsHash,result.Receipt!.Protection.FactsHash);
        var other=await Assess(p,o,facts with{GroupSids=[Sid+"-1002"]});Assert.NotEqual(assessment.FactsHash,other.FactsHash);
    }
    private sealed class Provider(DirectoryProtectionFacts? facts):IDirectoryProtectionFactsProvider
    {public Task<DirectoryProtectionFacts?> ReadAsync(DirectoryObjectObservation o,CancellationToken ct)=>Task.FromResult(facts);}
    private sealed class Clock:TimeProvider {public override DateTimeOffset GetUtcNow()=>Now;}
}
