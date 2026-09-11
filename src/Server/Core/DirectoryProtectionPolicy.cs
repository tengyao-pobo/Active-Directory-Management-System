using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ItManagement.Core;

// Provisioning must independently verify both domain SIDs. This value object cannot prove their origin.
public sealed class DirectoryProtectionPolicy
{
    private DirectoryProtectionPolicy(Guid environment, Guid domain, long version, string domainSid, string forestSid,
        FrozenSet<Guid> objects, FrozenSet<string> sids, FrozenSet<string> groups)
    {
        EnvironmentId=environment; DomainId=domain; Version=version; ProtectedObjects=objects; ProtectedSids=sids; ProtectedGroups=groups;
        Hash=Digest(["ProtectionPolicy/v1","Classifier/v1",environment.ToString("D"),domain.ToString("D"),version.ToString(CultureInfo.InvariantCulture),domainSid,forestSid,
            objects.Count.ToString(CultureInfo.InvariantCulture),..objects.Select(x=>x.ToString("D")).Order(StringComparer.Ordinal),
            sids.Count.ToString(CultureInfo.InvariantCulture),..sids.Order(StringComparer.Ordinal),
            groups.Count.ToString(CultureInfo.InvariantCulture),..groups.Order(StringComparer.Ordinal)]);
    }
    public Guid EnvironmentId {get;}
    public Guid DomainId {get;}
    public long Version {get;}
    public string Hash {get;}
    public FrozenSet<Guid> ProtectedObjects {get;}
    public FrozenSet<string> ProtectedSids {get;}
    public FrozenSet<string> ProtectedGroups {get;}
    // Each UTF-8 field has a signed 32-bit big-endian byte length; null is -1. No BOM.
    internal static string Digest(IEnumerable<string?> fields)
    {
        using var stream=new MemoryStream(); Span<byte> length=stackalloc byte[4];
        foreach(var field in fields)
        {
            var bytes=field is null ? null : Encoding.UTF8.GetBytes(field);
            BinaryPrimitives.WriteInt32BigEndian(length,bytes?.Length??-1);stream.Write(length);if(bytes is not null)stream.Write(bytes);
        }
        return Convert.ToHexString(SHA256.HashData(stream.ToArray()));
    }

    public static DirectoryProtectionPolicy Create(Guid environment, Guid domain, long version, string domainSid,
        string forestRootSid, IEnumerable<Guid> objects, IEnumerable<string> objectSids, IEnumerable<string> groupSids)
    {
        if(environment==Guid.Empty || domain==Guid.Empty || version<1 || !IsDomainSid(domainSid) || !IsDomainSid(forestRootSid))
            throw new ArgumentException("InvalidProtectionPolicy");
        var ids=objects.Take(10001).ToArray(); var sids=objectSids.Take(10001).ToArray(); var groups=groupSids.Take(10001).ToArray();
        if(ids.Length>10000 || sids.Length>10000 || groups.Length>10000 || ids.Contains(Guid.Empty) || sids.Any(s=>!IsCanonicalSid(s)) || groups.Any(s=>!IsCanonicalSid(s)))
            throw new ArgumentException("InvalidProtectionPolicy");
        // Mandatory conservative baseline, never localized display names or target-derived SID prefixes.
        sids=[..sids,domainSid+"-500",domainSid+"-502"];
        groups=[..groups,..new[]{512,516,520,521,525,526,527}.Select(r=>domainSid+"-"+r.ToString(CultureInfo.InvariantCulture)),
            forestRootSid+"-518",forestRootSid+"-519",..new[]{544,548,549,550,551,552}.Select(r=>"S-1-5-32-"+r.ToString(CultureInfo.InvariantCulture))];
        return new(environment,domain,version,domainSid,forestRootSid,ids.ToFrozenSet(),sids.ToFrozenSet(StringComparer.Ordinal),groups.ToFrozenSet(StringComparer.Ordinal));
    }
    internal static bool IsCanonicalSid(string? value)
    {
        if(value is not {Length: >0 and <=184}) return false;
        var parts=value.Split('-');
        if(parts.Length is <4 or >18 || parts[0]!="S" || parts[1]!="1" ||
            !ulong.TryParse(parts[2],NumberStyles.None,CultureInfo.InvariantCulture,out var authority) || authority>281474976710655 || parts[2]!=authority.ToString(CultureInfo.InvariantCulture)) return false;
        return parts.Skip(3).All(p=>uint.TryParse(p,NumberStyles.None,CultureInfo.InvariantCulture,out var n) && p==n.ToString(CultureInfo.InvariantCulture));
    }
    private static bool IsDomainSid(string value) => IsCanonicalSid(value) && value.Split('-').Length==7 && value.StartsWith("S-1-5-21-",StringComparison.Ordinal);
}

public sealed record DirectoryProtectionFacts(DirectoryObjectObservation Observation, DateTimeOffset ReadStartedAt,
    DateTimeOffset ReadCompletedAt, string? ObjectSid, ImmutableArray<string> SidHistory, ImmutableArray<string> GroupSids,
    bool ObjectSidComplete, bool SidHistoryComplete, bool GroupsComplete, bool? IsServiceAccount, bool? IsVip, bool? IsPrivileged)
{
    // Provider postcondition: source and subject must come from the actual facts read, not copied from a request.
    public DirectoryEvidenceServer? ReadServer {get;init;}
    public Guid ReadObjectId {get;init;}
}
public interface IDirectoryProtectionFactsProvider
{
    Task<DirectoryProtectionFacts?> ReadAsync(DirectoryObjectObservation observation,CancellationToken ct);
}
public sealed class UnavailableDirectoryProtectionFactsProvider : IDirectoryProtectionFactsProvider
{
    public Task<DirectoryProtectionFacts?> ReadAsync(DirectoryObjectObservation observation,CancellationToken ct)
    { ct.ThrowIfCancellationRequested(); return Task.FromResult<DirectoryProtectionFacts?>(null); }
}

public sealed class PolicyDirectoryProtectionAssessor(DirectoryProtectionPolicy policy, IDirectoryProtectionFactsProvider factsProvider, TimeProvider time) : IDirectoryProtectionAssessor
{
    public async Task<DirectoryProtectionObservation> AssessAsync(DirectoryObjectObservation observation,CancellationToken ct)
    {
        var binding=observation.Binding;
        DirectoryProtectionFacts? captured=null;
        string? digest=null;
        DirectoryProtectionObservation Result(DirectoryProtectionDecision decision,string reason) => new(binding,observation.Object.UsnChanged,
            observation.Object.DistinguishedName,decision,time.GetUtcNow()) { Reason=reason,FactsHash=digest,
                FactsReadStartedAt=captured?.ReadStartedAt,FactsReadCompletedAt=captured?.ReadCompletedAt };
        ct.ThrowIfCancellationRequested();
        var kind=binding.Permission==PermissionCatalog.UserDisable ? DirectoryChangeKind.DisableUser : DirectoryChangeKind.SetUserDepartment;
        var obj=observation.Object;var current=time.GetUtcNow();
        if(!DirectoryEvidenceAssembler.IsBindingValid(binding,kind) || observation.Source!=DirectoryObservationSource.DirectDirectoryRead ||
            observation.ReadStartedAt>observation.ReadCompletedAt || observation.ReadCompletedAt>current || observation.ReadStartedAt<current.AddMinutes(-2) ||
            obj.EnvironmentId!=binding.EnvironmentId || obj.DomainId!=binding.DomainId || obj.ObjectId!=binding.ObjectId || obj.ObjectKind!="User" ||
            obj.PolicyVersion!=binding.PolicyVersion || obj.ConnectorConfigurationHash!=binding.ConfigurationHash || obj.UsnChanged<0 ||
            string.IsNullOrWhiteSpace(obj.DistinguishedName) || obj.DistinguishedName.Length>4096 ||
            obj.ObservedAt<observation.ReadStartedAt || obj.ObservedAt>observation.ReadCompletedAt)
            return Result(DirectoryProtectionDecision.Unknown,"InvalidObservation");
        if(binding.EnvironmentId!=policy.EnvironmentId || binding.DomainId!=policy.DomainId || binding.PolicyVersion!=policy.Version || binding.ProtectionPolicyHash!=policy.Hash)
            return Result(DirectoryProtectionDecision.Unknown,"PolicyMismatch");
        if(policy.ProtectedObjects.Contains(binding.ObjectId) || observation.Object.IsProtected)
            return Result(DirectoryProtectionDecision.Protected,"ProtectedObject");
        var facts=await factsProvider.ReadAsync(observation,ct); ct.ThrowIfCancellationRequested();
        var now=time.GetUtcNow();
        if(facts is null || facts.Observation!=observation || facts.ReadServer!=binding.Server || facts.ReadObjectId!=binding.ObjectId ||
            facts.ReadStartedAt<observation.ReadCompletedAt || facts.ReadStartedAt>facts.ReadCompletedAt || facts.ReadCompletedAt>now || facts.ReadStartedAt<now.AddMinutes(-2))
            return Result(DirectoryProtectionDecision.Unknown,"FactsUnavailable");
        if(facts.IsServiceAccount==true || facts.IsVip==true || facts.IsPrivileged==true)
            return Result(DirectoryProtectionDecision.Protected,"ProtectedClassification");
        var history=facts.SidHistory.IsDefault ? [] : facts.SidHistory.Take(10001).ToArray(); var groups=facts.GroupSids.IsDefault ? [] : facts.GroupSids.Take(10001).ToArray();
        bool ProtectedSid(string sid)=>policy.ProtectedSids.Contains(sid)||policy.ProtectedGroups.Contains(sid);
        if((facts.ObjectSid is not null && ProtectedSid(facts.ObjectSid)) || history.Any(ProtectedSid) || groups.Any(ProtectedSid) ||
            facts.IsServiceAccount==true || facts.IsVip==true || facts.IsPrivileged==true)
            return Result(DirectoryProtectionDecision.Protected,"ProtectedIdentity");
        if(facts.SidHistory.IsDefault || facts.GroupSids.IsDefault || history.Length>10000 || groups.Length>10000 ||
            history.Any(s=>!DirectoryProtectionPolicy.IsCanonicalSid(s)) || groups.Any(s=>!DirectoryProtectionPolicy.IsCanonicalSid(s)) ||
            (facts.ObjectSid is not null && !DirectoryProtectionPolicy.IsCanonicalSid(facts.ObjectSid)))
            return Result(DirectoryProtectionDecision.Unknown,"InvalidFacts");
        if(!facts.ObjectSidComplete || facts.ObjectSid is null || !facts.SidHistoryComplete || !facts.GroupsComplete ||
            facts.IsServiceAccount is null || facts.IsVip is null || facts.IsPrivileged is null)
            return Result(DirectoryProtectionDecision.Unknown,"IncompleteFacts");
        captured=facts;
        digest=DirectoryProtectionPolicy.Digest(["ProtectionFacts/v1",binding.EnvironmentId.ToString("D"),binding.DomainId.ToString("D"),binding.ObjectId.ToString("D"),
            binding.ActorId.ToString("D"),binding.Permission,binding.PolicyVersion.ToString(CultureInfo.InvariantCulture),binding.ConfigurationHash,binding.ProtectionPolicyHash,
            binding.Server.DnsHostName,binding.Server.ServiceDn,binding.Server.DsaObjectId.ToString("D"),binding.Server.InvocationId.ToString("D"),
            obj.DistinguishedName,obj.UsnChanged.ToString(CultureInfo.InvariantCulture),facts.ReadStartedAt.UtcTicks.ToString(CultureInfo.InvariantCulture),facts.ReadCompletedAt.UtcTicks.ToString(CultureInfo.InvariantCulture),
            facts.ObjectSid,history.Length.ToString(CultureInfo.InvariantCulture),..history.Order(StringComparer.Ordinal),groups.Length.ToString(CultureInfo.InvariantCulture),..groups.Order(StringComparer.Ordinal),
            "CompleteNegativeFacts"]);
        return Result(DirectoryProtectionDecision.Unprotected,"CompleteNegativeFacts");
    }
}
