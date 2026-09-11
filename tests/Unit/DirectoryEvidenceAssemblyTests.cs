using ItManagement.Core;

namespace ItManagement.UnitTests;

public sealed class DirectoryEvidenceAssemblyTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-11T15:00:00Z");
    private static readonly DirectoryEvidenceBinding Binding = new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
        Guid.NewGuid(), PermissionCatalog.UserDisable, 7, new string('A', 64), new("dc01.example.test", "CN=NTDS Settings,CN=DC01,CN=Configuration,DC=example,DC=test", Guid.NewGuid(), Guid.NewGuid()), new string('C',64));
    private static readonly DirectoryChangeEvidence Object = new(Binding.EnvironmentId, Binding.DomainId, Binding.ObjectId,
        "User", "CN=Test,DC=example,DC=test", 42, Binding.ConfigurationHash, Binding.PolicyVersion,
        false, false, false, Now.AddSeconds(-1), true, "IT");
    private static DirectoryObjectObservation Read() => new(Binding, Object, DirectoryObservationSource.DirectDirectoryRead, Now.AddSeconds(-2), Now.AddSeconds(-1));
    private static DirectoryScopeObservation Scope() => new(Binding, 42, Object.DistinguishedName, true, Now);
    private static DirectoryProtectionObservation Protection() => new(Binding, 42, Object.DistinguishedName, DirectoryProtectionDecision.Unprotected, Now)
    {FactsHash=new string('D',64),FactsReadStartedAt=Now.AddSeconds(-1),FactsReadCompletedAt=Now};
    private static DirectoryEvidenceAssemblyResult Assemble(DirectoryObjectObservation? read = null,
        DirectoryScopeObservation? scope = null, DirectoryProtectionObservation? protection = null) =>
        DirectoryEvidenceAssembler.Assemble(Binding, DirectoryChangeKind.DisableUser, read ?? Read(), scope ?? Scope(), protection ?? Protection(), Now);

    [Fact]
    public void Bound_decisions_retain_the_full_context_in_a_consistency_receipt()
    {
        var result = Assemble(); Assert.Equal(DirectoryEvidenceFailure.None, result.Failure);
        var receipt = Assert.IsType<DirectoryEvidenceReceipt>(result.Receipt);
        Assert.Equal(Binding, receipt.Binding); Assert.Equal(Read(), receipt.Observation);
        Assert.Equal(Scope(), receipt.Scope); Assert.Equal(Protection(), receipt.Protection);
        Assert.Empty(typeof(DirectoryEvidenceReceipt).GetConstructors());
        var evidence = receipt.Evidence;
        Assert.Equal(Read().ReadStartedAt, evidence.ObservedAt); Assert.True(evidence.ScopeKnown); Assert.True(evidence.ProtectionKnown);
    }

    public static IEnumerable<object[]> BindingDrifts()
    {
        yield return [Binding with { EnvironmentId = Guid.NewGuid() }];
        yield return [Binding with { DomainId = Guid.NewGuid() }];
        yield return [Binding with { ObjectId = Guid.NewGuid() }];
        yield return [Binding with { ActorId = Guid.NewGuid() }];
        yield return [Binding with { Permission = PermissionCatalog.UserEdit }];
        yield return [Binding with { PolicyVersion = 8 }];
        yield return [Binding with { ConfigurationHash = new string('B', 64) }];
        yield return [Binding with { SchemaVersion = 1 }];
        yield return [Binding with { ProtectionPolicyHash = new string('D',64) }];
        yield return [Binding with { Server = Binding.Server with { DnsHostName = "dc02.example.test" } }];
        yield return [Binding with { Server = Binding.Server with { ServiceDn = "CN=Other" } }];
        yield return [Binding with { Server = Binding.Server with { DsaObjectId = Guid.NewGuid() } }];
        yield return [Binding with { Server = Binding.Server with { InvocationId = Guid.NewGuid() } }];
    }
    [Theory] [MemberData(nameof(BindingDrifts))]
    public void Every_binding_field_is_required_on_each_receipt(DirectoryEvidenceBinding changed)
    {
        foreach (var result in new[] { Assemble(Read() with { Binding = changed }), Assemble(scope: Scope() with { Binding = changed }),
            Assemble(protection: Protection() with { Binding = changed }) })
        { Assert.Null(result.Receipt); Assert.Equal(DirectoryEvidenceFailure.BindingMismatch, result.Failure); }
    }
    [Theory] [InlineData(DirectoryObservationSource.Unknown)] [InlineData(DirectoryObservationSource.CachedProjection)] [InlineData((DirectoryObservationSource)99)]
    public void Cached_or_unknown_sources_never_become_usable_evidence(DirectoryObservationSource source)
    {
        var result = Assemble(Read() with { Source = source }); Assert.Null(result.Receipt); Assert.Equal(DirectoryEvidenceFailure.SourceUnavailable, result.Failure);
    }
    [Fact]
    public void Full_read_window_and_assessment_order_are_checked_without_completion_time_refresh()
    {
        foreach (var read in new[] { Read() with { ReadStartedAt = Now.AddMinutes(-2).AddTicks(-1) },
            Read() with { ReadCompletedAt = Now.AddTicks(1) }, Read() with { ReadCompletedAt = Now.AddSeconds(-3) } })
            Assert.Equal(DirectoryEvidenceFailure.StaleObservation, Assemble(read).Failure);
        foreach (var at in new[] { Now.AddTicks(1), Now.AddSeconds(-2), Now.AddMinutes(-3) })
        {
            Assert.Equal(DirectoryEvidenceFailure.StaleObservation, Assemble(scope: Scope() with { EvaluatedAt = at }).Failure);
            Assert.Equal(DirectoryEvidenceFailure.StaleObservation, Assemble(protection: Protection() with { EvaluatedAt = at }).Failure);
        }
        Assert.Equal(DirectoryEvidenceFailure.None, Assemble(Read() with { ReadStartedAt = Now.AddMinutes(-2) }).Failure);
    }
    [Fact]
    public void Unknown_or_denied_decisions_override_positive_raw_flags()
    {
        var read = Read() with { Object = Object with { ScopeKnown = true, ProtectionKnown = true } };
        Assert.Equal(DirectoryEvidenceFailure.ScopeDenied, Assemble(read, Scope() with { Allowed = false }).Failure);
        Assert.Equal(DirectoryEvidenceFailure.ProtectionUnknown, Assemble(read, protection: Protection() with { Decision = DirectoryProtectionDecision.Unknown }).Failure);
        Assert.Equal(DirectoryEvidenceFailure.ProtectionUnknown, Assemble(read, protection: Protection() with { Decision = (DirectoryProtectionDecision)99 }).Failure);
        Assert.Equal(DirectoryEvidenceFailure.ProtectedObject, Assemble(read, protection: Protection() with { Decision = DirectoryProtectionDecision.Protected }).Failure);
        Assert.Equal(DirectoryEvidenceFailure.ProtectedObject, Assemble(Read() with { Object = Object with { IsProtected = true } }).Failure);
    }
    [Fact]
    public void Object_identity_versions_and_exact_dn_cannot_be_mixed()
    {
        foreach (var item in new[] { Object with { EnvironmentId = Guid.NewGuid() }, Object with { DomainId = Guid.NewGuid() },
            Object with { ObjectId = Guid.NewGuid() }, Object with { PolicyVersion = 8 }, Object with { ConnectorConfigurationHash = new string('B',64) },
            Object with { UsnChanged = 43 }, Object with { DistinguishedName = "CN=Moved,DC=example,DC=test" }, Object with { ObservedAt = Now } })
            Assert.Equal(DirectoryEvidenceFailure.ObjectMismatch, Assemble(Read() with { Object = item }).Failure);
        Assert.Equal(DirectoryEvidenceFailure.ObjectMismatch, Assemble(scope: Scope() with { UsnChanged = 43 }).Failure);
        Assert.Equal(DirectoryEvidenceFailure.ObjectMismatch, Assemble(protection: Protection() with { DistinguishedName = "CN=Other" }).Failure);
    }
    [Fact]
    public void Template_permission_and_required_account_state_are_checked()
    {
        Assert.Equal(DirectoryEvidenceFailure.InvalidBinding, DirectoryEvidenceAssembler.Assemble(Binding, DirectoryChangeKind.SetUserDepartment, Read(), Scope(), Protection(), Now).Failure);
        Assert.Equal(DirectoryEvidenceFailure.InvalidBinding, DirectoryEvidenceAssembler.Assemble(Binding with { ConfigurationHash = "bad" }, DirectoryChangeKind.DisableUser, Read(), Scope(), Protection(), Now).Failure);
        Assert.Equal(DirectoryEvidenceFailure.InvalidObject, Assemble(Read() with { Object = Object with { Enabled = null } }).Failure);
        Assert.Equal(DirectoryEvidenceFailure.InvalidObject, Assemble(Read() with { Object = Object with { ObjectKind = "Computer" } }).Failure);
        var b = Binding with { Permission = PermissionCatalog.UserEdit };
        var result = DirectoryEvidenceAssembler.Assemble(b, DirectoryChangeKind.SetUserDepartment,
            Read() with { Binding = b, Object = Object with { Enabled = null } }, Scope() with { Binding = b }, Protection() with { Binding = b }, Now);
        Assert.Equal(DirectoryEvidenceFailure.None, result.Failure);
    }

    [Fact]
    public void Invalid_expected_bindings_and_observation_before_read_are_rejected()
    {
        foreach (var binding in new[] { Binding with { EnvironmentId = Guid.Empty }, Binding with { DomainId = Guid.Empty },
            Binding with { ObjectId = Guid.Empty }, Binding with { ActorId = Guid.Empty }, Binding with { PolicyVersion = 0 },
            Binding with { SchemaVersion = 0 }, Binding with { ConfigurationHash = new string('Z',64) } })
        {
            var result = DirectoryEvidenceAssembler.Assemble(binding, DirectoryChangeKind.DisableUser, Read(), Scope(), Protection(), Now);
            Assert.Equal(DirectoryEvidenceFailure.InvalidBinding, result.Failure); Assert.Null(result.Receipt);
        }
        Assert.Equal(DirectoryEvidenceFailure.ObjectMismatch, Assemble(Read() with { Object = Object with { ObservedAt = Now.AddSeconds(-3) } }).Failure);
    }
}
