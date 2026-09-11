using ItManagement.DirectoryConnector;

namespace DirectoryConnector.Tests;

public sealed class LdapDirectoryReaderTests
{
    private static readonly Guid DomainId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    [Fact]
    public async Task ReadSnapshotAsync_MapsCompletePagedSnapshot()
    {
        var objectId = Guid.Parse("11111111-2222-3333-4444-555555555555");
        var transport = new FakeTransport
        {
            Pages = new Queue<object>(
            [
                new DirectoryPage([Entry(objectId)], [1, 2, 3]),
                new DirectoryPage([], []),
            ]),
        };
        var reader = Reader(transport);

        var snapshot = await reader.ReadSnapshotAsync(CancellationToken.None);

        Assert.Equal("dc01.example.com", snapshot.SourceServer);
        Assert.Equal("DC=example,DC=com", snapshot.NamingContext);
        var entry = Assert.Single(snapshot.Entries);
        Assert.Equal(objectId, entry.ObjectId);
        Assert.Equal(DirectoryObjectKind.User, entry.Kind);
        Assert.Equal("OU=People,DC=example,DC=com", entry.ParentDn);
        Assert.Equal("S-1-5-21-1000", entry.ObjectSid);
        Assert.False(entry.IsProtected);
        Assert.False(entry.ProtectionKnown);
        Assert.Equal(2, transport.PageCalls);
    }

    [Fact]
    public async Task ReadSnapshotAsync_RejectsUnadvertisedBaseWithoutReadingPages()
    {
        var transport = new FakeTransport
        {
            RootDse = new RootDseResult(["DC=other,DC=com"]),
        };

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => Reader(transport).ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.NamingContextMismatch, exception.Code);
        Assert.Equal(0, transport.PageCalls);
    }

    [Fact]
    public async Task ReadSnapshotAsync_RejectsUnexpectedDomainGuid()
    {
        var transport = new FakeTransport { BaseObjectId = Guid.NewGuid() };

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => Reader(transport).ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.DomainIdentityMismatch, exception.Code);
        Assert.Equal(0, transport.PageCalls);
    }

    [Fact]
    public async Task ReadSnapshotAsync_RejectsRepeatedPagingCookie()
    {
        var transport = new FakeTransport
        {
            Pages = new Queue<object>(
            [
                new DirectoryPage([Entry(Guid.NewGuid())], [7]),
                new DirectoryPage([Entry(Guid.NewGuid())], [7]),
            ]),
        };

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => Reader(transport).ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.PagingLoop, exception.Code);
    }

    [Fact]
    public async Task ReadSnapshotAsync_RejectsWholeSnapshotWhenLimitExceeded()
    {
        var transport = new FakeTransport
        {
            Pages = new Queue<object>(
            [
                new DirectoryPage([Entry(Guid.NewGuid())], [1]),
                new DirectoryPage([Entry(Guid.NewGuid())], []),
            ]),
        };

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => Reader(transport, maxEntries: 1).ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.EntryLimitExceeded, exception.Code);
    }

    [Fact]
    public async Task ReadSnapshotAsync_SanitizesFailureAfterPartialPage()
    {
        var transport = new FakeTransport
        {
            Pages = new Queue<object>(
            [
                new DirectoryPage([Entry(Guid.NewGuid())], [1]),
                new DirectoryTransportException(DirectoryReadErrorCode.ConnectionFailed),
            ]),
        };

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => Reader(transport).ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.ConnectionFailed, exception.Code);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain("dc01", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadSnapshotAsync_RejectsMalformedRequiredAttribute()
    {
        var entry = Entry(Guid.NewGuid());
        var attributes = new Dictionary<string, IReadOnlyList<object>>(entry.Attributes, StringComparer.OrdinalIgnoreCase)
        {
            ["uSNChanged"] = ["not-a-number"],
        };
        var transport = new FakeTransport
        {
            Pages = new Queue<object>([new DirectoryPage([entry with { Attributes = attributes }], [])]),
        };

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => Reader(transport).ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.InvalidResponse, exception.Code);
    }

    [Theory]
    [InlineData("user", DirectoryObjectKind.User)]
    [InlineData("group", DirectoryObjectKind.Group)]
    [InlineData("computer", DirectoryObjectKind.Computer)]
    [InlineData("organizationalUnit", DirectoryObjectKind.OrganizationalUnit)]
    public async Task ReadSnapshotAsync_ClassifiesEverySupportedObjectKind(
        string objectClass,
        DirectoryObjectKind expected)
    {
        var transport = new FakeTransport
        {
            Pages = new Queue<object>([new DirectoryPage([Entry(Guid.NewGuid(), objectClass)], [])]),
        };

        var snapshot = await Reader(transport).ReadSnapshotAsync(CancellationToken.None);

        Assert.Equal(expected, Assert.Single(snapshot.Entries).Kind);
    }

    [Fact]
    public async Task ReadSnapshotAsync_RejectsTooManyUniquePages()
    {
        var transport = new FakeTransport
        {
            Pages = new Queue<object>(
            [
                new DirectoryPage([Entry(Guid.NewGuid())], [1]),
                new DirectoryPage([Entry(Guid.NewGuid())], [2]),
                new DirectoryPage([], []),
            ]),
        };

        var reader = new LdapDirectoryReader(
            ValidOptions() with { MaxPages = 2 },
            new FakeTransportFactory(transport));

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => reader.ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.PageLimitExceeded, exception.Code);
    }

    [Fact]
    public async Task ReadSnapshotAsync_RejectsOversizedPagingCookie()
    {
        var transport = new FakeTransport
        {
            Pages = new Queue<object>(
                [new DirectoryPage([Entry(Guid.NewGuid())], new byte[4_097])]),
        };

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => Reader(transport).ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.InvalidResponse, exception.Code);
    }

    [Fact]
    public async Task ReadSnapshotAsync_EnforcesOverallSnapshotDeadline()
    {
        var transport = new FakeTransport { RootDseDelay = TimeSpan.FromSeconds(1) };
        var reader = new LdapDirectoryReader(
            ValidOptions() with { SnapshotTimeout = TimeSpan.FromMilliseconds(20), RequestTimeout = TimeSpan.FromMilliseconds(10) },
            new FakeTransportFactory(transport));

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => reader.ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.Timeout, exception.Code);
    }

    [Theory]
    [InlineData("https://dc01.example.com", 100)]
    [InlineData("dc01.example.com:636", 100)]
    [InlineData("dc01", 100)]
    [InlineData("dc01_example.com", 100)]
    [InlineData("dc01.example.com", 100001)]
    public async Task ReadSnapshotAsync_RejectsUnsafeConfigurationBeforeTransport(
        string host,
        int maxEntries)
    {
        var transport = new FakeTransport();
        var options = ValidOptions() with { Host = host, MaxEntries = maxEntries };

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => new LdapDirectoryReader(options, new FakeTransportFactory(transport))
                .ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.InvalidConfiguration, exception.Code);
        Assert.Equal(0, transport.RootDseCalls);
    }

    [Fact]
    public async Task ReadSnapshotAsync_RejectsHostLongerThanDnsMaximum()
    {
        var transport = new FakeTransport();
        var host = $"{new string('a', 63)}.{new string('b', 63)}.{new string('c', 63)}.{new string('d', 62)}";
        var options = ValidOptions() with { Host = host };

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => new LdapDirectoryReader(options, new FakeTransportFactory(transport))
                .ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.InvalidConfiguration, exception.Code);
        Assert.Equal(254, host.Length);
        Assert.Equal(0, transport.RootDseCalls);
    }

    [Fact]
    public async Task ReadSnapshotAsync_RejectsPageCapAboveLibraryMaximum()
    {
        var transport = new FakeTransport();
        var options = ValidOptions() with { MaxPages = 10_001 };

        var exception = await Assert.ThrowsAsync<DirectoryReadException>(
            () => new LdapDirectoryReader(options, new FakeTransportFactory(transport))
                .ReadSnapshotAsync(CancellationToken.None));

        Assert.Equal(DirectoryReadErrorCode.InvalidConfiguration, exception.Code);
        Assert.Equal(0, transport.RootDseCalls);
    }

    private static LdapDirectoryReader Reader(FakeTransport transport, int maxEntries = 100) =>
        new(
            ValidOptions() with { MaxEntries = maxEntries },
            new FakeTransportFactory(transport));

    [Fact]
    public async Task Snapshot_retains_verified_domain_configuration_and_full_read_window()
    {
        var transport = new FakeTransport { RootDseDelay = TimeSpan.FromMilliseconds(30) };
        var before = DateTimeOffset.UtcNow;
        var snapshot = await Reader(transport).ReadSnapshotAsync(CancellationToken.None);
        Assert.Equal(DomainId, snapshot.VerifiedDomainId);
        Assert.Equal(ValidOptions().ComputeConfigurationHash(), snapshot.ConfigurationHash);
        Assert.InRange(snapshot.ReadStartedAt!.Value, before, snapshot.CapturedAt);
        Assert.True(snapshot.CapturedAt - snapshot.ReadStartedAt >= TimeSpan.FromMilliseconds(20));
    }

    [Theory]
    [InlineData("512", true)] [InlineData("514", false)] [InlineData("66048", true)] [InlineData("66050", false)]
    public async Task Enabled_state_preserves_the_disable_flag(string flags, bool enabled)
    {
        var entry = Entry(Guid.NewGuid());
        var attributes = new Dictionary<string, IReadOnlyList<object>>(entry.Attributes) { ["userAccountControl"] = [flags] };
        var transport = new FakeTransport { Pages = new([new DirectoryPage([entry with { Attributes = attributes }], [])]) };
        var row = Assert.Single((await Reader(transport).ReadSnapshotAsync(CancellationToken.None)).Entries);
        Assert.Equal(enabled, row.Enabled); Assert.False(row.ProtectionKnown);
    }

    [Fact]
    public async Task Missing_enabled_state_stays_unknown()
    {
        var transport = new FakeTransport { Pages = new([new DirectoryPage([Entry(Guid.NewGuid())], [])]) };
        Assert.Null(Assert.Single((await Reader(transport).ReadSnapshotAsync(CancellationToken.None)).Entries).Enabled);
    }

    [Theory]
    [InlineData("-1")] [InlineData("4294967296")] [InlineData("garbage")] [InlineData(" 512")]
    public async Task Invalid_account_flags_reject_the_whole_snapshot(string flags)
    {
        var entry = Entry(Guid.NewGuid());
        var attributes = new Dictionary<string, IReadOnlyList<object>>(entry.Attributes) { ["userAccountControl"] = [flags] };
        var transport = new FakeTransport { Pages = new([new DirectoryPage([entry with { Attributes = attributes }], [])]) };
        var error = await Assert.ThrowsAsync<DirectoryReadException>(() => Reader(transport).ReadSnapshotAsync(CancellationToken.None));
        Assert.Equal(DirectoryReadErrorCode.InvalidResponse, error.Code);
    }

    [Fact]
    public void Configuration_digest_changes_with_every_effective_setting()
    {
        var options = ValidOptions(); var hash = options.ComputeConfigurationHash();
        Assert.Equal(hash, (options with { Host = options.Host.ToUpperInvariant() }).ComputeConfigurationHash());
        foreach (var changed in new[] { options with { Host = "dc02.example.com" }, options with { BaseDn = "DC=other,DC=com" },
            options with { ExpectedDomainId = Guid.NewGuid() }, options with { PageSize = 11 }, options with { MaxPages = 21 },
            options with { MaxEntries = 101 }, options with { RequestTimeout = TimeSpan.FromSeconds(6) }, options with { SnapshotTimeout = TimeSpan.FromSeconds(31) } })
            Assert.NotEqual(hash, changed.ComputeConfigurationHash());
        Assert.Throws<DirectoryReadException>(() => (options with { Host = "invalid" }).ComputeConfigurationHash());
    }

    [Fact]
    public async Task Multiple_account_flags_are_rejected_and_non_accounts_remain_unknown()
    {
        var entry = Entry(Guid.NewGuid());
        var attributes = new Dictionary<string, IReadOnlyList<object>>(entry.Attributes) { ["userAccountControl"] = ["512", "514"] };
        var transport = new FakeTransport { Pages = new([new DirectoryPage([entry with { Attributes = attributes }], [])]) };
        var error = await Assert.ThrowsAsync<DirectoryReadException>(() => Reader(transport).ReadSnapshotAsync(CancellationToken.None));
        Assert.Equal(DirectoryReadErrorCode.InvalidResponse, error.Code);
        var group = Entry(Guid.NewGuid(), "group");
        attributes = new Dictionary<string, IReadOnlyList<object>>(group.Attributes) { ["userAccountControl"] = ["512"] };
        transport = new FakeTransport { Pages = new([new DirectoryPage([group with { Attributes = attributes }], [])]) };
        Assert.Null(Assert.Single((await Reader(transport).ReadSnapshotAsync(CancellationToken.None)).Entries).Enabled);
    }

    private static DirectoryConnectorOptions ValidOptions() => new()
    {
        Host = "dc01.example.com",
        BaseDn = "DC=example,DC=com",
        ExpectedDomainId = DomainId,
        PageSize = 10,
        MaxEntries = 100,
        RequestTimeout = TimeSpan.FromSeconds(5),
        SnapshotTimeout = TimeSpan.FromSeconds(30),
        MaxPages = 20,
    };

    [Fact]
    public async Task Target_read_binds_domain_and_both_source_checks_without_paging()
    {
        var id = Guid.NewGuid(); var transport = new FakeTransport { Targets = [Entry(id)] };
        var target = await Reader(transport).ReadUserAsync(id, default);
        Assert.Equal(id, target.Entry.ObjectId); Assert.Equal(DomainId, target.VerifiedDomainId);
        Assert.Equal(FakeTransport.Source, target.Source); Assert.Equal(2, transport.IdentityCalls);
        Assert.Equal(0, transport.PageCalls); Assert.False(target.Entry.ProtectionKnown);
        Assert.True(target.ReadStartedAt <= target.ReadCompletedAt);
    }
    [Theory] [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public async Task Any_source_identity_change_rejects_target(int field)
    {
        var original=FakeTransport.Source;
        var changed=field switch { 0=>original with { DnsHostName="dc02.example.com" }, 1=>original with { ServiceDn="CN=Other" },
            2=>original with { DsaObjectId=Guid.NewGuid() }, _=>original with { InvocationId=Guid.NewGuid() } };
        var id=Guid.NewGuid(); var transport=new FakeTransport { Targets=[Entry(id)], Sources=new([original,changed]) };
        var error=await Assert.ThrowsAsync<DirectoryReadException>(()=>Reader(transport).ReadUserAsync(id,default));
        Assert.Equal(DirectoryReadErrorCode.DomainIdentityMismatch,error.Code);
    }
    [Fact]
    public async Task Wrong_domain_or_missing_invocation_stops_before_target_search()
    {
        var id=Guid.NewGuid();
        foreach(var transport in new[] { new FakeTransport { BaseObjectId=Guid.NewGuid() },
            new FakeTransport { Sources=new([FakeTransport.Source with { InvocationId=Guid.Empty }]) } })
        {
            await Assert.ThrowsAsync<DirectoryReadException>(()=>Reader(transport).ReadUserAsync(id,default));
            Assert.Equal(0,transport.TargetCalls);
        }
    }
    [Theory] [InlineData(0)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public async Task Missing_duplicate_wrong_guid_or_kind_is_rejected(int scenario)
    {
        var id=Guid.NewGuid(); var entry=Entry(id);
        DirectoryRawEntry[] entries=scenario switch { 0=>[], 2=>[entry,entry], 3=>[Entry(Guid.NewGuid())], _=>[Entry(id,"computer")] };
        await Assert.ThrowsAsync<DirectoryReadException>(()=>Reader(new FakeTransport { Targets=entries }).ReadUserAsync(id,default));
    }
    [Fact]
    public async Task Target_deadline_and_caller_cancellation_are_distinct()
    {
        var transport=new FakeTransport { TargetDelay=TimeSpan.FromSeconds(2) };
        var reader=new LdapDirectoryReader(ValidOptions() with { TargetReadTimeout=TimeSpan.FromMilliseconds(10) },new FakeTransportFactory(transport));
        var error=await Assert.ThrowsAsync<DirectoryReadException>(()=>reader.ReadUserAsync(Guid.NewGuid(),default));
        Assert.Equal(DirectoryReadErrorCode.Timeout,error.Code);
        using var cancellation=new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Reader(new FakeTransport()).ReadUserAsync(Guid.NewGuid(),cancellation.Token));
    }
    [Fact]
    public void Guid_query_is_binary_escaped_bounded_and_has_no_paging_or_arbitrary_attributes()
    {
        var id=Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
        var request=ProtocolsDirectoryTransport.UserRequest("DC=example,DC=com",id);
        Assert.Equal("(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))(objectGUID=\\33\\22\\11\\00\\55\\44\\77\\66\\88\\99\\aa\\bb\\cc\\dd\\ee\\ff))",request.Filter);
        Assert.Equal(2,request.SizeLimit); Assert.Empty(request.Controls);
        Assert.Equal(System.DirectoryServices.Protocols.SearchScope.Subtree,request.Scope);
        Assert.DoesNotContain("unicodePwd",request.Attributes.Cast<string>());
        Assert.Contains("userAccountControl",request.Attributes.Cast<string>());
        Assert.NotEqual(ValidOptions().ComputeConfigurationHash(),(ValidOptions() with { TargetReadTimeout=TimeSpan.FromSeconds(10) }).ComputeConfigurationHash());
    }

    [Fact]
    public async Task Out_of_naming_context_and_malformed_target_are_rejected()
    {
        var id=Guid.NewGuid(); var entry=Entry(id);
        var dn="CN=Outside,DC=other,DC=com";
        var attributes=new Dictionary<string,IReadOnlyList<object>>(entry.Attributes) { ["distinguishedName"]=[dn] };
        await Assert.ThrowsAsync<DirectoryReadException>(()=>Reader(new FakeTransport { Targets=[entry with { DistinguishedName=dn,Attributes=attributes }] }).ReadUserAsync(id,default));
        attributes=new Dictionary<string,IReadOnlyList<object>>(entry.Attributes) { ["uSNChanged"]=["-1"] };
        await Assert.ThrowsAsync<DirectoryReadException>(()=>Reader(new FakeTransport { Targets=[entry with { Attributes=attributes }] }).ReadUserAsync(id,default));
    }
    [Fact]
    public async Task Invalid_target_or_timeout_configuration_never_opens_transport()
    {
        var transport=new FakeTransport();
        await Assert.ThrowsAsync<DirectoryReadException>(()=>Reader(transport).ReadUserAsync(Guid.Empty,default));
        var reader=new LdapDirectoryReader(ValidOptions() with { TargetReadTimeout=TimeSpan.FromSeconds(61) },new FakeTransportFactory(transport));
        await Assert.ThrowsAsync<DirectoryReadException>(()=>reader.ReadUserAsync(Guid.NewGuid(),default));
        Assert.Equal(0,transport.RootDseCalls);
    }

    private static DirectoryRawEntry Entry(Guid objectId, string objectClass = "user")
    {
        var sid = new byte[] { 1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 232, 3, 0, 0 };
        return new DirectoryRawEntry(
            "CN=Jane,OU=People,DC=example,DC=com",
            new Dictionary<string, IReadOnlyList<object>>(StringComparer.OrdinalIgnoreCase)
            {
                ["objectGUID"] = [objectId.ToByteArray()],
                ["objectClass"] = ["top", objectClass],
                ["distinguishedName"] = ["CN=Jane,OU=People,DC=example,DC=com"],
                ["name"] = ["Jane"],
                ["sAMAccountName"] = ["jane"],
                ["department"] = ["IT"],
                ["objectSid"] = [sid],
                ["uSNChanged"] = ["42"],
            });
    }

    private sealed class FakeTransportFactory(FakeTransport transport) : IDirectoryTransportFactory
    {
        public IDirectoryTransport Create(DirectoryConnectorOptions options) => transport;
    }

    private sealed class FakeTransport : IDirectoryTargetTransport
    {
        public static readonly DirectorySourceIdentity Source = new("dc01.example.com", "CN=NTDS Settings,CN=DC01,CN=Configuration,DC=example,DC=com", Guid.NewGuid(), Guid.NewGuid());
        public Queue<DirectorySourceIdentity> Sources { get; init; } = new([Source, Source]);
        public IReadOnlyList<DirectoryRawEntry> Targets { get; init; } = [];
        public int TargetCalls { get; private set; }
        public int IdentityCalls { get; private set; }
        public TimeSpan TargetDelay { get; init; }
        public Task<DirectorySourceIdentity> ReadSourceIdentityAsync(CancellationToken ct) { IdentityCalls++; return Task.FromResult(Sources.Dequeue()); }
        public async Task<IReadOnlyList<DirectoryRawEntry>> ReadUserAsync(string baseDn, Guid id, CancellationToken ct)
        { TargetCalls++; if (TargetDelay > TimeSpan.Zero) await Task.Delay(TargetDelay, ct); return Targets; }
        public RootDseResult RootDse { get; init; } = new(["DC=example,DC=com"]);

        public Guid BaseObjectId { get; init; } = DomainId;

        public Queue<object> Pages { get; init; } = new([new DirectoryPage([], [])]);

        public int PageCalls { get; private set; }

        public int RootDseCalls { get; private set; }

        public TimeSpan RootDseDelay { get; init; }

        public async Task<RootDseResult> ReadRootDseAsync(CancellationToken cancellationToken)
        {
            RootDseCalls++;
            if (RootDseDelay > TimeSpan.Zero)
            {
                await Task.Delay(RootDseDelay, cancellationToken);
            }

            return RootDse;
        }

        public Task<Guid> ReadBaseObjectIdAsync(string baseDn, CancellationToken cancellationToken) =>
            Task.FromResult(BaseObjectId);

        public Task<DirectoryPage> ReadPageAsync(
            string baseDn,
            int pageSize,
            byte[] cookie,
            CancellationToken cancellationToken)
        {
            PageCalls++;
            var result = Pages.Dequeue();
            return result is Exception exception
                ? Task.FromException<DirectoryPage>(exception)
                : Task.FromResult((DirectoryPage)result);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
