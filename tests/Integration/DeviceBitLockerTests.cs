using ItManagement.AgentProjection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class DeviceBitLockerTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db() => new(new DbContextOptionsBuilder<ConsoleDbContext>()
        .UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Options);
    private static readonly string[] Permissions = [PermissionCatalog.ComputerView, PermissionCatalog.ComputerInventory, PermissionCatalog.BitLockerStatusView];

    private async Task<(TestData Data, Guid Id)> Seed(string? missing = null, bool disjoint = false)
    {
        var data = await fixture.SeedAsync(); var id = Guid.NewGuid(); var generation = Guid.NewGuid(); var ou = Guid.NewGuid();
        await using var db = Db();
        db.DirectorySync.Add(new() { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Generation = generation, Status = "Ready", CompletedAt = DateTimeOffset.UtcNow });
        db.DirectoryObjects.Add(new() { EnvironmentId = data.Environment.Id, Id = id, Generation = generation, Kind = "Computer",
            Name = "synthetic-bitlocker-device", DistinguishedName = "CN=synthetic,DC=test", ParentOuId = ou, OuAncestry = [ou] });
        foreach (var permission in Permissions.Where(x => x != missing))
        {
            var role = new Role { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Name = permission };
            var scope = new Scope { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Kind = ScopeKind.OrganizationalUnit,
                Value = (disjoint && permission == PermissionCatalog.BitLockerStatusView ? Guid.NewGuid() : ou).ToString() };
            db.AddRange(role, scope, new RolePermission { EnvironmentId = data.Environment.Id, RoleId = role.Id, Permission = permission },
                new RoleAssignment { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), PrincipalId = data.Viewer.Id, RoleId = role.Id, ScopeId = scope.Id });
        }
        await db.SaveChangesAsync(); return (data, id);
    }

    private static string Path(Guid env, Guid id) => $"/api/v1/environments/{env}/devices/{id}/bitlocker";
    private WebApplicationFactory<Program> Factory(FakeReader fake, TimeProvider? clock = null) => fixture.Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
    {
        services.RemoveAll<IAgentBitLockerProjectionReader>(); services.AddSingleton<IAgentBitLockerProjectionReader>(fake);
        if (clock is not null) { services.RemoveAll<TimeProvider>(); services.AddSingleton(clock); }
    }));
    private static HttpClient Client(WebApplicationFactory<Program> factory, string token) => factory.CreateClient(new()
    { BaseAddress = new Uri("https://localhost:7443"), HandleCookies = false }).WithSession(token);
    private static BitLockerProjection Observed(Guid env, Guid id)
    {
        var now = DateTimeOffset.UtcNow.AddMinutes(-1);
        return new(ProjectionReadState.Observed, ProjectionDiagnostic.None, env, id, Guid.NewGuid(), Guid.NewGuid(), 1, 1, Guid.NewGuid(),
            now, now, now, now, @"root\cimv2\Security\MicrosoftVolumeEncryption:Win32_EncryptableVolume", true,
            [new("PRIVATE-DEVICE-CANARY", "PRIVATE-PERSISTENT-CANARY", "C:", 0, uint.MaxValue, 0, 7, false)]);
    }
    private sealed class FakeReader(BitLockerProjection value) : IAgentBitLockerProjectionReader
    {
        public int Calls { get; private set; }
        public Task<BitLockerProjection> ReadAsync(Guid env, Guid id, CancellationToken ct) { Calls++; return Task.FromResult(value); }
    }
    private sealed class FixedClock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)]
    public async Task Freshness_boundaries_are_inclusive_and_one_tick_beyond_is_rejected_or_stale(int field)
    {
        var (data, id) = await Seed(); var now = DateTimeOffset.UtcNow; var clock = new FixedClock(now);
        foreach (var (offset, expected) in new[] { (TimeSpan.FromHours(-24), "Current"), (TimeSpan.FromHours(-24) - TimeSpan.FromTicks(1), "Stale"),
            (TimeSpan.FromMinutes(5), "Current"), (TimeSpan.FromMinutes(5) + TimeSpan.FromTicks(1), "BitLockerUnavailable") })
        {
            var value = Observed(data.Environment.Id, id); var changed = now + offset;
            value = field switch { 0 => value with { CollectedAt = changed }, 1 => value with { SourceObservedAt = changed }, _ => value with { ReceivedAt = changed } };
            using var factory = Factory(new(value), clock); using var client = Client(factory, data.ViewerToken);
            using var response = await client.GetAsync(Path(data.Environment.Id, id));
            Assert.Equal(expected == "BitLockerUnavailable" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK, response.StatusCode);
            var json = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(expected, json.GetProperty(expected == "BitLockerUnavailable" ? "title" : "state").GetString());
        }
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public async Task Each_permission_and_intersecting_scope_is_required_before_private_read(int denied)
    {
        var (data, id) = await Seed(denied < 3 ? Permissions[denied] : null, denied == 3);
        var fake = new FakeReader(Observed(data.Environment.Id, id)); using var factory = Factory(fake); using var client = Client(factory, data.ViewerToken);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(Path(data.Environment.Id, id))).StatusCode);
        Assert.Equal(0, fake.Calls);
    }

    [Theory]
    [InlineData("object")] [InlineData("kind")] [InlineData("environment")] [InlineData("membership")] [InlineData("generation")] [InlineData("directory-stale")]
    public async Task Directory_and_membership_checks_precede_private_read(string denied)
    {
        var (data, id) = await Seed(); var env = data.Environment.Id; var fake = new FakeReader(Observed(env, id));
        await using var db = Db();
        if (denied == "object") id = Guid.NewGuid();
        if (denied == "environment") env = data.OtherEnvironment.Id;
        if (denied == "kind") (await db.DirectoryObjects.SingleAsync(x => x.EnvironmentId == env && x.Id == id)).Kind = "User";
        if (denied == "membership") (await db.Memberships.SingleAsync(x => x.EnvironmentId == env && x.PrincipalId == data.Viewer.Id)).Active = false;
        if (denied == "generation") (await db.DirectorySync.SingleAsync(x => x.EnvironmentId == env)).Generation = Guid.NewGuid();
        if (denied == "directory-stale") (await db.DirectorySync.SingleAsync(x => x.EnvironmentId == env)).CompletedAt = DateTimeOffset.UtcNow.AddHours(-1);
        await db.SaveChangesAsync(); using var factory = Factory(fake); using var client = Client(factory, data.ViewerToken);
        Assert.Equal(denied == "directory-stale" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.NotFound, (await client.GetAsync(Path(env, id))).StatusCode);
        Assert.Equal(0, fake.Calls);
    }

    [Fact]
    public async Task Current_observation_projects_only_public_fields_and_preserves_unknown_codes()
    {
        var (data, id) = await Seed(); var fake = new FakeReader(Observed(data.Environment.Id, id)); using var factory = Factory(fake); using var client = Client(factory, data.ViewerToken);
        using var response = await client.GetAsync(Path(data.Environment.Id, id)); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore); var text = await response.Content.ReadAsStringAsync(); var json = JsonDocument.Parse(text).RootElement;
        Assert.Equal("Current", json.GetProperty("state").GetString()); Assert.True(json.GetProperty("isTruncated").GetBoolean());
        var volume = json.GetProperty("volumes")[0]; Assert.Equal(uint.MaxValue, volume.GetProperty("protectionStatus").GetUInt32());
        Assert.False(volume.GetProperty("isVolumeInitializedForProtection").GetBoolean()); Assert.Equal(6, volume.EnumerateObject().Count());
        foreach (var forbidden in new[] { "PRIVATE-", "registrationId", "receiptId", "deviceId", "persistentVolumeId", "online", "recovery" })
            Assert.DoesNotContain(forbidden, text, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, fake.Calls);
    }

    [Theory]
    [InlineData(0, "old")] [InlineData(1, "old")] [InlineData(2, "old")]
    [InlineData(0, "future")] [InlineData(1, "future")] [InlineData(2, "future")]
    [InlineData(0, "missing")] [InlineData(1, "missing")] [InlineData(2, "missing")]
    public async Task Every_provenance_time_is_required_and_checked(int field, string variant)
    {
        var (data, id) = await Seed(); var value = Observed(data.Environment.Id, id);
        DateTimeOffset? changed = variant == "missing" ? null : DateTimeOffset.UtcNow.AddHours(variant == "old" ? -25 : 1);
        value = field switch { 0 => value with { CollectedAt = changed }, 1 => value with { SourceObservedAt = changed }, _ => value with { ReceivedAt = changed } };
        using var factory = Factory(new(value)); using var client = Client(factory, data.ViewerToken); using var response = await client.GetAsync(Path(data.Environment.Id, id));
        Assert.Equal(variant == "old" ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(variant == "old" ? "Stale" : "BitLockerUnavailable", json.GetProperty(variant == "old" ? "state" : "title").GetString());
    }

    [Theory]
    [InlineData("missing")] [InlineData("unavailable")] [InlineData("wrong-environment")] [InlineData("wrong-object")]
    public async Task Absent_or_mismatched_projection_cannot_expose_observation(string variant)
    {
        var (data, id) = await Seed(); var value = Observed(data.Environment.Id, id);
        value = variant switch { "missing" => value with { State = ProjectionReadState.Missing }, "unavailable" => value with { State = ProjectionReadState.Unavailable },
            "wrong-environment" => value with { EnvironmentId = Guid.NewGuid() }, _ => value with { DirectoryObjectId = Guid.NewGuid() } };
        using var factory = Factory(new(value)); using var client = Client(factory, data.ViewerToken); using var response = await client.GetAsync(Path(data.Environment.Id, id));
        Assert.Equal(variant == "missing" ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var text = await response.Content.ReadAsStringAsync(); Assert.DoesNotContain("PRIVATE-", text);
        if (variant == "missing") { var json = JsonDocument.Parse(text).RootElement; Assert.Equal("Missing", json.GetProperty("state").GetString()); Assert.Equal(0, json.GetProperty("volumes").GetArrayLength()); }
    }

    [Fact]
    public async Task No_projection_configuration_returns_unavailable_without_database_fallback()
    {
        var (data, id) = await Seed(); using var client = fixture.Client(data.ViewerToken);
        using var response = await client.GetAsync(Path(data.Environment.Id, id)); Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("BitLockerUnavailable", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
    }
}
