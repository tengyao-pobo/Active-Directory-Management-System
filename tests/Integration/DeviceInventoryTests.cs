using ItManagement.AgentProjection;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class DeviceInventoryTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db() => new(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Options);
    private async Task<(TestData Data, Guid Id)> Seed(string? missing = null, bool disjoint = false)
    {
        var data = await fixture.SeedAsync(); var id = Guid.NewGuid(); var generation = Guid.NewGuid(); var ou = Guid.NewGuid();
        await using var db = Db();
        db.DirectorySync.Add(new() { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Generation = generation, Status = "Ready", CompletedAt = DateTimeOffset.UtcNow });
        db.DirectoryObjects.Add(new() { EnvironmentId = data.Environment.Id, Id = id, Generation = generation, Kind = "Computer", Name = "inventory-synthetic",
            DistinguishedName = "CN=synthetic,DC=test", ParentOuId = ou, OuAncestry = [ou] });
        foreach (var permission in new[] { PermissionCatalog.ComputerView, PermissionCatalog.ComputerInventory }.Where(x => x != missing))
        {
            var role = new Role { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Name = permission };
            var scope = new Scope { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Kind = ScopeKind.OrganizationalUnit,
                Value = (disjoint && permission == PermissionCatalog.ComputerInventory ? Guid.NewGuid() : ou).ToString() };
            db.AddRange(role, scope, new RolePermission { EnvironmentId = data.Environment.Id, RoleId = role.Id, Permission = permission },
                new RoleAssignment { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), PrincipalId = data.Viewer.Id, RoleId = role.Id, ScopeId = scope.Id });
        }
        await db.SaveChangesAsync(); return (data, id);
    }
    private static string Path(Guid env, Guid id) => $"/api/v1/environments/{env}/devices/{id}/inventory";
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }
    private sealed class Reader(AgentInventoryProjection result) : IAgentInventoryProjectionReader
    {
        public int Calls { get; private set; }
        public Task<AgentInventoryProjection> ReadInventoryAsync(Guid env, Guid id, CancellationToken ct) { Calls++; return Task.FromResult(result); }
    }
    private WebApplicationFactory<Program> Factory(Reader reader, DateTimeOffset now) => fixture.Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
    {
        services.RemoveAll<IAgentInventoryProjectionReader>(); services.AddSingleton<IAgentInventoryProjectionReader>(reader);
        services.RemoveAll<TimeProvider>(); services.AddSingleton<TimeProvider>(new Clock(now));
    }));
    private static HttpClient Client(WebApplicationFactory<Program> factory, string token) => factory.CreateClient(new()
    { BaseAddress = new Uri("https://localhost:7443"), HandleCookies = false }).WithSession(token);

    private static AgentInventoryProjection Observation(Guid env, Guid id, DateTimeOffset now, string? changedField = null, DateTimeOffset? changed = null,
        ProjectionReadState state = ProjectionReadState.Observed, ProjectionAvailability component = ProjectionAvailability.Observed, bool invalidRow = false)
    {
        DateTimeOffset? Time(string key) => key == changedField ? changed : now.AddMinutes(-1);
        return new(state, ProjectionDiagnostic.None, env, id, Guid.NewGuid(), Guid.NewGuid(), 3, 7, Guid.NewGuid(), Time("collected"), Time("received"), now,
            new(component, ProjectionDiagnostic.None, "basic-device", Time("basic"), true, "synthetic-host", new("Windows synthetic", "10", "X64"),
                [new("Ethernet", "Ethernet", ["192.0.2.10"], ["192.0.2.1"], ["192.0.2.53"], "00:00:00:00:00:01")]),
            new(component, ProjectionDiagnostic.None, "HKLM uninstall registry (32-bit and 64-bit views)", Time("software"), false,
                [new("Synthetic software", "1", "Synthetic publisher", "20240229", "x64")]),
            new(component, ProjectionDiagnostic.None, "hardware", Time("hardware"),
                [new(ProjectedHardwareKind.System, "Win32_ComputerSystem", ProjectionAvailability.Observed, ProjectionDiagnostic.None,
                    Time("system") ?? DateTimeOffset.MinValue, false, [invalidRow ? new UnexpectedRow("RECOVERY-CANARY") : new ProjectedSystemHardwareRow("Synthetic vendor", "Synthetic model", "18446744073709551615")]),
                 new(ProjectedHardwareKind.Battery, "Win32_Battery", ProjectionAvailability.NotApplicable, ProjectionDiagnostic.None,
                    Time("battery") ?? DateTimeOffset.MinValue, false, [])]));
    }
    private sealed record UnexpectedRow(string RecoveryPassword) : ProjectedHardwareRow;

    [Fact]
    public async Task Inventory_permissions_are_sufficient_and_projection_identity_and_other_collectors_are_not_returned()
    {
        var (data, id) = await Seed(); var now = DateTimeOffset.UtcNow; var value = Observation(data.Environment.Id, id, now); var reader = new Reader(value);
        using var factory = Factory(reader, now); using var client = Client(factory, data.ViewerToken);
        using var response = await client.GetAsync(Path(data.Environment.Id, id)); Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.True(response.Headers.CacheControl?.NoStore);
        var text = await response.Content.ReadAsStringAsync(); var json = JsonDocument.Parse(text).RootElement;
        Assert.Equal("Observed", json.GetProperty("basic").GetProperty("availability").GetString());
        Assert.Equal("192.0.2.10", json.GetProperty("basic").GetProperty("data").GetProperty("networkInterfaces")[0].GetProperty("addresses")[0].GetString());
        Assert.Equal("18446744073709551615", json.GetProperty("hardware").GetProperty("sections")[0].GetProperty("rows")[0].GetProperty("TotalPhysicalMemory").GetString());
        foreach (var forbidden in new[] { value.DeviceId!.Value.ToString(), value.RegistrationId!.Value.ToString(), value.ReceiptId!.Value.ToString(), "diagnosticCode", "deviceGuid", "bitlocker", "recovery", "online", "normalized_payload" })
            Assert.DoesNotContain(forbidden, text, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(Path(data.Environment.Id, id).Replace("/inventory", "/bitlocker", StringComparison.Ordinal))).StatusCode);
        Assert.Equal(1, reader.Calls);
    }

    [Theory]
    [InlineData("view")] [InlineData("inventory")] [InlineData("scope")] [InlineData("membership")]
    [InlineData("environment")] [InlineData("id")] [InlineData("kind")] [InlineData("generation")] [InlineData("stale")]
    public async Task Authorization_and_directory_state_precede_private_reads(string denied)
    {
        var (data, id) = await Seed(denied == "view" ? PermissionCatalog.ComputerView : denied == "inventory" ? PermissionCatalog.ComputerInventory : null, denied == "scope");
        var now = DateTimeOffset.UtcNow; var env = data.Environment.Id; var reader = new Reader(Observation(env, id, now));
        await using var db = Db();
        if (denied == "membership") (await db.Memberships.SingleAsync(x => x.EnvironmentId == env && x.PrincipalId == data.Viewer.Id)).Active = false;
        if (denied == "kind") (await db.DirectoryObjects.SingleAsync(x => x.EnvironmentId == env && x.Id == id)).Kind = "User";
        if (denied == "generation") (await db.DirectorySync.SingleAsync(x => x.EnvironmentId == env)).Generation = Guid.NewGuid();
        if (denied == "stale") (await db.DirectorySync.SingleAsync(x => x.EnvironmentId == env)).CompletedAt = now.AddHours(-1);
        if (denied == "environment") env = data.OtherEnvironment.Id;
        if (denied == "id") id = Guid.NewGuid();
        await db.SaveChangesAsync(); using var factory = Factory(reader, now); using var client = Client(factory, data.ViewerToken);
        Assert.Equal(denied == "stale" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.NotFound, (await client.GetAsync(Path(env, id))).StatusCode);
        Assert.Equal(0, reader.Calls);
    }

    [Theory]
    [InlineData("collected")] [InlineData("received")]
    public async Task Shared_times_are_required_and_bound_all_sources(string field)
    {
        var (data, id) = await Seed(); var now = DateTimeOffset.UtcNow;
        foreach (var (offset, expected) in new (TimeSpan?, string)[] { (null, "Unavailable"), (TimeSpan.FromHours(-24), "Current"),
            (TimeSpan.FromHours(-24) - TimeSpan.FromTicks(1), "Stale"), (TimeSpan.FromMinutes(5), "Current"), (TimeSpan.FromMinutes(5) + TimeSpan.FromTicks(1), "Unavailable") })
        {
            using var factory = Factory(new(Observation(data.Environment.Id, id, now, field, offset is null ? null : now + offset)), now);
            using var client = Client(factory, data.ViewerToken); using var response = await client.GetAsync(Path(data.Environment.Id, id));
            Assert.Equal(expected == "Unavailable" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK, response.StatusCode);
            if (expected == "Unavailable") continue;
            var json = await response.Content.ReadFromJsonAsync<JsonElement>();
            foreach (var source in new[] { "basic", "hardware", "software" }) Assert.Equal(expected, json.GetProperty(source).GetProperty("freshness").GetString());
            Assert.Equal(expected, json.GetProperty("hardware").GetProperty("sections")[1].GetProperty("freshness").GetString());
            Assert.Equal("NotApplicable", json.GetProperty("hardware").GetProperty("sections")[1].GetProperty("availability").GetString());
        }
    }

    [Theory]
    [InlineData("basic")] [InlineData("hardware")] [InlineData("software")]
    public async Task Collector_times_do_not_poison_other_sources(string field)
    {
        var (data, id) = await Seed(); var now = DateTimeOffset.UtcNow;
        foreach (var (offset, expected) in new (TimeSpan?, string)[] { (null, "Unavailable"), (TimeSpan.FromHours(-24), "Current"),
            (TimeSpan.FromHours(-24) - TimeSpan.FromTicks(1), "Stale"), (TimeSpan.FromMinutes(5), "Current"), (TimeSpan.FromMinutes(5) + TimeSpan.FromTicks(1), "Unavailable") })
        {
            using var factory = Factory(new(Observation(data.Environment.Id, id, now, field, offset is null ? null : now + offset)), now);
            using var client = Client(factory, data.ViewerToken); var json = await client.GetFromJsonAsync<JsonElement>(Path(data.Environment.Id, id));
            var changed = json.GetProperty(field);
            Assert.Equal(expected == "Unavailable" ? "Unavailable" : "Observed", changed.GetProperty("availability").GetString());
            Assert.Equal(expected == "Unavailable" ? null : expected, changed.GetProperty("freshness").GetString());
            foreach (var other in new[] { "basic", "hardware", "software" }.Where(x => x != field)) Assert.Equal("Current", json.GetProperty(other).GetProperty("freshness").GetString());
            if (expected == "Unavailable")
            {
                if (field == "basic") Assert.Equal(JsonValueKind.Null, changed.GetProperty("data").ValueKind);
                else Assert.Equal(0, changed.GetProperty(field == "hardware" ? "sections" : "applications").GetArrayLength());
            }
        }
    }

    [Theory]
    [InlineData("system")] [InlineData("battery")]
    public async Task Individual_hardware_time_keeps_availability_and_freshness_separate(string field)
    {
        var (data, id) = await Seed(); var now = DateTimeOffset.UtcNow;
        foreach (var (offset, expected) in new[] { (TimeSpan.FromHours(-24), "Current"), (TimeSpan.FromHours(-24) - TimeSpan.FromTicks(1), "Stale"),
            (TimeSpan.FromMinutes(5), "Current"), (TimeSpan.FromMinutes(5) + TimeSpan.FromTicks(1), "Unavailable") })
        {
            using var factory = Factory(new(Observation(data.Environment.Id, id, now, field, now + offset)), now); using var client = Client(factory, data.ViewerToken);
            var json = await client.GetFromJsonAsync<JsonElement>(Path(data.Environment.Id, id)); var hardware = json.GetProperty("hardware"); var index = field == "system" ? 0 : 1;
            Assert.Equal("Current", hardware.GetProperty("freshness").GetString());
            Assert.Equal(expected == "Unavailable" ? "Unavailable" : field == "battery" ? "NotApplicable" : "Observed", hardware.GetProperty("sections")[index].GetProperty("availability").GetString());
            Assert.Equal(expected == "Unavailable" ? null : expected, hardware.GetProperty("sections")[index].GetProperty("freshness").GetString());
            Assert.Equal("Current", hardware.GetProperty("sections")[1 - index].GetProperty("freshness").GetString());
        }
    }

    [Theory]
    [InlineData(ProjectionReadState.Missing)] [InlineData(ProjectionReadState.Unavailable)]
    public async Task Whole_missing_or_unavailable_projection_discards_retained_values(ProjectionReadState state)
    {
        var (data, id) = await Seed(); var now = DateTimeOffset.UtcNow;
        using var factory = Factory(new(Observation(data.Environment.Id, id, now, state: state)), now); using var client = Client(factory, data.ViewerToken);
        using var response = await client.GetAsync(Path(data.Environment.Id, id));
        Assert.Equal(state == ProjectionReadState.Missing ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var text = await response.Content.ReadAsStringAsync(); Assert.DoesNotContain("synthetic-host", text); Assert.DoesNotContain("Synthetic model", text);
        if (state == ProjectionReadState.Missing)
        {
            var json = JsonDocument.Parse(text).RootElement;
            foreach (var source in new[] { "basic", "hardware", "software" }) Assert.Equal("Missing", json.GetProperty(source).GetProperty("availability").GetString());
        }
    }

    [Fact]
    public async Task Unexpected_hardware_row_is_not_serialized_and_other_sources_remain_available()
    {
        var (data, id) = await Seed(); var now = DateTimeOffset.UtcNow;
        using var factory = Factory(new(Observation(data.Environment.Id, id, now, invalidRow: true)), now); using var client = Client(factory, data.ViewerToken);
        var json = await client.GetFromJsonAsync<JsonElement>(Path(data.Environment.Id, id)); Assert.DoesNotContain("RECOVERY-CANARY", json.GetRawText());
        Assert.Equal("Unavailable", json.GetProperty("hardware").GetProperty("sections")[0].GetProperty("availability").GetString());
        Assert.Equal("Observed", json.GetProperty("basic").GetProperty("availability").GetString());
    }

    [Fact]
    public async Task Unconfigured_projection_has_no_database_fallback()
    {
        var (data, id) = await Seed(); using var client = fixture.Client(data.ViewerToken);
        using var response = await client.GetAsync(Path(data.Environment.Id, id)); Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("InventoryUnavailable", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
    }

    [Theory]
    [InlineData(ProjectionAvailability.Missing)] [InlineData(ProjectionAvailability.Unavailable)] [InlineData(ProjectionAvailability.NotApplicable)]
    public async Task Non_observed_containers_never_emit_retained_values(ProjectionAvailability availability)
    {
        var (data, id) = await Seed(); var now = DateTimeOffset.UtcNow;
        using var factory = Factory(new(Observation(data.Environment.Id, id, now, component: availability)), now); using var client = Client(factory, data.ViewerToken);
        var json = await client.GetFromJsonAsync<JsonElement>(Path(data.Environment.Id, id));
        Assert.DoesNotContain("synthetic-host", json.GetRawText()); Assert.DoesNotContain("Synthetic software", json.GetRawText()); Assert.DoesNotContain("Synthetic model", json.GetRawText());
        foreach (var source in new[] { "basic", "hardware", "software" })
            Assert.Equal(availability == ProjectionAvailability.Missing ? "Missing" : "Unavailable", json.GetProperty(source).GetProperty("availability").GetString());
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task Mismatched_private_identity_is_unavailable(bool environmentMismatch)
    {
        var (data, id) = await Seed(); var now = DateTimeOffset.UtcNow;
        using var factory = Factory(new(Observation(environmentMismatch ? Guid.NewGuid() : data.Environment.Id, environmentMismatch ? id : Guid.NewGuid(), now)), now);
        using var client = Client(factory, data.ViewerToken); using var response = await client.GetAsync(Path(data.Environment.Id, id));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode); Assert.DoesNotContain("synthetic-host", await response.Content.ReadAsStringAsync());
    }
}
