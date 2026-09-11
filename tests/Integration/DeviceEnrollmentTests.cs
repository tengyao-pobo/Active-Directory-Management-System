using ItManagement.AgentEnrollmentTargets;
using ItManagement.Api;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class DeviceEnrollmentTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db() => new(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Options);
    private async Task<(TestData Data, Guid Id)> Seed(string? denied = null)
    {
        var data = await fixture.SeedAsync(); var id = Guid.NewGuid(); var generation = Guid.NewGuid(); var ou = Guid.NewGuid();
        await using var db = Db();
        db.DirectorySync.Add(new() { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Generation = generation, Status = "Ready", CompletedAt = DateTimeOffset.UtcNow });
        db.DirectoryObjects.Add(new() { EnvironmentId = data.Environment.Id, Id = id, Generation = generation, Kind = "Computer", Name = "enrollment-synthetic",
            DistinguishedName = "CN=synthetic,DC=test", ParentOuId = ou, OuAncestry = [ou] });
        foreach (var permission in new[] { PermissionCatalog.ComputerView, PermissionCatalog.AgentEnrollmentGrantManage })
        {
            if (denied == "view" && permission == PermissionCatalog.ComputerView || denied == "manage" && permission == PermissionCatalog.AgentEnrollmentGrantManage) continue;
            var role = new Role { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Name = permission == PermissionCatalog.AgentEnrollmentGrantManage ? "Owner" : "Computer reader",
                BuiltInKind = denied == "custom-owner" ? null : BuiltInRoleKinds.Owner };
            var scope = new Scope { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Kind = ScopeKind.OrganizationalUnit,
                Value = (denied == "disjoint" && permission == PermissionCatalog.AgentEnrollmentGrantManage ? Guid.NewGuid() : ou).ToString() };
            db.AddRange(role, scope, new RolePermission { EnvironmentId = data.Environment.Id, RoleId = role.Id, Permission = permission },
                new RoleAssignment { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), PrincipalId = data.Requester.Id, RoleId = role.Id, ScopeId = scope.Id });
        }
        await db.SaveChangesAsync(); return (data, id);
    }

    private static string Path(Guid env, Guid id) => $"/api/v1/environments/{env}/devices/{id}/enrollment-target";
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }
    private sealed class Reader(EnrollmentTargetResult result) : IEnrollmentTargetReader
    {
        public int Calls { get; private set; }
        public Task<EnrollmentTargetResult> ReadAsync(Guid env, Guid id, CancellationToken ct) { Calls++; return Task.FromResult(result); }
    }
    private WebApplicationFactory<Program> Factory(Reader reader, DateTimeOffset now) => fixture.Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
    {
        services.RemoveAll<IEnrollmentTargetReader>(); services.AddSingleton<IEnrollmentTargetReader>(reader);
        services.RemoveAll<TimeProvider>(); services.AddSingleton<TimeProvider>(new Clock(now));
    }));
    private static HttpClient Client(WebApplicationFactory<Program> factory, string token) => factory.CreateClient(new()
    { BaseAddress = new Uri("https://localhost:7443"), HandleCookies = false }).WithSession(token);
    private static DateTimeOffset Canonical(DateTimeOffset value) => new(value.UtcTicks - value.UtcTicks % 10, TimeSpan.Zero);

    [Theory]
    [InlineData("resolved", "Eligible")]
    [InlineData("missing", "MappingRequired")]
    [InlineData("inactive", "MappingRequired")]
    public async Task ReadinessReturnsOnlyPresentationStateWithNoPrivateTuple(string kind, string expected)
    {
        var (data, id) = await Seed(); var now = DateTimeOffset.UtcNow; var device = Guid.NewGuid();
        var result = kind == "resolved" ? EnrollmentTargetResult.Resolved(data.Environment.Id, id, device, Canonical(now.AddMinutes(-1))) :
            EnrollmentTargetResult.MappingRequired(data.Environment.Id, id, kind == "missing" ? EnrollmentTargetDiagnostic.MappingMissing : EnrollmentTargetDiagnostic.DeviceInactive);
        var reader = new Reader(result); using var factory = Factory(reader, now); using var client = Client(factory, data.RequesterToken);
        using var response = await client.GetAsync(Path(data.Environment.Id, id));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.True(response.Headers.CacheControl?.NoStore);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["queriedAt", "status"], json.EnumerateObject().Select(p => p.Name).Order().ToArray());
        Assert.Equal(expected, json.GetProperty("status").GetString());
        Assert.Equal(now, json.GetProperty("queriedAt").GetDateTimeOffset());
        Assert.Equal(TimeSpan.Zero, json.GetProperty("queriedAt").GetDateTimeOffset().Offset);
        Assert.DoesNotContain(device.ToString(), json.GetRawText()); Assert.Equal(1, reader.Calls);
    }

    [Theory]
    [InlineData("view")] [InlineData("manage")] [InlineData("custom-owner")] [InlineData("disjoint")]
    [InlineData("membership")] [InlineData("environment")] [InlineData("id")] [InlineData("kind")]
    [InlineData("generation")] [InlineData("stale")] [InlineData("future")] [InlineData("sync-failed")]
    public async Task CurrentMembershipObjectAndBothScopesPrecedeEveryPrivateRead(string denied)
    {
        var (data, id) = await Seed(denied); var env = data.Environment.Id; var now = DateTimeOffset.UtcNow;
        var reader = new Reader(EnrollmentTargetResult.Resolved(env, id, Guid.NewGuid(), Canonical(now.AddMinutes(-1))));
        await using var db = Db();
        if (denied == "membership") (await db.Memberships.SingleAsync(x => x.EnvironmentId == env && x.PrincipalId == data.Requester.Id)).Active = false;
        if (denied == "kind") (await db.DirectoryObjects.SingleAsync(x => x.EnvironmentId == env && x.Id == id)).Kind = "User";
        var state = await db.DirectorySync.SingleAsync(x => x.EnvironmentId == env);
        if (denied == "generation") state.Generation = Guid.NewGuid();
        if (denied == "stale") state.CompletedAt = now.AddMinutes(-16);
        if (denied == "future") state.CompletedAt = now.AddMinutes(1);
        if (denied == "sync-failed") state.Status = "Failed";
        if (denied == "environment") env = data.OtherEnvironment.Id;
        if (denied == "id") id = Guid.NewGuid();
        await db.SaveChangesAsync(); using var factory = Factory(reader, now); using var client = Client(factory, data.RequesterToken);
        using var response = await client.GetAsync(Path(env, id));
        Assert.Equal(denied is "stale" or "future" or "sync-failed" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(0, reader.Calls);
    }

    [Theory]
    [InlineData("environment")] [InlineData("directory")] [InlineData("empty-device")] [InlineData("future-mapping")]
    [InlineData("offset")] [InlineData("precision")] [InlineData("diagnostic")] [InlineData("unavailable")]
    public async Task InvalidOrUnavailablePrivateResultsNeverBecomeEligible(string fault)
    {
        var (data, id) = await Seed(); var now = DateTimeOffset.UtcNow; var mappedAt = Canonical(now.AddMinutes(-1));
        if (fault == "future-mapping") mappedAt = Canonical(now.AddMinutes(1));
        if (fault == "offset") mappedAt = mappedAt.ToOffset(TimeSpan.FromHours(1));
        if (fault == "precision") mappedAt = mappedAt.AddTicks(1);
        var result = fault == "diagnostic" ? EnrollmentTargetResult.MappingRequired(data.Environment.Id, id, EnrollmentTargetDiagnostic.None) :
            fault == "unavailable" ? EnrollmentTargetResult.Unavailable(data.Environment.Id, id, EnrollmentTargetDiagnostic.PrivilegeAuditFailed) :
            EnrollmentTargetResult.Resolved(fault == "environment" ? Guid.NewGuid() : data.Environment.Id, fault == "directory" ? Guid.NewGuid() : id,
                fault == "empty-device" ? Guid.Empty : Guid.NewGuid(), mappedAt);
        using var factory = Factory(new Reader(result), now); using var client = Client(factory, data.RequesterToken);
        using var response = await client.GetAsync(Path(data.Environment.Id, id));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.DoesNotContain("deviceId", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task UnconfiguredPoolIsUnavailableWithoutCreatingAnyPlatformOperation()
    {
        var (data, id) = await Seed(); using var client = Client(fixture.Factory, data.RequesterToken);
        using var response = await client.GetAsync(Path(data.Environment.Id, id));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        await using var db = Db();
        Assert.False(await db.Plans.AnyAsync(x => x.EnvironmentId == data.Environment.Id));
    }

    [Fact]
    public async Task PermissionMigrationBackfillsOnlyBuiltInOwnersAndCanBeRolledBack()
    {
        var data = await fixture.SeedAsync(); await using var db = Db();
        await using var transaction = await db.Database.BeginTransactionAsync();
        var custom = new Role { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Name = "Owner", BuiltInKind = null };
        db.Roles.Add(custom); await db.SaveChangesAsync();
        var migration = new ItManagement.Persistence.Migrations.EnrollmentGrantPermission();
        foreach (var operation in migration.UpOperations.Cast<Microsoft.EntityFrameworkCore.Migrations.Operations.SqlOperation>())
            await db.Database.ExecuteSqlRawAsync(operation.Sql);
        Assert.True(await db.RolePermissions.AnyAsync(x => x.EnvironmentId == data.Environment.Id && x.RoleId == data.RequesterRoleId && x.Permission == PermissionCatalog.AgentEnrollmentGrantManage));
        Assert.False(await db.RolePermissions.AnyAsync(x => x.EnvironmentId == data.Environment.Id && x.RoleId == custom.Id && x.Permission == PermissionCatalog.AgentEnrollmentGrantManage));
        foreach (var operation in migration.DownOperations.Cast<Microsoft.EntityFrameworkCore.Migrations.Operations.SqlOperation>())
            await db.Database.ExecuteSqlRawAsync(operation.Sql);
        Assert.False(await db.RolePermissions.AnyAsync(x => x.EnvironmentId == data.Environment.Id && x.Permission == PermissionCatalog.AgentEnrollmentGrantManage));
        await transaction.RollbackAsync();
    }

    [Theory]
    [InlineData(-9000000000L, true)]
    [InlineData(-9000000010L, false)]
    [InlineData(10L, false)]
    public async Task DirectoryFreshnessUsesAnInclusiveFifteenMinuteBoundAndRejectsFutureTime(long offsetTicks, bool allowed)
    {
        var (data, id) = await Seed(); var now = Canonical(DateTimeOffset.UtcNow);
        await using var db = Db();
        (await db.DirectorySync.SingleAsync(x => x.EnvironmentId == data.Environment.Id)).CompletedAt = now.AddTicks(offsetTicks);
        await db.SaveChangesAsync();
        var reader = new Reader(EnrollmentTargetResult.Resolved(data.Environment.Id, id, Guid.NewGuid(), now.AddMinutes(-1)));
        using var factory = Factory(reader, now); using var client = Client(factory, data.RequesterToken);
        using var response = await client.GetAsync(Path(data.Environment.Id, id));
        Assert.Equal(allowed ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(allowed ? 1 : 0, reader.Calls);
    }
}
