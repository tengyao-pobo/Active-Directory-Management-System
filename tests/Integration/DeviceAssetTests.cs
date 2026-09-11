namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class DeviceAssetTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db(bool runtime = false) => new(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(Environment.GetEnvironmentVariable(runtime ? "CONSOLE_TEST_RUNTIME_DB" : "CONSOLE_TEST_DB")!).Options);
    private async Task<(TestData Data, Guid Id, Guid Ou)> Seed(bool edit = true)
    {
        var data = await fixture.SeedAsync(); var id = Guid.NewGuid(); var ou = Guid.NewGuid(); var generation = Guid.NewGuid();
        await using var db = Db();
        db.DirectorySync.Add(new() { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Generation = generation, Status = "Ready", CompletedAt = DateTimeOffset.UtcNow });
        db.DirectoryObjects.Add(new() { EnvironmentId = data.Environment.Id, Id = id, Generation = generation, Kind = "Computer", Name = "synthetic-device", DistinguishedName = "CN=synthetic-device,DC=test", ParentOuId = ou, OuAncestry = [ou], ProtectionKnown = false });
        var role = new Role { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Name = "asset-test" };
        var scope = new Scope { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Kind = ScopeKind.OrganizationalUnit, Value = ou.ToString() };
        db.AddRange(role, scope, new RoleAssignment { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), PrincipalId = data.Viewer.Id, RoleId = role.Id, ScopeId = scope.Id }, new RolePermission { EnvironmentId = data.Environment.Id, RoleId = role.Id, Permission = PermissionCatalog.ComputerView });
        if (edit) db.RolePermissions.Add(new() { EnvironmentId = data.Environment.Id, RoleId = role.Id, Permission = PermissionCatalog.AssetEdit });
        await db.SaveChangesAsync(); return (data, id, ou);
    }
    private static string Path(TestData data, Guid id) => $"/api/v1/environments/{data.Environment.Id}/devices/{id}/asset";
    private static async Task<HttpResponseMessage> Put(HttpClient client, string path, string? version = "0", string notes = "private-note-canary", string lifecycle = "Active")
    {
        using var request = await client.MutationAsync(HttpMethod.Put, path, new { lifecycle, notes });
        if (version is not null) request.Headers.TryAddWithoutValidation("If-Match", $"\"{version}\"");
        return await client.SendAsync(request);
    }
    [Fact]
    public async Task Metadata_persists_with_version_and_atomic_body_free_audit()
    {
        var (data,id,_) = await Seed(); using var client = fixture.Client(data.ViewerToken); var path = Path(data,id);
        Assert.Null((await client.GetFromJsonAsync<JsonElement>(path)).GetProperty("item").GetString());
        Assert.Equal(HttpStatusCode.OK, (await Put(client,path)).StatusCode);
        Assert.Equal(HttpStatusCode.PreconditionFailed, (await Put(client,path)).StatusCode);
        Assert.Equal((HttpStatusCode)428, (await Put(client,path,null)).StatusCode);
        var result = await client.GetFromJsonAsync<JsonElement>(path);
        Assert.Equal(1, result.GetProperty("item").GetProperty("version").GetInt64());
        Assert.False(result.GetProperty("item").TryGetProperty("updatedBy", out _));
        await using var db = Db(); var audits = await db.Audit.Where(x => x.EnvironmentId == data.Environment.Id && x.Action == "Device.AssetUpdated").ToListAsync();
        Assert.Single(audits); Assert.DoesNotContain("private-note-canary", JsonSerializer.Serialize(audits));
        Assert.Equal("private-note-canary", (await db.DeviceAssets.SingleAsync(x => x.Id == id)).Notes);
    }
    [Theory]
    [InlineData("ReplacementPlanned")]
    [InlineData("Disposed")]
    [InlineData("Lost")]
    public async Task Additional_lifecycle_states_roundtrip_and_appear_in_dashboard(string lifecycle)
    {
        var (data, id, _) = await Seed(); using var client = fixture.Client(data.ViewerToken);
        Assert.Equal(HttpStatusCode.OK, (await Put(client, Path(data, id), lifecycle: lifecycle)).StatusCode);
        var asset = await client.GetFromJsonAsync<JsonElement>(Path(data, id));
        Assert.Equal(lifecycle, asset.GetProperty("item").GetProperty("lifecycle").GetString());
        var summary = await client.GetFromJsonAsync<JsonElement>($"/api/v1/environments/{data.Environment.Id}/dashboard");
        Assert.Equal(1, summary.GetProperty("lifecycle").GetProperty(lifecycle).GetInt32());
        await using var db = Db();
        Assert.Single(await db.Audit.Where(x => x.EnvironmentId == data.Environment.Id && x.Action == "Device.AssetUpdated").ToListAsync());
        Assert.True(await db.DirectoryObjects.AnyAsync(x => x.EnvironmentId == data.Environment.Id && x.Id == id));
    }
    [Fact]
    public async Task View_only_and_foreign_scope_cannot_write_and_revocation_is_rechecked()
    {
        var (data,id,_) = await Seed(false); using var client = fixture.Client(data.ViewerToken); var path = Path(data,id);
        Assert.False((await client.GetFromJsonAsync<JsonElement>(path)).GetProperty("canEdit").GetBoolean());
        Assert.Equal(HttpStatusCode.Forbidden, (await Put(client,path)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(Path(data,Guid.NewGuid()))).StatusCode);
        await using var db = Db(); var row = await db.DirectoryObjects.SingleAsync(x => x.Id == id); row.ParentOuId = Guid.NewGuid(); row.OuAncestry = []; await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Put(client,path)).StatusCode);
    }
    [Fact]
    public async Task Invalid_input_csrf_and_protected_objects_do_not_change_metadata()
    {
        var (data,id,_) = await Seed(); using var client = fixture.Client(data.ViewerToken); var path = Path(data,id);
        Assert.Equal(HttpStatusCode.BadRequest, (await Put(client,path,notes:new string('x',4001))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Put(client,path,lifecycle:"DeleteAD")).StatusCode);
        using var missing = new HttpRequestMessage(HttpMethod.Put,path) { Content = JsonContent.Create(new { lifecycle="Active",notes="bad" }) }; missing.Headers.Add("Origin","https://localhost:7443");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(missing)).StatusCode);
        await using var db = Db(); var row = await db.DirectoryObjects.SingleAsync(x => x.Id == id); row.IsProtected = true; await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.Forbidden, (await Put(client,path)).StatusCode);
        Assert.False(await db.DeviceAssets.AnyAsync(x => x.Id == id));
    }
    [Fact]
    public async Task Runtime_rls_hides_assets_without_context_and_in_foreign_environment()
    {
        var (data,id,_) = await Seed(); using var client = fixture.Client(data.ViewerToken); Assert.Equal(HttpStatusCode.OK,(await Put(client,Path(data,id))).StatusCode);
        await using var db = Db(true); Assert.Empty(await db.DeviceAssets.ToListAsync());
        await using var tx = await db.BeginEnvironment(data.OtherEnvironment.Id,data.Viewer.Id,CancellationToken.None);
        Assert.Empty(await db.DeviceAssets.ToListAsync());
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Concurrent_saves_have_one_winner_and_one_audit(bool existing)
    {
        var (data,id,_) = await Seed(); using var a = fixture.Client(data.ViewerToken); using var b = fixture.Client(data.ViewerToken); var path = Path(data,id);
        if (existing) Assert.Equal(HttpStatusCode.OK,(await Put(a,path)).StatusCode);
        var results = await Task.WhenAll(Put(a,path,existing ? "1" : "0", "a"), Put(b,path,existing ? "1" : "0", "b"));
        Assert.Single(results, r => r.StatusCode == HttpStatusCode.OK);
        Assert.Single(results, r => r.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.PreconditionFailed);
        await using var db = Db(); Assert.Equal(existing ? 2 : 1, await db.Audit.CountAsync(x => x.EnvironmentId == data.Environment.Id && x.Action == "Device.AssetUpdated"));
    }    [Fact]
    public async Task Edit_grant_requires_view_and_matching_scope_and_active_membership()
    {
        var (data,id,_) = await Seed(); using var client = fixture.Client(data.ViewerToken); var path = Path(data,id);
        await using var db = Db();
        var grant = await db.RolePermissions.SingleAsync(x => x.EnvironmentId == data.Environment.Id && x.Permission == PermissionCatalog.ComputerView);
        db.RolePermissions.Remove(grant); await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.NotFound,(await Put(client,path)).StatusCode);
        db.RolePermissions.Add(grant); await db.SaveChangesAsync();
        var member = await db.Memberships.SingleAsync(x => x.EnvironmentId == data.Environment.Id && x.PrincipalId == data.Viewer.Id); member.Active = false; await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.NotFound,(await Put(client,path)).StatusCode);
        Assert.False(await db.DeviceAssets.AnyAsync(x => x.Id == id));
    }
    [Fact]
    public async Task Stale_wrong_kind_and_missing_computer_hide_persisted_metadata()
    {
        var (data,id,_) = await Seed(); using var client = fixture.Client(data.ViewerToken); var path = Path(data,id);
        Assert.Equal(HttpStatusCode.OK,(await Put(client,path)).StatusCode);
        await using var db = Db(); var sync = await db.DirectorySync.SingleAsync(x => x.EnvironmentId == data.Environment.Id); sync.CompletedAt = DateTimeOffset.UtcNow.AddMinutes(-20); await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.ServiceUnavailable,(await Put(client,path,"1")).StatusCode);
        sync.CompletedAt = DateTimeOffset.UtcNow; var row = await db.DirectoryObjects.SingleAsync(x => x.Id == id); row.Kind = "User"; await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.NotFound,(await client.GetAsync(path)).StatusCode);
        db.DirectoryObjects.Remove(row); await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.NotFound,(await client.GetAsync(path)).StatusCode);
        Assert.True(await db.DeviceAssets.AnyAsync(x => x.Id == id));
    }}
