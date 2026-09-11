namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class DeviceTagTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db(bool runtime = false) => new(new DbContextOptionsBuilder<ConsoleDbContext>()
        .UseNpgsql(Environment.GetEnvironmentVariable(runtime ? "CONSOLE_TEST_RUNTIME_DB" : "CONSOLE_TEST_DB")!).Options);
    private static string Root(TestData d) => $"/api/v1/environments/{d.Environment.Id}";
    private async Task<(TestData Data, Guid Device, DeviceTag Tag)> Seed()
    {
        var d = await fixture.SeedAsync(); var generation = Guid.NewGuid(); var device = Guid.NewGuid(); var now = DateTimeOffset.UtcNow;
        await using var db = Db();
        db.RolePermissions.Add(new() { EnvironmentId = d.Environment.Id, RoleId = d.RequesterRoleId, Permission = PermissionCatalog.DeviceTagManage });
        db.RolePermissions.Add(new() { EnvironmentId = d.Environment.Id, RoleId = d.RequesterRoleId, Permission = PermissionCatalog.ComputerView });
        db.DirectorySync.Add(new() { EnvironmentId = d.Environment.Id, Id = Guid.NewGuid(), Generation = generation, Status = "Ready", CompletedAt = now });
        db.DirectoryObjects.Add(new() { EnvironmentId = d.Environment.Id, Id = device, Generation = generation, Kind = "Computer", Name = "synthetic-tag-device", DistinguishedName = "CN=synthetic,DC=test" });
        var tag = new DeviceTag { EnvironmentId = d.Environment.Id, Id = Guid.NewGuid(), Key = "VIP", CreatedBy = d.Requester.Id, UpdatedBy = d.Requester.Id, CreatedAt = now, UpdatedAt = now };
        db.DeviceTags.Add(tag); await db.SaveChangesAsync(); return (d, device, tag);
    }
    private static async Task<HttpResponseMessage> Post(HttpClient client, string path, object body)
    {
        using var request = await client.MutationAsync(HttpMethod.Post, path, body);
        return await client.SendAsync(request);
    }
    private async Task<JsonElement> Propose(TestData d, object change, long version = 1)
    {
        using var owner = fixture.Client(d.RequesterToken);
        var response = await Post(owner, Root(d) + "/change-plans", new { change, expectedVersion = version, reason = "Synthetic tag test" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }
    private async Task<HttpResponseMessage> ApproveExecute(TestData d, JsonElement plan)
    {
        var path = Root(d) + "/change-plans/" + plan.GetProperty("id").GetGuid();
        using var reviewer = fixture.Client(d.ReviewerToken);
        Assert.Equal(HttpStatusCode.OK, (await Post(reviewer, path + "/approval", new { planHash = plan.GetProperty("planHash").GetString() })).StatusCode);
        using var owner = fixture.Client(d.RequesterToken);
        return await Post(owner, path + "/execution", new { });
    }
    [Fact]
    public async Task Creation_uses_server_identity_and_commits_actor_version_audit_and_outbox_together()
    {
        var (d, _, _) = await Seed(); var supplied = Guid.NewGuid();
        var plan = await Propose(d, new { kind = "device-tag.create", tagKey = "Finance", tagId = supplied });
        var tagId = plan.GetProperty("change").GetProperty("tagId").GetGuid(); Assert.NotEqual(supplied, tagId);
        Assert.Equal(HttpStatusCode.OK, (await ApproveExecute(d, plan)).StatusCode);
        await using var db = Db(); var tag = await db.DeviceTags.SingleAsync(t => t.EnvironmentId == d.Environment.Id && t.Id == tagId);
        Assert.Equal("Finance", tag.Key); Assert.Equal(d.Requester.Id, tag.CreatedBy); Assert.Equal(d.Requester.Id, tag.UpdatedBy);
        Assert.Equal(2, (await db.Environments.SingleAsync(e => e.Id == d.Environment.Id)).Version);
        Assert.Single(await db.Outbox.Where(o => o.EnvironmentId == d.Environment.Id).ToListAsync());
        var audit = await db.Audit.SingleAsync(a => a.EnvironmentId == d.Environment.Id && a.Action == "ChangePlan.Executed");
        Assert.Equal(d.Requester.Id, audit.ActorId);
    }
    [Theory]
    [InlineData("Asset.Edit", "Admin", false)]
    [InlineData("DeviceTag.Manage", "Admin", false)]
    [InlineData("DeviceTag.Manage", "Owner", true)]
    public async Task Asset_admin_and_tag_scoped_owner_cannot_manage(string permission, string kind, bool scoped)
    {
        var (d, _, tag) = await Seed(); await using var db = Db();
        await db.RolePermissions.Where(p => p.EnvironmentId == d.Environment.Id && p.RoleId == d.RequesterRoleId).ExecuteDeleteAsync();
        var role = new Role { EnvironmentId = d.Environment.Id, Id = Guid.NewGuid(), Name = "bounded-test-role", BuiltInKind = kind };
        db.Roles.Add(role);
        db.Assignments.Add(new() { EnvironmentId = d.Environment.Id, Id = Guid.NewGuid(), PrincipalId = d.Requester.Id, RoleId = role.Id, ScopeId = d.AllScopeId });
        db.RolePermissions.Add(new() { EnvironmentId = d.Environment.Id, RoleId = role.Id, Permission = permission });
        if (scoped) { var scope = await db.Scopes.SingleAsync(s => s.Id == d.AllScopeId); scope.Kind = ScopeKind.DeviceTag; scope.Value = tag.Id.ToString(); }
        await db.SaveChangesAsync(); using var owner = fixture.Client(d.RequesterToken);
        Assert.Equal(HttpStatusCode.NotFound, (await Post(owner, Root(d) + "/change-plans", new { change = new { kind = "device-tag.create", tagKey = "Finance" }, expectedVersion = 1, reason = "Synthetic test" })).StatusCode);
    }
    [Fact]
    public async Task Self_approval_missing_stepup_and_execution_permission_revocation_fail_closed()
    {
        var (d, device, tag) = await Seed(); var plan = await Propose(d, new { kind = "device-tag.assign", tagId = tag.Id, objectId = device, expectedTagVersion = 1 });
        using var owner = fixture.Client(d.RequesterToken); var path = Root(d) + "/change-plans/" + plan.GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.Conflict, (await Post(owner, path + "/approval", new { planHash = plan.GetProperty("planHash").GetString() })).StatusCode);
        using var reviewer = fixture.Client(d.ReviewerToken);
        Assert.Equal(HttpStatusCode.OK, (await Post(reviewer, path + "/approval", new { planHash = plan.GetProperty("planHash").GetString() })).StatusCode);
        await using var db = Db(); await db.RolePermissions.Where(p => p.EnvironmentId == d.Environment.Id && p.Permission == PermissionCatalog.DeviceTagManage).ExecuteDeleteAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await Post(owner, path + "/execution", new { })).StatusCode);
        Assert.Empty(await db.DeviceTagAssignments.Where(a => a.EnvironmentId == d.Environment.Id).ToListAsync());
        await db.Sessions.Where(s => s.PrincipalId == d.Requester.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.StepUpAt, (DateTimeOffset?)null));
        Assert.Equal(HttpStatusCode.Forbidden, (await Post(owner, path + "/execution", new { })).StatusCode);
    }
    [Theory]
    [InlineData("environment")]
    [InlineData("tag")]
    [InlineData("presence")]
    [InlineData("directory")]
    public async Task Execution_rechecks_all_relevant_state(string drift)
    {
        var (d, device, tag) = await Seed(); var plan = await Propose(d, new { kind = "device-tag.assign", tagId = tag.Id, objectId = device, expectedTagVersion = 1 });
        await using var db = Db();
        if (drift == "environment") await fixture.BumpEnvironmentVersionAsync(d.Environment.Id);
        if (drift == "tag") await db.DeviceTags.Where(t => t.Id == tag.Id).ExecuteUpdateAsync(t => t.SetProperty(x => x.Version, 2));
        if (drift == "presence") { db.DeviceTagAssignments.Add(new() { EnvironmentId = d.Environment.Id, TagId = tag.Id, ObjectId = device, CreatedBy = d.Requester.Id, CreatedAt = DateTimeOffset.UtcNow }); await db.SaveChangesAsync(); }
        if (drift == "directory") await db.DirectoryObjects.Where(t => t.Id == device).ExecuteDeleteAsync();
        Assert.Equal(HttpStatusCode.Conflict, (await ApproveExecute(d, plan)).StatusCode);
        Assert.Empty(await db.Outbox.Where(o => o.EnvironmentId == d.Environment.Id).ToListAsync());
    }
    [Theory]
    [InlineData("name")]
    [InlineData("missing")]
    [InlineData("archived")]
    [InlineData("descendants")]
    [InlineData("foreign")]
    public async Task Device_tag_scope_requires_same_environment_active_canonical_id(string invalid)
    {
        var (d, _, tag) = await Seed(); await using var db = Db();
        if (invalid == "archived") await db.DeviceTags.Where(t => t.Id == tag.Id).ExecuteUpdateAsync(t => t.SetProperty(x => x.ArchivedAt, DateTimeOffset.UtcNow));
        if (invalid == "foreign") { db.DeviceTags.Add(new() { EnvironmentId = d.OtherEnvironment.Id, Id = Guid.NewGuid(), Key = "Finance", CreatedBy = d.Requester.Id, UpdatedBy = d.Requester.Id, CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow }); await db.SaveChangesAsync(); tag = await db.DeviceTags.SingleAsync(t => t.EnvironmentId == d.OtherEnvironment.Id); }
        var value = invalid == "name" ? "VIP" : invalid == "missing" ? Guid.NewGuid().ToString() : tag.Id.ToString();
        using var owner = fixture.Client(d.RequesterToken);
        var response = await Post(owner, Root(d) + "/change-plans", new { change = new { kind = "scope.create", scopeKind = ScopeKind.DeviceTag, scopeValue = value, includeDescendants = invalid == "descendants" }, expectedVersion = 1, reason = "Synthetic scope test" });
        Assert.Equal(invalid is "name" or "descendants" ? HttpStatusCode.BadRequest : HttpStatusCode.Conflict, response.StatusCode);
    }
    private async Task GrantViewerTag(TestData d, DeviceTag tag)
    {
        await using var db = Db(); var role = new Role { EnvironmentId = d.Environment.Id, Id = Guid.NewGuid(), Name = "tag-reader" };
        var scope = new Scope { EnvironmentId = d.Environment.Id, Id = Guid.NewGuid(), Kind = ScopeKind.DeviceTag, Value = tag.Id.ToString() };
        db.AddRange(role, scope, new RoleAssignment { EnvironmentId = d.Environment.Id, Id = Guid.NewGuid(), PrincipalId = d.Viewer.Id, RoleId = role.Id, ScopeId = scope.Id });
        foreach (var p in new[] { PermissionCatalog.ComputerView, PermissionCatalog.UserView, PermissionCatalog.GroupView }) db.RolePermissions.Add(new() { EnvironmentId = d.Environment.Id, RoleId = role.Id, Permission = p });
        await db.SaveChangesAsync();
    }
    [Fact]
    public async Task Archived_assignments_keep_access_only_to_current_computers_and_survive_snapshot_replacement()
    {
        var (d, device, tag) = await Seed(); await GrantViewerTag(d, tag);
        Assert.Equal(HttpStatusCode.OK, (await ApproveExecute(d, await Propose(d, new { kind = "device-tag.assign", tagId = tag.Id, objectId = device, expectedTagVersion = 1 }))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await ApproveExecute(d, await Propose(d, new { kind = "device-tag.archive", tagId = tag.Id, expectedTagVersion = 2 }, 2))).StatusCode);
        using var viewer = fixture.Client(d.ViewerToken);
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync(Root(d) + $"/devices/{device}/tags")).StatusCode);
        var path = Root(d) + "/directory/objects?kind=Computer&tagId=" + tag.Id;
        Assert.Single((await viewer.GetFromJsonAsync<JsonElement>(path)).GetProperty("items").EnumerateArray());
        await using var db = Db(); var row = await db.DirectoryObjects.SingleAsync(x => x.Id == device); row.Kind = "User"; await db.SaveChangesAsync();
        Assert.Empty((await viewer.GetFromJsonAsync<JsonElement>(Root(d) + "/directory/objects?kind=User")).GetProperty("items").EnumerateArray());
        await db.DirectoryObjects.Where(x => x.Id == device).ExecuteDeleteAsync();
        db.ChangeTracker.Clear();
        Assert.Single(await db.DeviceTagAssignments.Where(a => a.EnvironmentId == d.Environment.Id).ToListAsync());
        var generation = Guid.NewGuid(); await db.DirectorySync.Where(s => s.EnvironmentId == d.Environment.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Generation, generation));
        db.DirectoryObjects.Add(new() { EnvironmentId = d.Environment.Id, Id = device, Generation = generation, Kind = "Computer", Name = "replacement snapshot", DistinguishedName = "CN=synthetic,DC=test" }); await db.SaveChangesAsync();
        Assert.Single((await viewer.GetFromJsonAsync<JsonElement>(path)).GetProperty("items").EnumerateArray());
        await db.DirectoryObjects.Where(x => x.Id == device).ExecuteDeleteAsync();
        Assert.Equal(HttpStatusCode.OK, (await ApproveExecute(d, await Propose(d, new { kind = "device-tag.unassign", tagId = tag.Id, objectId = device, expectedTagVersion = 3 }, 3))).StatusCode);
        Assert.Empty(await db.DeviceTagAssignments.Where(a => a.EnvironmentId == d.Environment.Id).ToListAsync());
    }
    [Fact]
    public async Task Runtime_tag_rls_requires_context_active_membership_and_same_environment()
    {
        var (d, _, _) = await Seed(); await using var runtime = Db(true);
        Assert.Empty(await runtime.DeviceTags.ToListAsync()); Assert.Empty(await runtime.DeviceTagAssignments.ToListAsync());
        await using (var tx = await runtime.BeginEnvironment(d.OtherEnvironment.Id, d.Viewer.Id, CancellationToken.None)) Assert.Empty(await runtime.DeviceTags.ToListAsync());
        await using (var tx = await runtime.BeginEnvironment(d.Environment.Id, d.Viewer.Id, CancellationToken.None)) Assert.Single(await runtime.DeviceTags.ToListAsync());
        await using var db = Db(); await db.Memberships.Where(m => m.EnvironmentId == d.Environment.Id && m.PrincipalId == d.Viewer.Id).ExecuteUpdateAsync(m => m.SetProperty(x => x.Active, false));
        await using (var tx = await runtime.BeginEnvironment(d.Environment.Id, d.Viewer.Id, CancellationToken.None)) Assert.Empty(await runtime.DeviceTags.ToListAsync());
    }
    [Theory]
    [InlineData("Id")]
    [InlineData("Key")]
    [InlineData("EnvironmentId")]
    [InlineData("CreatedAt")]
    [InlineData("CreatedBy")]
    public async Task Runtime_cannot_rewrite_tag_identity_or_assignment_metadata(string column)
    {
        var (d, device, tag) = await Seed();
        Assert.Equal(HttpStatusCode.OK, (await ApproveExecute(d, await Propose(d, new { kind = "device-tag.assign", tagId = tag.Id, objectId = device, expectedTagVersion = 1 }))).StatusCode);
        await using var runtime = Db(true);
        await using (var tx = await runtime.BeginEnvironment(d.Environment.Id, d.Requester.Id, CancellationToken.None))
        {
            // Column is one of the fixed InlineData values, not external input.
#pragma warning disable EF1002
            var error = await Assert.ThrowsAsync<Npgsql.PostgresException>(() => runtime.Database.ExecuteSqlRawAsync($"UPDATE public.\"DeviceTags\" SET \"{column}\"=\"{column}\""));
#pragma warning restore EF1002
            Assert.Equal("42501", error.SqlState);
        }
        await using (var tx = await runtime.BeginEnvironment(d.Environment.Id, d.Requester.Id, CancellationToken.None))
        {
            var error = await Assert.ThrowsAsync<Npgsql.PostgresException>(() => runtime.Database.ExecuteSqlRawAsync("UPDATE public.\"DeviceTagAssignments\" SET \"CreatedAt\"=\"CreatedAt\""));
            Assert.Equal("42501", error.SqlState);
        }
    }
}
