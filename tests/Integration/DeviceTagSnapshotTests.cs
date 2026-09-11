namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class DeviceTagSnapshotTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db(bool runtime = false) => new(new DbContextOptionsBuilder<ConsoleDbContext>()
        .UseNpgsql(Environment.GetEnvironmentVariable(runtime ? "CONSOLE_TEST_RUNTIME_DB" : "CONSOLE_TEST_DB")!).Options);
    private static string Root(TestData data) => $"/api/v1/environments/{data.Environment.Id}";

    [Fact]
    public async Task Directory_and_favorites_cursors_reject_environment_version_drift()
    {
        var state = await SeedAsync(deviceCount: 3);
        await GrantViewerAsync(state.Data, PermissionCatalog.ComputerView, state.Data.AllScopeId);
        await using (var db = Db())
        {
            db.Favorites.AddRange(state.Devices.Select(id => new DirectoryFavorite
                { EnvironmentId = state.Data.Environment.Id, PrincipalId = state.Data.Viewer.Id, ObjectId = id, Kind = "Computer" }));
            await db.SaveChangesAsync();
        }

        using var viewer = fixture.Client(state.Data.ViewerToken);
        var directory = await viewer.GetFromJsonAsync<JsonElement>(Root(state.Data) + "/directory/objects?kind=Computer&limit=1");
        var favorites = await viewer.GetFromJsonAsync<JsonElement>(Root(state.Data) + "/favorites?limit=1");
        var directoryCursor = Uri.EscapeDataString(directory.GetProperty("nextCursor").GetString()!);
        var favoritesCursor = Uri.EscapeDataString(favorites.GetProperty("nextCursor").GetString()!);
        await fixture.BumpEnvironmentVersionAsync(state.Data.Environment.Id);

        await AssertAuthorizationSnapshotChanged(viewer, Root(state.Data) + $"/directory/objects?kind=Computer&limit=1&cursor={directoryCursor}");
        await AssertAuthorizationSnapshotChanged(viewer, Root(state.Data) + $"/favorites?limit=1&cursor={favoritesCursor}");
    }

    [Fact]
    public async Task Tag_filter_intersects_authorized_scope_without_counts_or_foreign_rows()
    {
        var state = await SeedAsync(deviceCount: 2, tagCount: 2);
        await AssignDirectly(state.Data, state.Tags[0], state.Devices[0]);
        await AssignDirectly(state.Data, state.Tags[1], state.Devices[1]);
        var scope = await CreateTagScopeAsync(state.Data, state.Tags[0]);
        await GrantViewerAsync(state.Data, PermissionCatalog.ComputerView, scope.Id);
        using var viewer = fixture.Client(state.Data.ViewerToken);

        var allowed = await viewer.GetFromJsonAsync<JsonElement>(Root(state.Data) + $"/directory/objects?kind=Computer&tagId={state.Tags[0].Id}");
        var denied = await viewer.GetFromJsonAsync<JsonElement>(Root(state.Data) + $"/directory/objects?kind=Computer&tagId={state.Tags[1].Id}");

        Assert.Equal(state.Devices[0], Assert.Single(allowed.GetProperty("items").EnumerateArray()).GetProperty("id").GetGuid());
        Assert.Empty(denied.GetProperty("items").EnumerateArray());
        Assert.False(allowed.TryGetProperty("total", out _));
        Assert.False(denied.TryGetProperty("total", out _));
        Assert.DoesNotContain(state.Devices[1].ToString(), denied.GetRawText(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Archived_tag_blocks_new_assignment_and_scope_but_preserves_existing_scope()
    {
        var state = await SeedAsync(deviceCount: 2);
        await AssignDirectly(state.Data, state.Tags[0], state.Devices[0]);
        var scope = await CreateTagScopeAsync(state.Data, state.Tags[0]);
        await GrantViewerAsync(state.Data, PermissionCatalog.ComputerView, scope.Id);
        await using (var db = Db())
        {
            await db.DeviceTags.Where(x => x.EnvironmentId == state.Data.Environment.Id && x.Id == state.Tags[0].Id)
                .ExecuteUpdateAsync(x => x.SetProperty(t => t.ArchivedAt, DateTimeOffset.UtcNow).SetProperty(t => t.Version, 2));
        }

        using var requester = fixture.Client(state.Data.RequesterToken);
        var assignment = await Post(requester, Root(state.Data) + "/change-plans", new
        {
            change = new { kind = "device-tag.assign", tagId = state.Tags[0].Id, objectId = state.Devices[1], expectedTagVersion = 2 },
            expectedVersion = 1, reason = "Archived assignment check"
        });
        var newScope = await Post(requester, Root(state.Data) + "/change-plans", new
        {
            change = new { kind = "scope.create", scopeKind = ScopeKind.DeviceTag, scopeValue = state.Tags[0].Id.ToString("D"), includeDescendants = false },
            expectedVersion = 1, reason = "Archived scope check"
        });
        Assert.Equal(HttpStatusCode.Conflict, assignment.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, newScope.StatusCode);

        using var viewer = fixture.Client(state.Data.ViewerToken);
        var visible = await viewer.GetFromJsonAsync<JsonElement>(Root(state.Data) + "/directory/objects?kind=Computer");
        Assert.Equal(state.Devices[0], Assert.Single(visible.GetProperty("items").EnumerateArray()).GetProperty("id").GetGuid());
    }

    [Fact]
    public async Task Runtime_role_enforces_cross_environment_tag_fk_and_cannot_delete_tags()
    {
        var state = await SeedAsync();
        var foreign = NewTag(state.Data.OtherEnvironment.Id, "Finance", state.Data.Requester.Id);
        await using (var owner = Db()) { owner.DeviceTags.Add(foreign); await owner.SaveChangesAsync(); }

        await using (var runtime = Db(true))
        await using (var transaction = await runtime.BeginEnvironment(state.Data.Environment.Id, state.Data.Viewer.Id, CancellationToken.None))
        {
            runtime.DeviceTagAssignments.Add(new()
            {
                EnvironmentId = state.Data.Environment.Id, TagId = foreign.Id, ObjectId = state.Devices[0],
                CreatedAt = DateTimeOffset.UtcNow, CreatedBy = state.Data.Viewer.Id
            });
            var error = await Assert.ThrowsAsync<DbUpdateException>(() => runtime.SaveChangesAsync());
            Assert.Equal("23503", Assert.IsType<Npgsql.PostgresException>(error.InnerException).SqlState);
        }

        await using (var runtime = Db(true))
        await using (var transaction = await runtime.BeginEnvironment(state.Data.Environment.Id, state.Data.Requester.Id, CancellationToken.None))
        {
            var error = await Assert.ThrowsAsync<Npgsql.PostgresException>(() => runtime.DeviceTags
                .Where(x => x.EnvironmentId == state.Data.Environment.Id && x.Id == state.Tags[0].Id).ExecuteDeleteAsync());
            Assert.Equal("42501", error.SqlState);
        }
    }

    [Fact]
    public async Task Duplicate_create_and_assignment_plans_execute_at_most_once()
    {
        var createState = await SeedAsync();
        var createA = await Propose(createState.Data, new { kind = "device-tag.create", tagKey = "Finance" });
        var createB = await Propose(createState.Data, new { kind = "device-tag.create", tagKey = "Finance" });
        await Approve(createState.Data, createA);
        await Approve(createState.Data, createB);
        Assert.Equal(HttpStatusCode.OK, (await Execute(createState.Data, createA)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Execute(createState.Data, createB)).StatusCode);
        await using (var db = Db()) Assert.Single(await db.DeviceTags.Where(x => x.EnvironmentId == createState.Data.Environment.Id && x.Key == "Finance").ToListAsync());

        var assignState = await SeedAsync();
        var assignA = await Propose(assignState.Data, new { kind = "device-tag.assign", tagId = assignState.Tags[0].Id, objectId = assignState.Devices[0], expectedTagVersion = 1 });
        var assignB = await Propose(assignState.Data, new { kind = "device-tag.assign", tagId = assignState.Tags[0].Id, objectId = assignState.Devices[0], expectedTagVersion = 1 });
        await Approve(assignState.Data, assignA);
        await Approve(assignState.Data, assignB);
        Assert.Equal(HttpStatusCode.OK, (await Execute(assignState.Data, assignA)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Execute(assignState.Data, assignB)).StatusCode);
        await using (var db = Db()) Assert.Single(await db.DeviceTagAssignments.Where(x => x.EnvironmentId == assignState.Data.Environment.Id).ToListAsync());
    }

    [Fact]
    public async Task Tag_scope_is_rechecked_at_execution_after_archive()
    {
        var state = await SeedAsync();
        var plan = await Propose(state.Data, new
            { kind = "scope.create", scopeKind = ScopeKind.DeviceTag, scopeValue = state.Tags[0].Id.ToString("D"), includeDescendants = false });
        await Approve(state.Data, plan);
        await using (var db = Db()) await db.DeviceTags.Where(x => x.EnvironmentId == state.Data.Environment.Id && x.Id == state.Tags[0].Id)
            .ExecuteUpdateAsync(x => x.SetProperty(t => t.ArchivedAt, DateTimeOffset.UtcNow));

        var response = await Execute(state.Data, plan);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("TagUnavailable", body.GetProperty("title").GetString());
        await using var verify = Db();
        Assert.False(await verify.Scopes.AnyAsync(x => x.EnvironmentId == state.Data.Environment.Id && x.Kind == ScopeKind.DeviceTag));
    }

    [Theory]
    [InlineData("assignment.add", true)]
    [InlineData("group-mapping.add", true)]
    [InlineData("assignment.add", false)]
    [InlineData("group-mapping.add", false)]
    public async Task Archived_tag_scope_blocks_new_grant_at_proposal_and_execution(string kind, bool archivedBeforeProposal)
    {
        var state = await SeedAsync();
        var scope = await CreateTagScopeAsync(state.Data, state.Tags[0]);
        var role = new Role { EnvironmentId = state.Data.Environment.Id, Id = Guid.NewGuid(), Name = $"grant-target-{Guid.NewGuid():N}" };
        await using (var db = Db()) { db.Roles.Add(role); await db.SaveChangesAsync(); }
        var change = kind == "assignment.add"
            ? new { kind, principalId = (Guid?)state.Data.Viewer.Id, roleId = (Guid?)role.Id, scopeId = (Guid?)scope.Id, groupSid = (string?)null }
            : new { kind, principalId = (Guid?)null, roleId = (Guid?)role.Id, scopeId = (Guid?)scope.Id, groupSid = (string?)"S-1-5-21-100-200-300-400" };

        JsonElement plan = default;
        if (!archivedBeforeProposal)
        {
            plan = await Propose(state.Data, change);
            await Approve(state.Data, plan);
        }
        await using (var db = Db()) await db.DeviceTags.Where(x => x.EnvironmentId == state.Data.Environment.Id && x.Id == state.Tags[0].Id)
            .ExecuteUpdateAsync(x => x.SetProperty(t => t.ArchivedAt, DateTimeOffset.UtcNow));

        HttpResponseMessage response;
        if (archivedBeforeProposal)
        {
            using var requester = fixture.Client(state.Data.RequesterToken);
            response = await Post(requester, Root(state.Data) + "/change-plans", new { change, expectedVersion = 1, reason = "Archived grant scope check" });
        }
        else response = await Execute(state.Data, plan);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("TagUnavailable", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
        await using var verify = Db();
        Assert.False(await verify.Assignments.AnyAsync(x => x.EnvironmentId == state.Data.Environment.Id && x.RoleId == role.Id));
        Assert.False(await verify.GroupMappings.AnyAsync(x => x.EnvironmentId == state.Data.Environment.Id && x.RoleId == role.Id));
        if (archivedBeforeProposal) Assert.Equal(0, await fixture.PlanCountAsync(state.Data.Environment.Id));
    }

    [Fact]
    public async Task Archive_and_reactivate_remain_executable_through_the_api()
    {
        var state = await SeedAsync();
        var archive = await Propose(state.Data, new { kind = "device-tag.archive", tagId = state.Tags[0].Id, expectedTagVersion = 1 });
        await Approve(state.Data, archive);
        Assert.Equal(HttpStatusCode.OK, (await Execute(state.Data, archive)).StatusCode);

        var reactivate = await Propose(state.Data,
            new { kind = "device-tag.reactivate", tagId = state.Tags[0].Id, expectedTagVersion = 2 }, expectedVersion: 2);
        await Approve(state.Data, reactivate);
        Assert.Equal(HttpStatusCode.OK, (await Execute(state.Data, reactivate)).StatusCode);

        await using var db = Db();
        var tag = await db.DeviceTags.SingleAsync(x => x.EnvironmentId == state.Data.Environment.Id && x.Id == state.Tags[0].Id);
        Assert.Null(tag.ArchivedAt);
        Assert.Equal(3, tag.Version);
        Assert.Equal(3, (await db.Environments.SingleAsync(x => x.Id == state.Data.Environment.Id)).Version);
    }

    [Fact]
    public async Task Migration_backfill_targets_only_builtin_owner_and_is_idempotent()
    {
        var data = await fixture.SeedAsync();
        await using var db = Db();
        await using var transaction = await db.Database.BeginTransactionAsync();
        var admin = new Role { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Name = "migration-admin", BuiltInKind = BuiltInRoleKinds.Admin };
        var namedOwner = new Role { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Name = "Owner" };
        db.Roles.AddRange(admin, namedOwner);
        await db.SaveChangesAsync();
        var assignmentCount = await db.Assignments.CountAsync(x => x.EnvironmentId == data.Environment.Id);
        var scopeCount = await db.Scopes.CountAsync(x => x.EnvironmentId == data.Environment.Id);
        var migration = new global::Persistence.Migrations.DeviceTags();
        var statement = migration.UpOperations.OfType<Microsoft.EntityFrameworkCore.Migrations.Operations.SqlOperation>()
            .SelectMany(operation => operation.Sql.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Single(sql => sql.Contains("INSERT INTO public.\"RolePermissions\"", StringComparison.Ordinal)) + ";";

        await db.Database.ExecuteSqlRawAsync(statement);
        await db.Database.ExecuteSqlRawAsync(statement);

        var backfilled = await db.RolePermissions.Where(x => x.EnvironmentId == data.Environment.Id && x.Permission == PermissionCatalog.DeviceTagManage)
            .Select(x => x.RoleId).ToListAsync();
        Assert.Equal(new[] { data.RequesterRoleId }, backfilled);
        Assert.DoesNotContain(admin.Id, backfilled);
        Assert.DoesNotContain(namedOwner.Id, backfilled);
        Assert.Equal(assignmentCount, await db.Assignments.CountAsync(x => x.EnvironmentId == data.Environment.Id));
        Assert.Equal(scopeCount, await db.Scopes.CountAsync(x => x.EnvironmentId == data.Environment.Id));
        await transaction.RollbackAsync();
    }

    private async Task<TagState> SeedAsync(int deviceCount = 1, int tagCount = 1)
    {
        var data = await fixture.SeedAsync(); var generation = Guid.NewGuid(); var now = DateTimeOffset.UtcNow;
        var devices = Enumerable.Range(0, deviceCount).Select(_ => Guid.NewGuid()).ToArray();
        var keys = new[] { "VIP", "Finance", "Shared" };
        var tags = Enumerable.Range(0, tagCount).Select(i => NewTag(data.Environment.Id, keys[i], data.Requester.Id)).ToArray();
        await using var db = Db();
        db.RolePermissions.Add(new() { EnvironmentId = data.Environment.Id, RoleId = data.RequesterRoleId, Permission = PermissionCatalog.DeviceTagManage });
        db.DirectorySync.Add(new() { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Generation = generation, Status = "Ready", CompletedAt = now });
        db.DirectoryObjects.AddRange(devices.Select((id, i) => new DirectoryObjectRecord
        {
            EnvironmentId = data.Environment.Id, Id = id, Generation = generation, Kind = "Computer",
            Name = $"synthetic-tag-snapshot-{i}", DistinguishedName = $"CN=synthetic-{i},DC=test"
        }));
        db.DeviceTags.AddRange(tags); await db.SaveChangesAsync();
        return new(data, devices, tags);
    }

    private static DeviceTag NewTag(Guid environmentId, string key, Guid actor)
    {
        var now = DateTimeOffset.UtcNow;
        return new() { EnvironmentId = environmentId, Id = Guid.NewGuid(), Key = key, CreatedAt = now, UpdatedAt = now, CreatedBy = actor, UpdatedBy = actor };
    }

    private static async Task AssignDirectly(TestData data, DeviceTag tag, Guid device)
    {
        await using var db = Db();
        db.DeviceTagAssignments.Add(new() { EnvironmentId = data.Environment.Id, TagId = tag.Id, ObjectId = device, CreatedAt = DateTimeOffset.UtcNow, CreatedBy = data.Requester.Id });
        await db.SaveChangesAsync();
    }

    private static async Task<Scope> CreateTagScopeAsync(TestData data, DeviceTag tag)
    {
        var scope = new Scope { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Kind = ScopeKind.DeviceTag, Value = tag.Id.ToString("D") };
        await using var db = Db(); db.Scopes.Add(scope); await db.SaveChangesAsync(); return scope;
    }

    private static async Task GrantViewerAsync(TestData data, string permission, Guid scopeId)
    {
        await using var db = Db(); var role = new Role { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Name = $"snapshot-{Guid.NewGuid():N}" };
        db.AddRange(role, new RoleAssignment { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), PrincipalId = data.Viewer.Id, RoleId = role.Id, ScopeId = scopeId },
            new RolePermission { EnvironmentId = data.Environment.Id, RoleId = role.Id, Permission = permission });
        await db.SaveChangesAsync();
    }

    private async Task<JsonElement> Propose(TestData data, object change, long expectedVersion = 1)
    {
        using var requester = fixture.Client(data.RequesterToken);
        var response = await Post(requester, Root(data) + "/change-plans", new { change, expectedVersion, reason = "Snapshot invariant test" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    private async Task Approve(TestData data, JsonElement plan)
    {
        using var reviewer = fixture.Client(data.ReviewerToken);
        var response = await Post(reviewer, Root(data) + $"/change-plans/{plan.GetProperty("id").GetGuid()}/approval",
            new { planHash = plan.GetProperty("planHash").GetString() });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private Task<HttpResponseMessage> Execute(TestData data, JsonElement plan)
    {
        var requester = fixture.Client(data.RequesterToken);
        return PostAndDispose(requester, Root(data) + $"/change-plans/{plan.GetProperty("id").GetGuid()}/execution");
    }

    private static async Task<HttpResponseMessage> PostAndDispose(HttpClient client, string path)
    {
        try { return await Post(client, path, new { }); }
        finally { client.Dispose(); }
    }

    private static async Task<HttpResponseMessage> Post(HttpClient client, string path, object body)
    {
        using var request = await client.MutationAsync(HttpMethod.Post, path, body);
        return await client.SendAsync(request);
    }

    private static async Task AssertAuthorizationSnapshotChanged(HttpClient client, string path)
    {
        var response = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("AuthorizationSnapshotChanged", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
    }

    private sealed record TagState(TestData Data, Guid[] Devices, DeviceTag[] Tags);
}
