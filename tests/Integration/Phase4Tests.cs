namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class Phase4Tests(PostgresApiFixture fixture)
{
    [Fact]
    public async Task Unconfigured_directory_reports_status_but_objects_are_unavailable()
    {
        var data = await fixture.SeedAsync();
        using var client = fixture.Client(data.ViewerToken);

        var status = await client.GetFromJsonAsync<JsonElement>(StatusPath(data));
        var objects = await client.GetAsync(ObjectsPath(data, "User"));

        Assert.Equal("Unconfigured", status.GetProperty("status").GetString());
        Assert.True(status.GetProperty("stale").GetBoolean());
        Assert.False(status.GetProperty("mutationAvailable").GetBoolean());
        Assert.Equal(HttpStatusCode.ServiceUnavailable, objects.StatusCode);
        Assert.Equal("DirectoryUnavailable", (await objects.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
    }

    [Fact]
    public async Task User_view_role_and_exact_or_subtree_ou_scope_control_list_and_detail()
    {
        var data = await fixture.SeedAsync();
        var parent = Guid.NewGuid();
        var child = Guid.NewGuid();
        var sibling = Guid.NewGuid();
        var direct = Object(data.Environment.Id, Guid.NewGuid(), "direct-user", parent, [parent]);
        var descendant = Object(data.Environment.Id, Guid.NewGuid(), "descendant-user", child, [parent, child]);
        var hidden = Object(data.Environment.Id, Guid.NewGuid(), "hidden-user", sibling, [sibling]);
        await SeedReadyAsync(data, [direct, descendant, hidden]);
        await GrantUserViewAsync(data.Environment.Id, data.Viewer.Id, parent, includeDescendants: false);
        using var client = fixture.Client(data.ViewerToken);

        var exact = await ListAsync(client, data, "User");
        Assert.Equal(new[] { direct.Id }, Ids(exact));
        Assert.False(exact.TryGetProperty("total", out _));
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(ObjectPath(data, descendant.Id))).StatusCode);

        await SetOuScopeDescendantsAsync(data.Environment.Id, data.Viewer.Id, parent);
        var subtree = await ListAsync(client, data, "User");
        Assert.Equal(new[] { direct.Id, descendant.Id }.Order(), Ids(subtree).Order());
        Assert.Equal(descendant.Id, (await client.GetFromJsonAsync<JsonElement>(ObjectPath(data, descendant.Id))).GetProperty("item").GetProperty("id").GetGuid());
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(ObjectPath(data, hidden.Id))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/api/v1/environments/{data.OtherEnvironment.Id}/directory/objects/{direct.Id}")).StatusCode);
    }

    [Fact]
    public async Task Directory_cursor_is_limited_and_bound_to_actor_environment_query_and_generation()
    {
        var data = await fixture.SeedAsync();
        var visible = Enumerable.Range(0, 3).Select(i => Object(data.Environment.Id, Guid.NewGuid(), $"visible-{i}", Guid.NewGuid(), [])).ToArray();
        var hidden = Object(data.Environment.Id, Guid.NewGuid(), "hidden-secret", Guid.NewGuid(), []);
        await SeedReadyAsync(data, visible.Append(hidden));
        await GrantUserViewAsync(data.Environment.Id, data.Viewer.Id, null, includeDescendants: false, allScope: true);
        await GrantUserViewAsync(data.OtherEnvironment.Id, data.Viewer.Id, null, includeDescendants: false, allScope: true, addMembership: true);
        await SeedReadyOtherAsync(data);
        using var viewer = fixture.Client(data.ViewerToken);
        using var requester = fixture.Client(data.RequesterToken);

        var first = await ListAsync(viewer, data, "User", "", 1);
        Assert.Single(Ids(first));
        Assert.False(first.TryGetProperty("total", out _));
        var cursor = first.GetProperty("nextCursor").GetString();
        Assert.False(string.IsNullOrWhiteSpace(cursor));
        Assert.Equal(HttpStatusCode.BadRequest, (await viewer.GetAsync(ObjectsPath(data, "User", cursor: cursor + "."))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await viewer.GetAsync(ObjectsPath(data, "Group", cursor: cursor))).StatusCode);
        var secondResponse = await viewer.GetAsync(ObjectsPath(data, "User", cursor: cursor));
        secondResponse.EnsureSuccessStatusCode();
        var second = await secondResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.DoesNotContain(Ids(first).Single(), Ids(second));
        Assert.Equal(HttpStatusCode.BadRequest, (await requester.GetAsync(ObjectsPath(data, "User", cursor: cursor))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await viewer.GetAsync(ObjectsPath(data, "User", "different", cursor))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await viewer.GetAsync($"/api/v1/environments/{data.OtherEnvironment.Id}/directory/objects?kind=User&cursor={Uri.EscapeDataString(cursor!)}")).StatusCode);

        await ChangeGenerationAsync(data.Environment.Id);
        var changed = await viewer.GetAsync(ObjectsPath(data, "User", cursor: cursor));
        Assert.Equal(HttpStatusCode.Conflict, changed.StatusCode);
        Assert.Equal("DirectorySnapshotChanged", (await changed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
    }

    [Theory]
    [InlineData("Failed")]
    [InlineData("Ready")]
    public async Task Failed_or_stale_directory_snapshot_is_unavailable(string status)
    {
        var data = await fixture.SeedAsync();
        await SeedReadyAsync(data, [], status, status == "Ready" ? DateTimeOffset.UtcNow.AddMinutes(-16) : DateTimeOffset.UtcNow);
        await GrantUserViewAsync(data.Environment.Id, data.Viewer.Id, null, includeDescendants: false, allScope: true);
        using var client = fixture.Client(data.ViewerToken);

        var response = await client.GetAsync(ObjectsPath(data, "User"));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("DirectoryUnavailable", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
    }

    [Fact]
    public async Task Runtime_role_cannot_directly_write_directory_projection_tables()
    {
        var data = await fixture.SeedAsync();
        await SeedReadyAsync(data, []);
        await using var db = RuntimeDb();
        await using var tx = await db.BeginEnvironment(data.Environment.Id, data.Viewer.Id, CancellationToken.None);
        db.DirectoryObjects.Add(Object(data.Environment.Id, Guid.NewGuid(), "forbidden-write", Guid.NewGuid(), []));
        var error = await Assert.ThrowsAnyAsync<Exception>(() => db.SaveChangesAsync());

        Assert.True(error is Npgsql.PostgresException { SqlState: "42501" } || error.InnerException is Npgsql.PostgresException { SqlState: "42501" });
    }

    private static string StatusPath(TestData data) => $"/api/v1/environments/{data.Environment.Id}/directory/status";
    private static string ObjectsPath(TestData data, string kind, string search = "", string? cursor = null, int? limit = null) =>
        $"/api/v1/environments/{data.Environment.Id}/directory/objects?kind={kind}&search={Uri.EscapeDataString(search)}" +
        (limit is null ? "" : $"&limit={limit}") + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}");
    private static string ObjectPath(TestData data, Guid id) => $"/api/v1/environments/{data.Environment.Id}/directory/objects/{id}";
    private static IEnumerable<Guid> Ids(JsonElement page) => page.GetProperty("items").EnumerateArray().Select(x => x.GetProperty("id").GetGuid());
    private static async Task<JsonElement> ListAsync(HttpClient client, TestData data, string kind, string search = "", int? limit = null) =>
        (await client.GetFromJsonAsync<JsonElement>(ObjectsPath(data, kind, search, limit: limit)))!;

    private static ConsoleDbContext OwnerDb() => new(new DbContextOptionsBuilder<ConsoleDbContext>()
        .UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Options);
    private static ConsoleDbContext RuntimeDb() => new(new DbContextOptionsBuilder<ConsoleDbContext>()
        .UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")!).Options);

    private static DirectoryObjectRecord Object(Guid environment, Guid id, string name, Guid parentOu, Guid[] ancestry) => new()
    { EnvironmentId = environment, Id = id, Generation = CurrentGeneration, Kind = "User", DistinguishedName = $"CN={name},DC=example,DC=test", Name = name,
      SamAccountName = name, ParentOuId = parentOu, OuAncestry = ancestry, ObjectSid = $"S-1-5-21-{id:N}", UsnChanged = 1, ProtectionKnown = true };

    private static Guid CurrentGeneration { get; } = Guid.NewGuid();

    private static async Task SeedReadyAsync(TestData data, IEnumerable<DirectoryObjectRecord> rows, string status = "Ready", DateTimeOffset? completed = null)
    {
        await using var db = OwnerDb();
        var generation = CurrentGeneration;
        db.DirectorySync.Add(new DirectorySyncState { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Generation = generation, Status = status,
            CompletedAt = completed ?? DateTimeOffset.UtcNow, AttemptedAt = DateTimeOffset.UtcNow, SourceServer = "test", NamingContext = "DC=example,DC=test" });
        db.DirectoryObjects.AddRange(rows.Select(x => { x.Generation = generation; return x; }));
        await db.SaveChangesAsync();
    }

    private static async Task SeedReadyOtherAsync(TestData data)
    {
        await using var db = OwnerDb();
        db.DirectorySync.Add(new DirectorySyncState { EnvironmentId = data.OtherEnvironment.Id, Id = Guid.NewGuid(), Generation = Guid.NewGuid(), Status = "Ready",
            CompletedAt = DateTimeOffset.UtcNow, AttemptedAt = DateTimeOffset.UtcNow, SourceServer = "test", NamingContext = "DC=other,DC=test" });
        await db.SaveChangesAsync();
    }

    private static async Task GrantUserViewAsync(Guid environment, Guid principal, Guid? ou, bool includeDescendants, bool allScope = false, bool addMembership = false)
    {
        await using var db = OwnerDb();
        var role = new Role { EnvironmentId = environment, Id = Guid.NewGuid(), Name = $"directory-view-{Guid.NewGuid():N}" };
        var scope = new Scope { EnvironmentId = environment, Id = Guid.NewGuid(), Kind = allScope ? ScopeKind.All : ScopeKind.OrganizationalUnit,
            Value = allScope ? null : ou!.Value.ToString(), IncludeDescendants = includeDescendants };
        db.AddRange(role, scope, new RolePermission { EnvironmentId = environment, RoleId = role.Id, Permission = PermissionCatalog.UserView },
            new RoleAssignment { EnvironmentId = environment, Id = Guid.NewGuid(), PrincipalId = principal, RoleId = role.Id, ScopeId = scope.Id });
        if (addMembership) db.Memberships.Add(new EnvironmentMembership { EnvironmentId = environment, PrincipalId = principal, Active = true });
        await db.SaveChangesAsync();
    }

    private static async Task SetOuScopeDescendantsAsync(Guid environment, Guid principal, Guid ou)
    {
        await using var db = OwnerDb();
        var scope = await db.Scopes.Join(db.Assignments, s => new { s.EnvironmentId, s.Id }, a => new { a.EnvironmentId, Id = a.ScopeId }, (s, a) => new { s, a })
            .Where(x => x.a.EnvironmentId == environment && x.a.PrincipalId == principal && x.s.Kind == ScopeKind.OrganizationalUnit).Select(x => x.s).SingleAsync();
        scope.Value = ou.ToString();
        scope.IncludeDescendants = true;
        await db.SaveChangesAsync();
    }

    private static async Task ChangeGenerationAsync(Guid environment)
    {
        await using var db = OwnerDb();
        var state = await db.DirectorySync.SingleAsync(x => x.EnvironmentId == environment);
        state.Generation = Guid.NewGuid();
        await db.SaveChangesAsync();
    }
}
