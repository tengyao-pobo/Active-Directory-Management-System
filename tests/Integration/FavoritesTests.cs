namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class FavoritesTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db(bool runtime = false) => new(new DbContextOptionsBuilder<ConsoleDbContext>()
        .UseNpgsql(Environment.GetEnvironmentVariable(runtime ? "CONSOLE_TEST_RUNTIME_DB" : "CONSOLE_TEST_DB")!).Options);

    private async Task<(TestData Data, Guid[] Ids, Guid Ou)> Seed()
    {
        var data = await fixture.SeedAsync();
        var generation = Guid.NewGuid(); var ou = Guid.NewGuid();
        string[] kinds = ["Computer", "User", "Group", "OrganizationalUnit"];
        string[] permissions = [PermissionCatalog.ComputerView, PermissionCatalog.UserView, PermissionCatalog.GroupView];
        var ids = kinds.Select(_ => Guid.NewGuid()).ToArray();
        await using var db = Db();
        db.DirectorySync.Add(new() { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Generation = generation, Status = "Ready", CompletedAt = DateTimeOffset.UtcNow });
        for (var i = 0; i < kinds.Length; i++) db.DirectoryObjects.Add(new() { EnvironmentId = data.Environment.Id,
            Id = ids[i], Generation = generation, Kind = kinds[i], Name = $"synthetic-{kinds[i]}",
            DistinguishedName = $"CN=synthetic-{i},DC=test", ParentOuId = ou, OuAncestry = [ou] });
        var role = new Role { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Name = "favorites-test" };
        var scope = new Scope { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Kind = ScopeKind.OrganizationalUnit, Value = ou.ToString() };
        db.AddRange(role, scope, new RoleAssignment { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), PrincipalId = data.Viewer.Id, RoleId = role.Id, ScopeId = scope.Id });
        foreach (var permission in permissions) db.RolePermissions.Add(new() { EnvironmentId = data.Environment.Id, RoleId = role.Id, Permission = permission });
        await db.SaveChangesAsync(); return (data, ids, ou);
    }
    private static string Path(TestData data, Guid? id = null) => $"/api/v1/environments/{data.Environment.Id}/favorites" + (id is null ? "" : $"/{id}");
    private static async Task<HttpResponseMessage> Mutate(HttpClient client, string path, HttpMethod? method = null)
    {
        using var request = await client.MutationAsync(method ?? HttpMethod.Put, path, new { });
        return await client.SendAsync(request);
    }

    [Fact]
    public async Task All_four_kinds_are_personal_idempotent_and_paginated()
    {
        var (data, ids, _) = await Seed(); using var client = fixture.Client(data.ViewerToken);
        foreach (var id in ids) Assert.Equal(HttpStatusCode.NoContent, (await Mutate(client, Path(data, id))).StatusCode);
        await using var db = Db();
        var before = await db.Favorites.Where(x => x.EnvironmentId == data.Environment.Id).ToDictionaryAsync(x => x.ObjectId, x => x.CreatedAt);
        foreach (var id in ids) Assert.Equal(HttpStatusCode.NoContent, (await Mutate(client, Path(data, id))).StatusCode);
        var after = await db.Favorites.AsNoTracking().Where(x => x.EnvironmentId == data.Environment.Id).ToDictionaryAsync(x => x.ObjectId, x => x.CreatedAt);
        Assert.Equal(before.OrderBy(x => x.Key), after.OrderBy(x => x.Key));
        var first = await client.GetFromJsonAsync<JsonElement>(Path(data) + "?limit=2");
        Assert.Equal(2, first.GetProperty("items").GetArrayLength());
        var cursor = first.GetProperty("nextCursor").GetString()!;
        var second = await client.GetFromJsonAsync<JsonElement>(Path(data) + "?limit=2&cursor=" + Uri.EscapeDataString(cursor));
        var returned = first.GetProperty("items").EnumerateArray().Concat(second.GetProperty("items").EnumerateArray()).Select(x => x.GetProperty("id").GetGuid()).ToArray();
        Assert.Equal(ids.Order(), returned.Order()); Assert.Null(second.GetProperty("nextCursor").GetString());
        Assert.True((await client.GetFromJsonAsync<JsonElement>(Path(data, ids[0]))).GetProperty("saved").GetBoolean());
        using var other = fixture.Client(data.ReviewerToken);
        Assert.Empty((await other.GetFromJsonAsync<JsonElement>(Path(data))).GetProperty("items").EnumerateArray());
        Assert.Equal(HttpStatusCode.BadRequest, (await other.GetAsync(Path(data) + "?cursor=" + Uri.EscapeDataString(cursor))).StatusCode);
    }

    [Fact]
    public async Task Scope_loss_and_stale_generation_hide_rows_but_allow_opaque_cleanup()
    {
        var (data, ids, _) = await Seed(); using var client = fixture.Client(data.ViewerToken);
        Assert.Equal(HttpStatusCode.NoContent, (await Mutate(client, Path(data, ids[0]))).StatusCode);
        await using var db = Db();
        var row = await db.DirectoryObjects.SingleAsync(x => x.EnvironmentId == data.Environment.Id && x.Id == ids[0]);
        row.ParentOuId = Guid.NewGuid(); row.OuAncestry = []; await db.SaveChangesAsync();
        Assert.Empty((await client.GetFromJsonAsync<JsonElement>(Path(data))).GetProperty("items").EnumerateArray());
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(Path(data, ids[0]))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Mutate(client, Path(data, ids[0]))).StatusCode);
        var state = await db.DirectorySync.SingleAsync(x => x.EnvironmentId == data.Environment.Id);
        state.CompletedAt = DateTimeOffset.UtcNow.AddHours(-1); await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await client.GetAsync(Path(data))).StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await Mutate(client, Path(data, ids[1]))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Mutate(client, Path(data, ids[0]), HttpMethod.Delete)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Mutate(client, Path(data, Guid.NewGuid()), HttpMethod.Delete)).StatusCode);
        Assert.False(await db.Favorites.AnyAsync(x => x.EnvironmentId == data.Environment.Id));
    }

    [Fact]
    public async Task Cursor_rechecks_generation_and_input_boundaries()
    {
        var (data, ids, _) = await Seed(); using var client = fixture.Client(data.ViewerToken);
        foreach (var id in ids) await Mutate(client, Path(data, id));
        var page = await client.GetFromJsonAsync<JsonElement>(Path(data) + "?limit=1");
        var cursor = Uri.EscapeDataString(page.GetProperty("nextCursor").GetString()!);
        await using var db = Db(); var state = await db.DirectorySync.SingleAsync(x => x.EnvironmentId == data.Environment.Id);
        state.Generation = Guid.NewGuid(); await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.Conflict, (await client.GetAsync(Path(data) + "?cursor=" + cursor)).StatusCode);
        Assert.Empty((await client.GetFromJsonAsync<JsonElement>(Path(data))).GetProperty("items").EnumerateArray());
        foreach (var query in new[] { "?limit=0", "?limit=101", "?cursor=invalid" })
            Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync(Path(data) + query)).StatusCode);
    }

    [Fact]
    public async Task Active_membership_and_csrf_are_required_and_actor_cannot_be_overridden()
    {
        var (data, ids, _) = await Seed(); using var client = fixture.Client(data.ViewerToken);
        using var missing = new HttpRequestMessage(HttpMethod.Put, Path(data, ids[0])); missing.Headers.Add("Origin", "https://localhost:7443");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(missing)).StatusCode);
        using var impersonation = await client.MutationAsync(HttpMethod.Put, Path(data, ids[0]), new { principalId = data.Requester.Id, kind = "User", environmentId = data.OtherEnvironment.Id });
        Assert.Equal(HttpStatusCode.NoContent, (await client.SendAsync(impersonation)).StatusCode);
        await using var db = Db(); var favorite = await db.Favorites.SingleAsync(x => x.EnvironmentId == data.Environment.Id);
        Assert.Equal(data.Viewer.Id, favorite.PrincipalId); Assert.Equal("Computer", favorite.Kind);
        var membership = await db.Memberships.SingleAsync(x => x.EnvironmentId == data.Environment.Id && x.PrincipalId == data.Viewer.Id);
        membership.Active = false; await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(Path(data))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Mutate(client, Path(data, ids[0]), HttpMethod.Delete)).StatusCode);
    }

    [Fact]
    public async Task Runtime_rls_rejects_foreign_principal_writes_and_hides_other_favorites()
    {
        var (data, ids, _) = await Seed(); using var client = fixture.Client(data.ViewerToken); await Mutate(client, Path(data, ids[0]));
        await using var db = Db(true); Assert.Empty(await db.Favorites.ToListAsync());
        await using var tx = await db.BeginEnvironment(data.Environment.Id, data.Requester.Id, CancellationToken.None);
        Assert.Empty(await db.Favorites.ToListAsync());
        Assert.Equal(0, await db.Favorites.Where(x => x.ObjectId == ids[0]).ExecuteDeleteAsync());
        db.Favorites.Add(new() { EnvironmentId = data.Environment.Id, PrincipalId = data.Viewer.Id, ObjectId = ids[1], Kind = "User" });
        var error = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        Assert.Equal("42501", Assert.IsType<Npgsql.PostgresException>(error.InnerException).SqlState);
    }

    [Fact]
    public async Task Capacity_is_bounded_under_concurrent_insert_and_existing_retry_still_succeeds()
    {
        var (data, ids, _) = await Seed();
        await using var db = Db();
        for (var i = 0; i < 499; i++) db.Favorites.Add(new() { EnvironmentId = data.Environment.Id, PrincipalId = data.Viewer.Id, ObjectId = Guid.NewGuid(), Kind = "Computer" });
        await db.SaveChangesAsync();
        using var a = fixture.Client(data.ViewerToken); using var b = fixture.Client(data.ViewerToken);
        var results = await Task.WhenAll(Mutate(a, Path(data, ids[0])), Mutate(b, Path(data, ids[1])));
        Assert.Single(results, x => x.StatusCode == HttpStatusCode.NoContent);
        Assert.Single(results, x => x.StatusCode == HttpStatusCode.Conflict);
        Assert.Equal(500, await db.Favorites.CountAsync(x => x.EnvironmentId == data.Environment.Id));
        var accepted = await db.Favorites.Where(x => x.EnvironmentId == data.Environment.Id && ids.Contains(x.ObjectId)).Select(x => x.ObjectId).SingleAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await Mutate(a, Path(data, accepted))).StatusCode);
    }
}
