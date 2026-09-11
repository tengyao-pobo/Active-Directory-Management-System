namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class DirectoryProposalTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db() => new(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Options);
    private async Task<(TestData Data, Guid Id)> Seed(bool view = true, bool edit = true)
    {
        var d = await fixture.SeedAsync(); var id = Guid.NewGuid(); var generation = Guid.NewGuid();
        await using var db = Db();
        db.DirectorySync.Add(new() { EnvironmentId = d.Environment.Id, Id = Guid.NewGuid(), Generation = generation, Status = "Ready", CompletedAt = DateTimeOffset.UtcNow });
        db.DirectoryObjects.Add(new() { EnvironmentId = d.Environment.Id, Id = id, Generation = generation, Kind = "User", Name = "proposal-user", DistinguishedName = "CN=user,DC=test", Department = "Operations" });
        if (view) db.RolePermissions.Add(new() { EnvironmentId = d.Environment.Id, RoleId = d.RequesterRoleId, Permission = PermissionCatalog.UserView });
        if (edit) db.RolePermissions.Add(new() { EnvironmentId = d.Environment.Id, RoleId = d.RequesterRoleId, Permission = PermissionCatalog.UserEdit });
        await db.SaveChangesAsync(); return (d, id);
    }
    private static string Path(TestData d, Guid id) => $"/api/v1/environments/{d.Environment.Id}/directory/users/{id}/proposal";
    private static async Task<HttpResponseMessage> Preview(HttpClient c, string path, string department = "Finance", string kind = "SetUserDepartment")
    {
        using var request = await c.MutationAsync(HttpMethod.Post, path, new { kind, department });
        return await c.SendAsync(request);
    }
    [Fact]
    public async Task Proposal_is_server_derived_and_cannot_authorize_or_change_anything()
    {
        var (d,id) = await Seed(); using var client = fixture.Client(d.RequesterToken);
        var response = await Preview(client, Path(d,id)); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Operations", json.GetProperty("before").GetString()); Assert.Equal("Finance", json.GetProperty("after").GetString());
        Assert.False(json.GetProperty("approvalAvailable").GetBoolean()); Assert.False(json.GetProperty("executionAvailable").GetBoolean());
        Assert.Contains("ProtectionClassificationUnavailable", json.ToString()); Assert.False(json.TryGetProperty("planHash", out _));
        Assert.Equal(0, await fixture.PlanCountAsync(d.Environment.Id));
        await using var db = Db(); Assert.Equal("Operations", (await db.DirectoryObjects.SingleAsync(x => x.Id == id)).Department);
        Assert.False(await db.Approvals.AnyAsync(x => x.EnvironmentId == d.Environment.Id));
        Assert.False(await db.Audit.AnyAsync(x => x.EnvironmentId == d.Environment.Id));
        Assert.False(await db.Outbox.AnyAsync(x => x.EnvironmentId == d.Environment.Id));
    }
    [Theory] [InlineData(false,true)] [InlineData(true,false)]
    public async Task Either_missing_permission_denies_preview(bool view, bool edit)
    {
        var(d,id)=await Seed(view,edit); using var client=fixture.Client(d.RequesterToken);
        Assert.Equal(HttpStatusCode.NotFound,(await Preview(client,Path(d,id))).StatusCode);
    }
    [Fact]
    public async Task Stale_wrong_kind_foreign_and_disjoint_scopes_fail_closed()
    {
        var(d,id)=await Seed(); using var client=fixture.Client(d.RequesterToken); await using var db=Db();
        Assert.Equal(HttpStatusCode.NotFound,(await Preview(client,$"/api/v1/environments/{d.OtherEnvironment.Id}/directory/users/{id}/proposal")).StatusCode);
        var row=await db.DirectoryObjects.SingleAsync(x=>x.Id==id); row.Kind="Computer"; await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.NotFound,(await Preview(client,Path(d,id))).StatusCode);
        row.Kind="User";
        var grant=await db.RolePermissions.SingleAsync(x=>x.EnvironmentId==d.Environment.Id && x.Permission==PermissionCatalog.UserEdit); db.Remove(grant);
        var role=new Role{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Name="disjoint-edit"};
        var scope=new Scope{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Kind=ScopeKind.Department,Value="Other"};
        db.AddRange(role,scope,new RoleAssignment{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),PrincipalId=d.Requester.Id,RoleId=role.Id,ScopeId=scope.Id},new RolePermission{EnvironmentId=d.Environment.Id,RoleId=role.Id,Permission=PermissionCatalog.UserEdit}); await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.NotFound,(await Preview(client,Path(d,id))).StatusCode);
        var sync=await db.DirectorySync.SingleAsync(x=>x.EnvironmentId==d.Environment.Id); sync.CompletedAt=DateTimeOffset.UtcNow.AddMinutes(-3); await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.ServiceUnavailable,(await Preview(client,Path(d,id))).StatusCode);
    }
    [Theory] [InlineData("")] [InlineData(" ")] [InlineData("bad\nvalue")]
    public async Task Invalid_departments_are_rejected(string department)
    {
        var(d,id)=await Seed(); using var client=fixture.Client(d.RequesterToken);
        Assert.Equal(HttpStatusCode.BadRequest,(await Preview(client,Path(d,id),department)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,(await Preview(client,Path(d,id),"Finance","DisableUser")).StatusCode);
    }
    [Fact]
    public async Task Protected_preview_remains_informational_and_csrf_is_required()
    {
        var(d,id)=await Seed(); using var client=fixture.Client(d.RequesterToken); await using var db=Db();
        var row=await db.DirectoryObjects.SingleAsync(x=>x.Id==id); row.IsProtected=true; row.ProtectionKnown=true; await db.SaveChangesAsync();
        var response=await Preview(client,Path(d,id)); Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        var json=await response.Content.ReadFromJsonAsync<JsonElement>(); Assert.Contains("ProtectedObject",json.ToString()); Assert.False(json.GetProperty("approvalAvailable").GetBoolean());
        Assert.Equal(HttpStatusCode.BadRequest,(await Preview(client,Path(d,id),new string('x',129))).StatusCode);
        using var request=new HttpRequestMessage(HttpMethod.Post,Path(d,id)){Content=JsonContent.Create(new{kind="SetUserDepartment",department="Finance"})}; request.Headers.Add("Origin","https://localhost:7443");
        Assert.Equal(HttpStatusCode.BadRequest,(await client.SendAsync(request)).StatusCode);
    }
    [Theory] [InlineData("Ready",3)] [InlineData("Failed",0)] [InlineData("Syncing",0)]
    public async Task Future_or_unready_snapshot_is_rejected(string status,int offset)
    {
        var(d,id)=await Seed(); using var client=fixture.Client(d.RequesterToken); await using var db=Db();
        var sync=await db.DirectorySync.SingleAsync(x=>x.EnvironmentId==d.Environment.Id); sync.Status=status; sync.CompletedAt=DateTimeOffset.UtcNow.AddMinutes(offset); await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.ServiceUnavailable,(await Preview(client,Path(d,id))).StatusCode);
    }
}
