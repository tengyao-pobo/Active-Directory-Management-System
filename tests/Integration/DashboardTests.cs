namespace ItManagement.IntegrationTests;
[Collection(nameof(PostgresApiCollection))]
public sealed class DashboardTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db() => new(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Options);
    private async Task<(TestData Data,Guid Ou,Guid Generation)> Seed(int repairs=2)
    {
        var d=await fixture.SeedAsync();var ou=Guid.NewGuid();var generation=Guid.NewGuid();await using var db=Db();
        db.DirectorySync.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Generation=generation,Status="Ready",CompletedAt=DateTimeOffset.UtcNow});
        var role=new Role{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Name="dashboard"};var scope=new Scope{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Kind=ScopeKind.OrganizationalUnit,Value=ou.ToString()};db.AddRange(role,scope,new RoleAssignment{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),PrincipalId=d.Viewer.Id,RoleId=role.Id,ScopeId=scope.Id});
        foreach(var permission in new[]{PermissionCatalog.ComputerView,PermissionCatalog.UserView})db.RolePermissions.Add(new(){EnvironmentId=d.Environment.Id,RoleId=role.Id,Permission=permission});
        for(int i=0;i<repairs+3;i++)
        {
            var id=Guid.NewGuid();bool hidden=i==repairs+2;
            db.DirectoryObjects.Add(new(){EnvironmentId=d.Environment.Id,Id=id,Generation=generation,Kind="Computer",Name=hidden?"hidden-canary":"device"+i,DistinguishedName="CN=test,DC=test",ParentOuId=hidden?Guid.NewGuid():ou});
            if(i!=repairs)db.DeviceAssets.Add(new(){EnvironmentId=d.Environment.Id,Id=id,Lifecycle=i==repairs+1?"Active":"Repair",Notes="notes-canary",Version=1,UpdatedAt=DateTimeOffset.UtcNow});
        }
        db.DirectoryObjects.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Generation=generation,Kind="User",Name="visible-user",DistinguishedName="CN=user,DC=test",ParentOuId=ou});
        db.DeviceAssets.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Lifecycle="Repair",Version=1,UpdatedAt=DateTimeOffset.UtcNow}); // orphan never counted
        await db.SaveChangesAsync();return(d,ou,generation);
    }
    private static string Path(TestData d)=>$"/api/v1/environments/{d.Environment.Id}/dashboard";
    [Fact]
    public async Task Scoped_counts_lifecycle_and_repair_list_agree_and_missing_metadata_is_unknown()
    {
        var(d,_,_)=await Seed();using var client=fixture.Client(d.ViewerToken);var json=await client.GetFromJsonAsync<JsonElement>(Path(d));
        Assert.Equal(4,json.GetProperty("counts").GetProperty("Computer").GetInt32());Assert.Equal(1,json.GetProperty("counts").GetProperty("User").GetInt32());Assert.Equal(0,json.GetProperty("counts").GetProperty("Group").GetInt32());
        Assert.Equal(2,json.GetProperty("lifecycle").GetProperty("Repair").GetInt32());Assert.Equal(1,json.GetProperty("lifecycle").GetProperty("Unknown").GetInt32());Assert.Equal(1,json.GetProperty("lifecycle").GetProperty("Active").GetInt32());Assert.Equal(2,json.GetProperty("repairs").GetArrayLength());
        Assert.DoesNotContain("hidden-canary",json.ToString());Assert.DoesNotContain("notes-canary",json.ToString());Assert.Equal("Unknown",json.GetProperty("health").GetString());
    }
    [Fact]
    public async Task No_grants_and_revocation_do_not_leak_counts()
    {
        var(d,_,_)=await Seed();using var client=fixture.Client(d.RequesterToken);var json=await client.GetFromJsonAsync<JsonElement>(Path(d));Assert.Equal(0,json.GetProperty("counts").GetProperty("Computer").GetInt32());Assert.Empty(json.GetProperty("repairs").EnumerateArray());
        await using var db=Db();var permission=await db.RolePermissions.SingleAsync(x=>x.EnvironmentId==d.Environment.Id && x.Permission==PermissionCatalog.ComputerView);db.Remove(permission);await db.SaveChangesAsync();using var viewer=fixture.Client(d.ViewerToken);Assert.Equal(0,(await viewer.GetFromJsonAsync<JsonElement>(Path(d))).GetProperty("lifecycle").GetProperty("Repair").GetInt32());
        Assert.Equal(HttpStatusCode.NotFound,(await viewer.GetAsync($"/api/v1/environments/{d.OtherEnvironment.Id}/dashboard")).StatusCode);
    }
    [Theory]
    [InlineData("Failed",0)] [InlineData("Ready",20)]
    public async Task Failed_or_stale_snapshot_never_returns_preserved_counts(string status,int minutes)
    {
        var(d,_,_)=await Seed();await using var db=Db();var sync=await db.DirectorySync.SingleAsync(x=>x.EnvironmentId==d.Environment.Id);sync.Status=status;sync.CompletedAt=DateTimeOffset.UtcNow.AddMinutes(-minutes);await db.SaveChangesAsync();using var client=fixture.Client(d.ViewerToken);Assert.Equal(HttpStatusCode.ServiceUnavailable,(await client.GetAsync(Path(d))).StatusCode);
    }
    [Fact]
    public async Task Repair_pages_are_scoped_cursor_bound_and_restart_on_generation_change()
    {
        var(d,_,_)=await Seed(52);using var client=fixture.Client(d.ViewerToken);var path=Path(d);var first=await client.GetFromJsonAsync<JsonElement>(path);Assert.Equal(52,first.GetProperty("lifecycle").GetProperty("Repair").GetInt32());Assert.Equal(50,first.GetProperty("repairs").GetArrayLength());
        var cursor=Uri.EscapeDataString(first.GetProperty("nextCursor").GetString()!);var second=await client.GetFromJsonAsync<JsonElement>(path+"?cursor="+cursor);Assert.Equal(2,second.GetProperty("repairs").GetArrayLength());
        Assert.Equal(HttpStatusCode.BadRequest,(await client.GetAsync(path+"?cursor=bad")).StatusCode);using(var other=fixture.Client(d.RequesterToken))Assert.Equal(HttpStatusCode.BadRequest,(await other.GetAsync(path+"?cursor="+cursor)).StatusCode);
        await using var db=Db();var sync=await db.DirectorySync.SingleAsync(x=>x.EnvironmentId==d.Environment.Id);sync.Generation=Guid.NewGuid();await db.SaveChangesAsync();Assert.Equal(HttpStatusCode.Conflict,(await client.GetAsync(path+"?cursor="+cursor)).StatusCode);
    }
    [Fact]
    public async Task Foreign_asset_with_same_guid_cannot_affect_lifecycle()
    {
        var(d,_,_)=await Seed();await using var db=Db();var missing=await db.DirectoryObjects.Where(x=>x.EnvironmentId==d.Environment.Id && x.Kind=="Computer" && !db.DeviceAssets.Any(a=>a.EnvironmentId==x.EnvironmentId && a.Id==x.Id)).SingleAsync();
        db.DeviceAssets.Add(new(){EnvironmentId=d.OtherEnvironment.Id,Id=missing.Id,Lifecycle="Repair",Version=1,UpdatedAt=DateTimeOffset.UtcNow});await db.SaveChangesAsync();
        using var client=fixture.Client(d.ViewerToken);var json=await client.GetFromJsonAsync<JsonElement>(Path(d));Assert.Equal(1,json.GetProperty("lifecycle").GetProperty("Unknown").GetInt32());Assert.Equal(2,json.GetProperty("lifecycle").GetProperty("Repair").GetInt32());Assert.Equal("Unknown",json.GetProperty("agent").GetString());
    }}
