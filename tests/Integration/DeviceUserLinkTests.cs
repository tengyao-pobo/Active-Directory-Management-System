namespace ItManagement.IntegrationTests;
[Collection(nameof(PostgresApiCollection))]
public sealed class DeviceUserLinkTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db(bool runtime = false) => new(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(Environment.GetEnvironmentVariable(runtime ? "CONSOLE_TEST_RUNTIME_DB" : "CONSOLE_TEST_DB")!).Options);
    private async Task<(TestData Data, Guid Computer, Guid User, Guid Hidden)> Seed()
    {
        var data = await fixture.SeedAsync(); var computer = Guid.NewGuid(); var user = Guid.NewGuid(); var hidden = Guid.NewGuid(); var ou = Guid.NewGuid(); var gen = Guid.NewGuid();
        await using var db = Db();
        db.DirectorySync.Add(new() { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Generation = gen, Status = "Ready", CompletedAt = DateTimeOffset.UtcNow });
        foreach (var (id,kind) in new[] { (computer,"Computer"), (user,"User"), (hidden,"User") })
            db.DirectoryObjects.Add(new() { EnvironmentId = data.Environment.Id, Id = id, Generation = gen, Kind = kind, Name = kind+id, DistinguishedName = "CN=synthetic,DC=test", ParentOuId = id == hidden ? Guid.NewGuid() : ou, OuAncestry = [] });
        var role = new Role { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Name="links" }; var scope = new Scope { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Kind = ScopeKind.OrganizationalUnit, Value = ou.ToString() };
        db.AddRange(role,scope,new RoleAssignment { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), PrincipalId = data.Viewer.Id, RoleId = role.Id, ScopeId = scope.Id });
        foreach(var permission in new[] {PermissionCatalog.ComputerView,PermissionCatalog.UserView,PermissionCatalog.AssetEdit}) db.RolePermissions.Add(new() { EnvironmentId=data.Environment.Id,RoleId=role.Id,Permission=permission });
        await db.SaveChangesAsync(); return(data,computer,user,hidden);
    }
    private static string ComputerPath(TestData d, Guid id) => $"/api/v1/environments/{d.Environment.Id}/devices/{id}/user";
    private static string UserPath(TestData d, Guid id) => $"/api/v1/environments/{d.Environment.Id}/users/{id}/devices";
    private static async Task<HttpResponseMessage> Put(HttpClient client,string path,Guid? user,string version="0")
    {
        using var r=await client.MutationAsync(HttpMethod.Put,path,new {userId=user});r.Headers.TryAddWithoutValidation("If-Match",$"\"{version}\"");return await client.SendAsync(r);
    }
    [Fact]
    public async Task Assign_reverse_lookup_clear_and_monotonic_version()
    {
        var(d,c,u,_)=await Seed();using var client=fixture.Client(d.ViewerToken);var path=ComputerPath(d,c);
        var assigned=await Put(client,path,u);Assert.Equal(HttpStatusCode.NoContent,assigned.StatusCode);Assert.Equal("\"1\"",assigned.Headers.ETag!.Tag);
        var current=await client.GetFromJsonAsync<JsonElement>(path);Assert.Equal(u,current.GetProperty("user").GetProperty("id").GetGuid());Assert.Equal("Manual",current.GetProperty("source").GetString());
        Assert.Single((await client.GetFromJsonAsync<JsonElement>(UserPath(d,u))).GetProperty("items").EnumerateArray());
        Assert.Equal(HttpStatusCode.NoContent,(await Put(client,path,null,"1")).StatusCode);
        Assert.Empty((await client.GetFromJsonAsync<JsonElement>(UserPath(d,u))).GetProperty("items").EnumerateArray());
        Assert.Equal(HttpStatusCode.PreconditionFailed,(await Put(client,path,u)).StatusCode);
        await using var db=Db();var row=await db.DeviceUserLinks.SingleAsync(x=>x.Id==c);Assert.Null(row.UserId);Assert.Equal(2,row.Version);Assert.Equal(2,await db.Audit.CountAsync(x=>x.EnvironmentId==d.Environment.Id && x.Action=="Device.PrimaryUserUpdated"));
    }
    [Fact]
    public async Task Hidden_previous_or_next_user_returns_no_identity_or_etag_and_no_write()
    {
        var(d,c,u,h)=await Seed();using var client=fixture.Client(d.ViewerToken);var path=ComputerPath(d,c);
        Assert.Equal(HttpStatusCode.NotFound,(await Put(client,path,h)).StatusCode);
        await using var db=Db();db.DeviceUserLinks.Add(new(){EnvironmentId=d.Environment.Id,Id=c,UserId=h,Version=1,UpdatedAt=DateTimeOffset.UtcNow});await db.SaveChangesAsync();
        var get=await client.GetAsync(path);Assert.Equal(HttpStatusCode.NotFound,get.StatusCode);Assert.Null(get.Headers.ETag);Assert.Empty(await get.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.NotFound,(await Put(client,path,u,"1")).StatusCode);Assert.Equal(HttpStatusCode.NotFound,(await Put(client,path,null,"1")).StatusCode);
        Assert.Equal(h,(await db.DeviceUserLinks.SingleAsync(x=>x.Id==c)).UserId);
    }
    [Fact]
    public async Task Missing_field_csrf_and_edit_permission_do_not_clear()
    {
        var(d,c,u,_)=await Seed();using var client=fixture.Client(d.ViewerToken);var path=ComputerPath(d,c);
        using var missing=await client.MutationAsync(HttpMethod.Put,path,new{});missing.Headers.TryAddWithoutValidation("If-Match","\"0\"");Assert.Equal(HttpStatusCode.BadRequest,(await client.SendAsync(missing)).StatusCode);
        using var noCsrf=new HttpRequestMessage(HttpMethod.Put,path){Content=JsonContent.Create(new{userId=u})};noCsrf.Headers.Add("Origin","https://localhost:7443");Assert.Equal(HttpStatusCode.BadRequest,(await client.SendAsync(noCsrf)).StatusCode);
        await using var db=Db();var permission=await db.RolePermissions.SingleAsync(x=>x.EnvironmentId==d.Environment.Id && x.Permission==PermissionCatalog.AssetEdit);db.Remove(permission);await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.Forbidden,(await Put(client,path,u)).StatusCode);Assert.False(await db.DeviceUserLinks.AnyAsync(x=>x.Id==c));
    }
    [Fact]
    public async Task Rls_and_reverse_query_hide_foreign_and_out_of_scope_computers()
    {
        var(d,c,u,_)=await Seed();using var client=fixture.Client(d.ViewerToken);Assert.Equal(HttpStatusCode.NoContent,(await Put(client,ComputerPath(d,c),u)).StatusCode);
        await using(var db=Db()){var computer=await db.DirectoryObjects.SingleAsync(x=>x.Id==c);computer.ParentOuId=Guid.NewGuid();await db.SaveChangesAsync();}
        Assert.Empty((await client.GetFromJsonAsync<JsonElement>(UserPath(d,u))).GetProperty("items").EnumerateArray());
        await using var runtime=Db(true);Assert.Empty(await runtime.DeviceUserLinks.ToListAsync());await using var tx=await runtime.BeginEnvironment(d.OtherEnvironment.Id,d.Viewer.Id,CancellationToken.None);Assert.Empty(await runtime.DeviceUserLinks.ToListAsync());
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Concurrent_create_and_replace_have_one_winner(bool existing)
    {
        var(d,c,u,_)=await Seed();using var a=fixture.Client(d.ViewerToken);using var b=fixture.Client(d.ViewerToken);var path=ComputerPath(d,c);
        if(existing)Assert.Equal(HttpStatusCode.NoContent,(await Put(a,path,u)).StatusCode);
        var results=await Task.WhenAll(Put(a,path,u,existing?"1":"0"),Put(b,path,u,existing?"1":"0"));Assert.Single(results,r=>r.StatusCode==HttpStatusCode.NoContent);Assert.Single(results,r=>r.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.PreconditionFailed);
        await using var db=Db();Assert.Equal(existing?2:1,await db.Audit.CountAsync(x=>x.EnvironmentId==d.Environment.Id && x.Action=="Device.PrimaryUserUpdated"));
    }
    [Fact]
    public async Task Cursor_is_bound_to_user_and_generation()
    {
        var(d,c,u,_)=await Seed();await using var db=Db();var original=await db.DirectoryObjects.SingleAsync(x=>x.Id==c);
        for(var i=0;i<52;i++){var id=Guid.NewGuid();db.DirectoryObjects.Add(new(){EnvironmentId=d.Environment.Id,Id=id,Generation=original.Generation,Kind="Computer",Name="paged",DistinguishedName="CN=paged,DC=test",ParentOuId=original.ParentOuId});db.DeviceUserLinks.Add(new(){EnvironmentId=d.Environment.Id,Id=id,UserId=u,Version=1,UpdatedAt=DateTimeOffset.UtcNow});}await db.SaveChangesAsync();
        using var client=fixture.Client(d.ViewerToken);var path=UserPath(d,u);var first=await client.GetFromJsonAsync<JsonElement>(path);Assert.Equal(50,first.GetProperty("items").GetArrayLength());var cursor=Uri.EscapeDataString(first.GetProperty("nextCursor").GetString()!);
        Assert.Equal(2,(await client.GetFromJsonAsync<JsonElement>(path+"?cursor="+cursor)).GetProperty("items").GetArrayLength());Assert.Equal(HttpStatusCode.BadRequest,(await client.GetAsync(path+"?cursor=bad")).StatusCode);
        var otherUser=Guid.NewGuid();db.DirectoryObjects.Add(new(){EnvironmentId=d.Environment.Id,Id=otherUser,Generation=original.Generation,Kind="User",Name="other",DistinguishedName="CN=other,DC=test",ParentOuId=original.ParentOuId});
        var roleId=await db.RolePermissions.Where(x=>x.EnvironmentId==d.Environment.Id && x.Permission==PermissionCatalog.UserView).Select(x=>x.RoleId).SingleAsync();var assignment=await db.Assignments.SingleAsync(x=>x.EnvironmentId==d.Environment.Id && x.RoleId==roleId);
        db.Assignments.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),PrincipalId=d.Reviewer.Id,RoleId=roleId,ScopeId=assignment.ScopeId});await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.BadRequest,(await client.GetAsync(UserPath(d,otherUser)+"?cursor="+cursor)).StatusCode);
        using(var reviewer=fixture.Client(d.ReviewerToken))Assert.Equal(HttpStatusCode.BadRequest,(await reviewer.GetAsync(path+"?cursor="+cursor)).StatusCode);
        var sync=await db.DirectorySync.SingleAsync(x=>x.EnvironmentId==d.Environment.Id);sync.Generation=Guid.NewGuid();foreach(var obj in await db.DirectoryObjects.Where(x=>x.EnvironmentId==d.Environment.Id).ToListAsync())obj.Generation=sync.Generation;await db.SaveChangesAsync();Assert.Equal(HttpStatusCode.Conflict,(await client.GetAsync(path+"?cursor="+cursor)).StatusCode);
    }
}
