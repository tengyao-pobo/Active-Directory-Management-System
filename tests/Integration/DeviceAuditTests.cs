namespace ItManagement.IntegrationTests;
[Collection(nameof(PostgresApiCollection))]
public sealed class DeviceAuditTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db()=>new(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Options);
    private async Task<(TestData Data,Guid Computer,Guid Ou)> Seed(bool computerView=true,bool auditView=true)
    {
        var d=await fixture.SeedAsync();var c=Guid.NewGuid();var ou=Guid.NewGuid();var generation=Guid.NewGuid();await using var db=Db();
        db.RolePermissions.RemoveRange(await db.RolePermissions.Where(x=>x.EnvironmentId==d.Environment.Id && x.Permission==PermissionCatalog.AuditView).ToListAsync());
        db.DirectorySync.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Generation=generation,Status="Ready",CompletedAt=DateTimeOffset.UtcNow});
        db.DirectoryObjects.Add(new(){EnvironmentId=d.Environment.Id,Id=c,Generation=generation,Kind="Computer",Name="audit-device",DistinguishedName="CN=device,DC=test",ParentOuId=ou});
        var role=new Role{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Name="device-audit"};var scope=new Scope{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Kind=ScopeKind.OrganizationalUnit,Value=ou.ToString()};db.AddRange(role,scope,new RoleAssignment{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),PrincipalId=d.Viewer.Id,RoleId=role.Id,ScopeId=scope.Id});
        if(computerView)db.RolePermissions.Add(new(){EnvironmentId=d.Environment.Id,RoleId=role.Id,Permission=PermissionCatalog.ComputerView});if(auditView)db.RolePermissions.Add(new(){EnvironmentId=d.Environment.Id,RoleId=role.Id,Permission=PermissionCatalog.AuditView});
        var at=DateTimeOffset.UtcNow;
        for(int i=0;i<52;i++)db.Audit.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),TargetId=c.ToString(),Action="Device.AssetUpdated",Result="Success",Reason="secret-canary",SourceIp="source-canary",ActorId=d.Requester.Id,OccurredAt=at,CorrelationId="correlation-canary"});
        db.Audit.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),TargetId=c.ToString(),Action="Unrelated.Secret",Result="Success",OccurredAt=at});
        db.Audit.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),TargetId=Guid.NewGuid().ToString(),Action="Device.AssetUpdated",Result="Success",OccurredAt=at});
        await db.SaveChangesAsync();return(d,c,ou);
    }
    private static string Path(TestData d,Guid c)=>$"/api/v1/environments/{d.Environment.Id}/devices/{c}/audit";
    [Fact]
    public async Task Scoped_audit_filters_target_action_and_dto_with_stable_tie_pagination()
    {
        var(d,c,_)=await Seed();using var client=fixture.Client(d.ViewerToken);var path=Path(d,c);var first=await client.GetFromJsonAsync<JsonElement>(path);
        Assert.Equal(50,first.GetProperty("items").GetArrayLength());Assert.DoesNotContain("canary",first.ToString());Assert.DoesNotContain("actorId",first.ToString());Assert.DoesNotContain("Unrelated",first.ToString());
        var cursor=Uri.EscapeDataString(first.GetProperty("nextCursor").GetString()!);var second=await client.GetFromJsonAsync<JsonElement>(path+"?cursor="+cursor);Assert.Equal(2,second.GetProperty("items").GetArrayLength());
        var ids=first.GetProperty("items").EnumerateArray().Select(x=>x.GetProperty("id").GetGuid()).ToHashSet();Assert.All(second.GetProperty("items").EnumerateArray(),x=>Assert.DoesNotContain(x.GetProperty("id").GetGuid(),ids));
        Assert.Equal(HttpStatusCode.BadRequest,(await client.GetAsync(path+"?cursor=bad")).StatusCode);
        await using var db=Db();var sync=await db.DirectorySync.SingleAsync(x=>x.EnvironmentId==d.Environment.Id);var row=await db.DirectoryObjects.SingleAsync(x=>x.Id==c);sync.Generation=Guid.NewGuid();row.Generation=sync.Generation;await db.SaveChangesAsync();Assert.Equal(HttpStatusCode.Conflict,(await client.GetAsync(path+"?cursor="+cursor)).StatusCode);
    }
    [Theory]
    [InlineData(true,false)] [InlineData(false,true)]
    public async Task Either_missing_permission_denies_entire_audit(bool computer,bool audit)
    {
        var(d,c,_)=await Seed(computer,audit);using var client=fixture.Client(d.ViewerToken);var response=await client.GetAsync(Path(d,c));Assert.Equal(HttpStatusCode.NotFound,response.StatusCode);Assert.Empty(await response.Content.ReadAsStringAsync());
    }
    [Fact]
    public async Task Scope_move_stale_and_foreign_environment_fail_closed()
    {
        var(d,c,_)=await Seed();using var client=fixture.Client(d.ViewerToken);await using var db=Db();var row=await db.DirectoryObjects.SingleAsync(x=>x.Id==c);row.ParentOuId=Guid.NewGuid();await db.SaveChangesAsync();Assert.Equal(HttpStatusCode.NotFound,(await client.GetAsync(Path(d,c))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,(await client.GetAsync($"/api/v1/environments/{d.OtherEnvironment.Id}/devices/{c}/audit")).StatusCode);
        var sync=await db.DirectorySync.SingleAsync(x=>x.EnvironmentId==d.Environment.Id);sync.CompletedAt=DateTimeOffset.UtcNow.AddMinutes(-20);await db.SaveChangesAsync();Assert.Equal(HttpStatusCode.ServiceUnavailable,(await client.GetAsync(Path(d,c))).StatusCode);
    }
    [Fact]
    public async Task Disjoint_permission_scopes_do_not_combine_to_authorize_audit()
    {
        var(d,c,_)=await Seed();await using var db=Db();var grant=await db.RolePermissions.SingleAsync(x=>x.EnvironmentId==d.Environment.Id && x.Permission==PermissionCatalog.AuditView);db.RolePermissions.Remove(grant);
        var role=new Role{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Name="other-audit"};var scope=new Scope{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Kind=ScopeKind.OrganizationalUnit,Value=Guid.NewGuid().ToString()};db.AddRange(role,scope,new RoleAssignment{EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),PrincipalId=d.Viewer.Id,RoleId=role.Id,ScopeId=scope.Id},new RolePermission{EnvironmentId=d.Environment.Id,RoleId=role.Id,Permission=PermissionCatalog.AuditView});await db.SaveChangesAsync();
        using var client=fixture.Client(d.ViewerToken);Assert.Equal(HttpStatusCode.NotFound,(await client.GetAsync(Path(d,c))).StatusCode);
    }}
