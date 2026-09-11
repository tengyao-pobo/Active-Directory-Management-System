namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class SavedFilterTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Db(bool runtime=false)=>new(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(
        Environment.GetEnvironmentVariable(runtime?"CONSOLE_TEST_RUNTIME_DB":"CONSOLE_TEST_DB")!).Options);
    private static string Root(TestData d)=>$"/api/v1/environments/{d.Environment.Id}/saved-filters";
    private static object Input(string name="My users",string kind="User",string search="",Guid? tagId=null)=>new{schemaVersion=1,name,kind,search,tagId};

    [Fact]
    public async Task Personal_crud_normalizes_and_enforces_closed_schema_and_etags()
    {
        var d=await fixture.SeedAsync();using var owner=fixture.Client(d.RequesterToken);
        var created=await Post(owner,Root(d),Input("  My users  ",search:"  literal  "));Assert.Equal(HttpStatusCode.Created,created.StatusCode);Assert.Equal("\"1\"",created.Headers.ETag!.Tag);
        var item=await created.Content.ReadFromJsonAsync<JsonElement>();var id=item.GetProperty("id").GetGuid();Assert.Equal("My users",item.GetProperty("name").GetString());Assert.Equal("literal",item.GetProperty("search").GetString());
        Assert.Single((await owner.GetFromJsonAsync<JsonElement>(Root(d))).GetProperty("items").EnumerateArray());
        Assert.Equal(HttpStatusCode.PreconditionRequired,(await Put(owner,$"{Root(d)}/{id}",Input())).StatusCode);
        Assert.Equal(HttpStatusCode.PreconditionFailed,(await Put(owner,$"{Root(d)}/{id}",Input(),2)).StatusCode);
        var updated=await Put(owner,$"{Root(d)}/{id}",Input("Renamed","Group","needle"),1);Assert.Equal(HttpStatusCode.OK,updated.StatusCode);Assert.Equal("\"2\"",updated.Headers.ETag!.Tag);Assert.Equal(item.GetProperty("createdAt").GetString(),(await updated.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("createdAt").GetString());
        Assert.Equal(HttpStatusCode.BadRequest,(await Post(owner,Root(d),new{schemaVersion=2,name="bad",kind="User",search=""})).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,(await Post(owner,Root(d),new{schemaVersion=1,name="bad",kind="User",search="",principalId=d.Viewer.Id})).StatusCode);
        Assert.Equal(HttpStatusCode.PreconditionRequired,(await Delete(owner,$"{Root(d)}/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.PreconditionFailed,(await Delete(owner,$"{Root(d)}/{id}",1)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent,(await Delete(owner,$"{Root(d)}/{id}",2)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,(await owner.GetAsync($"{Root(d)}/{id}")).StatusCode);
    }

    [Fact]
    public async Task Tag_definition_requires_computer_and_same_environment_but_accepts_archived_tag()
    {
        var d=await fixture.SeedAsync();var active=Tag(d.Environment.Id,"VIP",d.Requester.Id);var archived=Tag(d.Environment.Id,"Finance",d.Requester.Id);archived.ArchivedAt=DateTimeOffset.UtcNow;
        var foreign=Tag(d.OtherEnvironment.Id,"Shared",d.Requester.Id);await using(var db=Db()){db.DeviceTags.AddRange(active,archived,foreign);await db.SaveChangesAsync();}
        using var owner=fixture.Client(d.RequesterToken);
        Assert.Equal(HttpStatusCode.Created,(await Post(owner,Root(d),Input(tagId:active.Id,kind:"Computer"))).StatusCode);
        Assert.Equal(HttpStatusCode.Created,(await Post(owner,Root(d),Input("Archived","Computer","",archived.Id))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,(await Post(owner,Root(d),Input(tagId:active.Id))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,(await Post(owner,Root(d),Input(tagId:foreign.Id,kind:"Computer"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,(await Post(owner,Root(d),Input(tagId:Guid.NewGuid(),kind:"Computer"))).StatusCode);
    }

    [Fact]
    public async Task Personal_identity_active_membership_and_runtime_rls_fail_closed()
    {
        var d=await fixture.SeedAsync();using var owner=fixture.Client(d.RequesterToken);var item=await (await Post(owner,Root(d),Input())).Content.ReadFromJsonAsync<JsonElement>();var id=item.GetProperty("id").GetGuid();
        using var viewer=fixture.Client(d.ViewerToken);Assert.Empty((await viewer.GetFromJsonAsync<JsonElement>(Root(d))).GetProperty("items").EnumerateArray());Assert.Equal(HttpStatusCode.NotFound,(await viewer.GetAsync($"{Root(d)}/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,(await owner.GetAsync($"/api/v1/environments/{d.OtherEnvironment.Id}/saved-filters/{id}")).StatusCode);
        await using(var runtime=Db(true)){Assert.Empty(await runtime.SavedFilters.ToListAsync());await using var tx=await runtime.BeginEnvironment(d.Environment.Id,d.Viewer.Id,CancellationToken.None);Assert.Empty(await runtime.SavedFilters.ToListAsync());}
        await using(var db=Db())await db.Memberships.Where(x=>x.EnvironmentId==d.Environment.Id&&x.PrincipalId==d.Requester.Id).ExecuteUpdateAsync(x=>x.SetProperty(m=>m.Active,false));
        Assert.Equal(HttpStatusCode.NotFound,(await owner.GetAsync(Root(d))).StatusCode);
        await using(var runtime=Db(true)){await using var tx=await runtime.BeginEnvironment(d.Environment.Id,d.Requester.Id,CancellationToken.None);Assert.Empty(await runtime.SavedFilters.ToListAsync());}
    }

    [Fact]
    public async Task Results_use_current_scopes_and_literal_search_without_stored_authority()
    {
        var d=await fixture.SeedAsync();var generation=Guid.NewGuid();var visible=Guid.NewGuid();var hidden=Guid.NewGuid();var role=Guid.NewGuid();
        await using(var db=Db())
        {
            db.DirectorySync.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Generation=generation,Status="Ready",CompletedAt=DateTimeOffset.UtcNow});
            db.DirectoryObjects.AddRange(new DirectoryObjectRecord{EnvironmentId=d.Environment.Id,Id=visible,Generation=generation,Kind="User",Name="literal-%_-match",DistinguishedName="CN=visible,DC=test"},new DirectoryObjectRecord{EnvironmentId=d.Environment.Id,Id=hidden,Generation=generation,Kind="User",Name="literal-other",DistinguishedName="CN=hidden,DC=test"});
            db.Roles.Add(new(){EnvironmentId=d.Environment.Id,Id=role,Name="saved-filter-reader"});db.RolePermissions.Add(new(){EnvironmentId=d.Environment.Id,RoleId=role,Permission=PermissionCatalog.UserView});db.Assignments.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),PrincipalId=d.Viewer.Id,RoleId=role,ScopeId=d.AllScopeId});await db.SaveChangesAsync();
        }
        using var viewer=fixture.Client(d.ViewerToken);var item=await (await Post(viewer,Root(d),Input(search:"%_"))).Content.ReadFromJsonAsync<JsonElement>();var id=item.GetProperty("id").GetGuid();
        var result=await viewer.GetFromJsonAsync<JsonElement>($"{Root(d)}/{id}/results?filterVersion=1");Assert.Equal(visible,Assert.Single(result.GetProperty("items").EnumerateArray()).GetProperty("id").GetGuid());Assert.False(result.TryGetProperty("total",out _));
        await using(var db=Db())await db.RolePermissions.Where(x=>x.EnvironmentId==d.Environment.Id&&x.RoleId==role).ExecuteDeleteAsync();
        Assert.Empty((await viewer.GetFromJsonAsync<JsonElement>($"{Root(d)}/{id}/results?filterVersion=1")).GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Tagged_computer_results_intersect_current_scope_and_allow_archived_tag()
    {
        var d=await fixture.SeedAsync();var generation=Guid.NewGuid();var allowedOu=Guid.NewGuid();var hiddenOu=Guid.NewGuid();var visible=Guid.NewGuid();var hidden=Guid.NewGuid();var role=Guid.NewGuid();var scope=Guid.NewGuid();var tag=Tag(d.Environment.Id,"VIP",d.Requester.Id);
        await using(var db=Db())
        {
            db.DirectorySync.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Generation=generation,Status="Ready",CompletedAt=DateTimeOffset.UtcNow});
            db.DirectoryObjects.AddRange(new DirectoryObjectRecord{EnvironmentId=d.Environment.Id,Id=visible,Generation=generation,Kind="Computer",Name="visible",DistinguishedName="CN=visible,DC=test",ParentOuId=allowedOu},new DirectoryObjectRecord{EnvironmentId=d.Environment.Id,Id=hidden,Generation=generation,Kind="Computer",Name="hidden-canary",DistinguishedName="CN=hidden,DC=test",ParentOuId=hiddenOu});
            db.DeviceTags.Add(tag);db.DeviceTagAssignments.AddRange(new DeviceTagAssignment{EnvironmentId=d.Environment.Id,TagId=tag.Id,ObjectId=visible,CreatedAt=DateTimeOffset.UtcNow,CreatedBy=d.Requester.Id},new DeviceTagAssignment{EnvironmentId=d.Environment.Id,TagId=tag.Id,ObjectId=hidden,CreatedAt=DateTimeOffset.UtcNow,CreatedBy=d.Requester.Id});
            db.Roles.Add(new(){EnvironmentId=d.Environment.Id,Id=role,Name="tagged-filter-reader"});db.Scopes.Add(new(){EnvironmentId=d.Environment.Id,Id=scope,Kind=ScopeKind.OrganizationalUnit,Value=allowedOu.ToString("D")});db.RolePermissions.Add(new(){EnvironmentId=d.Environment.Id,RoleId=role,Permission=PermissionCatalog.ComputerView});db.Assignments.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),PrincipalId=d.Viewer.Id,RoleId=role,ScopeId=scope});await db.SaveChangesAsync();
        }
        using var viewer=fixture.Client(d.ViewerToken);var filter=await (await Post(viewer,Root(d),Input("Tagged","Computer","",tag.Id))).Content.ReadFromJsonAsync<JsonElement>();var id=filter.GetProperty("id").GetGuid();
        await using(var db=Db())await db.DeviceTags.Where(x=>x.EnvironmentId==d.Environment.Id&&x.Id==tag.Id).ExecuteUpdateAsync(x=>x.SetProperty(t=>t.ArchivedAt,DateTimeOffset.UtcNow));
        var result=await viewer.GetFromJsonAsync<JsonElement>($"{Root(d)}/{id}/results?filterVersion=1");Assert.Equal(visible,Assert.Single(result.GetProperty("items").EnumerateArray()).GetProperty("id").GetGuid());Assert.DoesNotContain("hidden-canary",result.GetRawText(),StringComparison.Ordinal);
    }

    [Fact]
    public async Task Result_cursor_binds_filter_version_environment_version_and_generation()
    {
        var d=await SeedResultsAsync();using var viewer=fixture.Client(d.Data.ViewerToken);var item=await (await Post(viewer,Root(d.Data),Input())).Content.ReadFromJsonAsync<JsonElement>();var id=item.GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.BadRequest,(await viewer.GetAsync($"{Root(d.Data)}/{id}/results")).StatusCode);
        var first=await viewer.GetFromJsonAsync<JsonElement>($"{Root(d.Data)}/{id}/results?filterVersion=1&limit=1");var cursor=Uri.EscapeDataString(first.GetProperty("nextCursor").GetString()!);
        var other=await (await Post(viewer,Root(d.Data),Input("Other filter"))).Content.ReadFromJsonAsync<JsonElement>();var otherId=other.GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.BadRequest,(await viewer.GetAsync($"{Root(d.Data)}/{otherId}/results?filterVersion=1&limit=1&cursor={cursor}")).StatusCode);
        using(var requester=fixture.Client(d.Data.RequesterToken))Assert.Equal(HttpStatusCode.NotFound,(await requester.GetAsync($"{Root(d.Data)}/{id}/results?filterVersion=1&limit=1&cursor={cursor}")).StatusCode);
        await fixture.BumpEnvironmentVersionAsync(d.Data.Environment.Id);var changed=await viewer.GetAsync($"{Root(d.Data)}/{id}/results?filterVersion=1&limit=1&cursor={cursor}");Assert.Equal(HttpStatusCode.Conflict,changed.StatusCode);Assert.Equal("AuthorizationSnapshotChanged",(await changed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
        await using(var db=Db()){await db.Environments.Where(x=>x.Id==d.Data.Environment.Id).ExecuteUpdateAsync(x=>x.SetProperty(e=>e.Version,1));await db.DirectorySync.Where(x=>x.EnvironmentId==d.Data.Environment.Id).ExecuteUpdateAsync(x=>x.SetProperty(s=>s.Generation,Guid.NewGuid()));}
        changed=await viewer.GetAsync($"{Root(d.Data)}/{id}/results?filterVersion=1&limit=1&cursor={cursor}");Assert.Equal("DirectorySnapshotChanged",(await changed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
        await using(var db=Db())await db.SavedFilters.Where(x=>x.EnvironmentId==d.Data.Environment.Id&&x.Id==id).ExecuteUpdateAsync(x=>x.SetProperty(f=>f.Version,2).SetProperty(f=>f.Search,"changed"));
        changed=await viewer.GetAsync($"{Root(d.Data)}/{id}/results?filterVersion=1");Assert.Equal(HttpStatusCode.Conflict,changed.StatusCode);Assert.Equal("SavedFilterChanged",(await changed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
    }

    [Fact]
    public async Task Fifty_row_cap_is_serialized_under_concurrent_create()
    {
        var d=await fixture.SeedAsync();await using(var db=Db()){var now=DateTimeOffset.UtcNow;db.SavedFilters.AddRange(Enumerable.Range(0,49).Select(i=>new SavedFilter{EnvironmentId=d.Environment.Id,PrincipalId=d.Viewer.Id,Id=Guid.NewGuid(),Name=$"filter-{i}",Kind="User",Search="",CreatedAt=now,UpdatedAt=now}));await db.SaveChangesAsync();}
        using var a=fixture.Client(d.ViewerToken);using var b=fixture.Client(d.ViewerToken);var responses=await Task.WhenAll(Post(a,Root(d),Input("concurrent-a")),Post(b,Root(d),Input("concurrent-b")));
        Assert.Single(responses,x=>x.StatusCode==HttpStatusCode.Created);Assert.Single(responses,x=>x.StatusCode==HttpStatusCode.Conflict);await using var verify=Db();Assert.Equal(50,await verify.SavedFilters.CountAsync(x=>x.EnvironmentId==d.Environment.Id&&x.PrincipalId==d.Viewer.Id));
    }

    [Fact]
    public async Task Runtime_can_update_only_mutable_columns()
    {
        var d=await fixture.SeedAsync();using var viewer=fixture.Client(d.ViewerToken);var item=await (await Post(viewer,Root(d),Input())).Content.ReadFromJsonAsync<JsonElement>();var id=item.GetProperty("id").GetGuid();
        await using(var runtime=Db(true)){await using var tx=await runtime.BeginEnvironment(d.Environment.Id,d.Viewer.Id,CancellationToken.None);runtime.SavedFilters.Add(new(){EnvironmentId=d.Environment.Id,PrincipalId=d.Viewer.Id,Id=Guid.NewGuid(),Name=" not-normalized ",Kind="User",Search="",CreatedAt=DateTimeOffset.UtcNow,UpdatedAt=DateTimeOffset.UtcNow});var invalid=await Assert.ThrowsAsync<DbUpdateException>(()=>runtime.SaveChangesAsync());Assert.Equal("23514",Assert.IsType<Npgsql.PostgresException>(invalid.InnerException).SqlState);}
        await using(var runtime=Db(true)){await using var tx=await runtime.BeginEnvironment(d.Environment.Id,d.Viewer.Id,CancellationToken.None);var error=await Assert.ThrowsAsync<Npgsql.PostgresException>(()=>runtime.SavedFilters.Where(x=>x.EnvironmentId==d.Environment.Id&&x.Id==id).ExecuteUpdateAsync(x=>x.SetProperty(f=>f.CreatedAt,DateTimeOffset.UtcNow.AddDays(-1))));Assert.Equal("42501",error.SqlState);}
    }

    private async Task<(TestData Data,Guid[] Ids)> SeedResultsAsync()
    {
        var d=await fixture.SeedAsync();var generation=Guid.NewGuid();var ids=Enumerable.Range(0,3).Select(_=>Guid.NewGuid()).ToArray();var role=Guid.NewGuid();await using var db=Db();db.DirectorySync.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),Generation=generation,Status="Ready",CompletedAt=DateTimeOffset.UtcNow});db.DirectoryObjects.AddRange(ids.Select((id,i)=>new DirectoryObjectRecord{EnvironmentId=d.Environment.Id,Id=id,Generation=generation,Kind="User",Name=$"user-{i}",DistinguishedName=$"CN=user-{i},DC=test"}));db.Roles.Add(new(){EnvironmentId=d.Environment.Id,Id=role,Name="saved-results"});db.RolePermissions.Add(new(){EnvironmentId=d.Environment.Id,RoleId=role,Permission=PermissionCatalog.UserView});db.Assignments.Add(new(){EnvironmentId=d.Environment.Id,Id=Guid.NewGuid(),PrincipalId=d.Viewer.Id,RoleId=role,ScopeId=d.AllScopeId});await db.SaveChangesAsync();return(d,ids);
    }
    private static DeviceTag Tag(Guid env,string key,Guid actor){var now=DateTimeOffset.UtcNow;return new(){EnvironmentId=env,Id=Guid.NewGuid(),Key=key,CreatedAt=now,UpdatedAt=now,CreatedBy=actor,UpdatedBy=actor};}
    private static async Task<HttpResponseMessage> Post(HttpClient c,string path,object body){using var r=await c.MutationAsync(HttpMethod.Post,path,body);return await c.SendAsync(r);}
    private static async Task<HttpResponseMessage> Put(HttpClient c,string path,object body,long? version=null){using var r=await c.MutationAsync(HttpMethod.Put,path,body);if(version is not null)r.Headers.TryAddWithoutValidation("If-Match",$"\"{version}\"");return await c.SendAsync(r);}
    private static async Task<HttpResponseMessage> Delete(HttpClient c,string path,long? version=null){using var r=await c.MutationAsync(HttpMethod.Delete,path,new{});if(version is not null)r.Headers.TryAddWithoutValidation("If-Match",$"\"{version}\"");return await c.SendAsync(r);}
}
