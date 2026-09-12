namespace ItManagement.IntegrationTests;

[CollectionDefinition(nameof(PostgresApiCollection), DisableParallelization = true)]
public sealed class PostgresApiCollection : ICollectionFixture<PostgresApiFixture>;

[Collection(nameof(PostgresApiCollection))]
public sealed class ApiSecurityBoundaryTests(PostgresApiFixture fixture)
{
    [Fact]
    public async Task Anonymous_requests_cannot_reach_authenticated_api()
    {
        using var client = fixture.Client();

        var health = await client.GetAsync("/health/live");
        var environments = await client.GetAsync("/api/v1/environments");

        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, environments.StatusCode);
    }

    [Fact]
    public async Task Wrong_origin_and_missing_antiforgery_reject_before_plan_mutation()
    {
        var data = await fixture.SeedAsync();
        using var client = fixture.Client(data.RequesterToken);
        var payload = Plan(data.Environment.Version, "boundary test");
        var before = await fixture.PlanCountAsync(data.Environment.Id);

        using var wrongOrigin = new HttpRequestMessage(HttpMethod.Post, PlanPath(data)) { Content = JsonContent.Create(payload) };
        wrongOrigin.Headers.Add("Origin", "https://attacker.invalid");
        var originResponse = await client.SendAsync(wrongOrigin);

        using var csrfMissing = new HttpRequestMessage(HttpMethod.Post, PlanPath(data)) { Content = JsonContent.Create(payload) };
        csrfMissing.Headers.Add("Origin", "https://localhost:7443");
        var csrfResponse = await client.SendAsync(csrfMissing);

        Assert.Equal(HttpStatusCode.Forbidden, originResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, csrfResponse.StatusCode);
        Assert.Equal(before, await fixture.PlanCountAsync(data.Environment.Id));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Expired_or_revoked_opaque_session_is_denied(bool revoked)
    {
        var data = await fixture.SeedAsync();
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await fixture.AddInvalidSessionAsync(data.Viewer.Id, token, revoked);
        using var client = fixture.Client(token);

        var response = await client.GetAsync("/api/v1/session/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Valid_hashed_session_has_only_its_environment_and_read_rights()
    {
        var data = await fixture.SeedAsync();
        using var client = fixture.Client(data.ViewerToken);

        var environments = await client.GetFromJsonAsync<JsonElement>("/api/v1/environments");
        var access = await client.GetFromJsonAsync<JsonElement>($"/api/v1/environments/{data.Environment.Id}/access");
        var other = await client.GetAsync($"/api/v1/environments/{data.OtherEnvironment.Id}/access");

        var items = environments.GetProperty("items").EnumerateArray().ToArray();
        Assert.Single(items);
        Assert.Equal(data.Environment.Id, items[0].GetProperty("id").GetGuid());
        Assert.Contains(PermissionCatalog.EnvironmentView, access.GetProperty("permissions").EnumerateArray().Select(x => x.GetString()));
        Assert.DoesNotContain(PermissionCatalog.RbacManage, access.GetProperty("permissions").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(HttpStatusCode.NotFound, other.StatusCode);
    }

    [Fact]
    public async Task Runtime_rls_requires_the_active_membership_bound_to_the_requested_environment()
    {
        var data = await fixture.SeedAsync();

        var ownRows = await fixture.RuntimeRoleCountAsync(data.Environment.Id, data.Viewer.Id);
        var foreignRows = await fixture.RuntimeRoleCountAsync(data.OtherEnvironment.Id, data.Viewer.Id);
        var missingPrincipalRows = await fixture.RuntimeRoleCountAsync(data.Environment.Id, Guid.NewGuid());
        var unsetContextRows = await fixture.RuntimeRoleCountAsync(null, null);

        Assert.Equal(3, ownRows);
        Assert.Equal(0, foreignRows);
        Assert.Equal(0, missingPrincipalRows);
        Assert.Equal(0, unsetContextRows);
    }

    [Fact]
    public async Task Audit_cursor_pages_same_timestamp_rows_without_repeats_or_omissions()
    {
        var data = await fixture.SeedAsync();
        var expectedIds = await fixture.SeedSameTimestampAuditAsync(data, 5);
        using var client = fixture.Client(data.ViewerToken);
        var actualIds = new List<Guid>();
        string? cursor = null;
        do
        {
            var path = $"/api/v1/environments/{data.Environment.Id}/audit?limit=2";
            if (cursor is not null) path += $"&cursor={Uri.EscapeDataString(cursor)}";
            var page = await client.GetFromJsonAsync<JsonElement>(path);
            actualIds.AddRange(page.GetProperty("items").EnumerateArray().Select(x => x.GetProperty("id").GetGuid()));
            cursor = page.GetProperty("nextCursor").ValueKind == JsonValueKind.Null ? null : page.GetProperty("nextCursor").GetString();
        } while (cursor is not null);

        Assert.Equal(expectedIds.Count, actualIds.Distinct().Count());
        Assert.Equal(expectedIds.Order(), actualIds.Order());
    }

    [Fact]
    public async Task Runtime_database_cannot_mutate_audit_or_map_a_group_to_owner()
    {
        var data = await fixture.SeedAsync();
        var auditId = (await fixture.SeedSameTimestampAuditAsync(data, 1)).Single();

        var update = await fixture.RuntimeAuditMutationErrorAsync(data, auditId, delete: false);
        var delete = await fixture.RuntimeAuditMutationErrorAsync(data, auditId, delete: true);
        var ownerMapping = await fixture.RuntimeOwnerMappingErrorAsync(data);

        Assert.Equal("42501", update);
        Assert.Equal("42501", delete);
        Assert.Equal("23514", ownerMapping);
    }

    [Theory]
    [InlineData(false, true, false)]
    [InlineData(true, true, false)]
    [InlineData(true, true, true)]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(true, false, true)]
    public async Task Runtime_owner_mapping_guard_ignores_temporary_roles_table(bool shadow, bool owner, bool update)
    {
        var data = await fixture.SeedAsync();
        Assert.Equal(owner ? "23514" : "allowed", await fixture.RuntimeOwnerMappingErrorAsync(data, shadow, owner, update));
    }

    [Fact]
    public async Task Approval_requires_a_distinct_operator_and_execution_rejects_version_drift()
    {
        var data = await fixture.SeedAsync();
        using var requester = fixture.Client(data.RequesterToken);
        using var reviewer = fixture.Client(data.ReviewerToken);
        using var create = await requester.MutationAsync(HttpMethod.Post, PlanPath(data), Plan(data.Environment.Version, "two-person approval"));
        using var created = await requester.SendAsync(create);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var plan = JsonDocument.Parse(await created.Content.ReadAsStringAsync()).RootElement;
        var planId = plan.GetProperty("id").GetGuid();
        var planHash = plan.GetProperty("planHash").GetString()!;

        using var selfApproval = await requester.MutationAsync(HttpMethod.Post, ApprovalPath(data, planId), new { planHash });
        using var selfResponse = await requester.SendAsync(selfApproval);
        Assert.Equal(HttpStatusCode.Conflict, selfResponse.StatusCode);
        Assert.Equal("IndependentOperatorRequired", (await selfResponse.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
        var persisted = await fixture.GetPlanAsync(data.Environment.Id, planId);
        Assert.Equal(planHash, persisted.PlanHash);
        // The reviewer approves the immutable plan as it was persisted, not an in-memory-only representation.
        Assert.Equal(planHash, new ChangePlanService().ComputeHash(persisted));

        using var approval = await reviewer.MutationAsync(HttpMethod.Post, ApprovalPath(data, planId), new { planHash });
        using var approved = await reviewer.SendAsync(approval);
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        await fixture.BumpEnvironmentVersionAsync(data.Environment.Id);

        using var execute = await requester.MutationAsync(HttpMethod.Post, ExecutionPath(data, planId), new { });
        using var execution = await requester.SendAsync(execute);
        Assert.Equal(HttpStatusCode.Conflict, execution.StatusCode);
        Assert.Equal("PlanChangedOrExpired", (await execution.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
    }

    [Fact]
    public async Task Distinct_principals_with_same_operator_cannot_approve_each_other()
    {
        var data = await fixture.SeedAsync(sameOperator: true);
        using var requester = fixture.Client(data.RequesterToken);
        using var reviewer = fixture.Client(data.ReviewerToken);
        using var create = await requester.MutationAsync(HttpMethod.Post, PlanPath(data), Plan(data.Environment.Version, "operator separation"));
        using var created = await requester.SendAsync(create);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var plan = JsonDocument.Parse(await created.Content.ReadAsStringAsync()).RootElement;
        using var approval = await reviewer.MutationAsync(HttpMethod.Post, ApprovalPath(data, plan.GetProperty("id").GetGuid()), new { planHash = plan.GetProperty("planHash").GetString() });
        using var response = await reviewer.SendAsync(approval);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("IndependentOperatorRequired", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
    }

    [Fact]
    public async Task Approved_plan_executes_once_with_role_audit_and_outbox_effects()
    {
        var data = await fixture.SeedAsync();
        using var requester = fixture.Client(data.RequesterToken);
        using var reviewer = fixture.Client(data.ReviewerToken);
        var roleName = $"executed-{Guid.NewGuid():N}";
        var payload = new
        {
            change = new { kind = "role.create", name = roleName, permissions = new[] { PermissionCatalog.UserView } },
            expectedVersion = data.Environment.Version,
            reason = "execute exactly once"
        };
        using var create = await requester.MutationAsync(HttpMethod.Post, PlanPath(data), payload);
        using var created = await requester.SendAsync(create);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var plan = JsonDocument.Parse(await created.Content.ReadAsStringAsync()).RootElement;
        var planId = plan.GetProperty("id").GetGuid();
        var planHash = plan.GetProperty("planHash").GetString()!;
        using var approve = await reviewer.MutationAsync(HttpMethod.Post, ApprovalPath(data, planId), new { planHash });
        Assert.Equal(HttpStatusCode.OK, (await reviewer.SendAsync(approve)).StatusCode);

        using var execute = await requester.MutationAsync(HttpMethod.Post, ExecutionPath(data, planId), new { });
        var execution = await requester.SendAsync(execute);
        Assert.Equal(HttpStatusCode.OK, execution.StatusCode);
        var effects = await fixture.ExecutionEffectsAsync(data.Environment.Id, planId);
        Assert.Equal(4, effects.RoleCount);
        Assert.Equal(1, effects.ExecutionAuditCount);
        Assert.Equal(1, effects.EnvironmentChangedOutboxCount);
        Assert.Equal(ChangePlanState.Executed, effects.PlanState);

        using var replay = await requester.MutationAsync(HttpMethod.Post, ExecutionPath(data, planId), new { });
        using var replayResponse = await requester.SendAsync(replay);
        Assert.Equal(HttpStatusCode.Conflict, replayResponse.StatusCode);
        Assert.Equal("PlanChangedOrExpired", (await replayResponse.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
    }

    [Fact]
    public async Task Disabled_approver_invalidates_an_approved_plan_before_execution()
    {
        var data = await fixture.SeedAsync();
        using var requester = fixture.Client(data.RequesterToken);
        using var reviewer = fixture.Client(data.ReviewerToken);
        using var create = await requester.MutationAsync(HttpMethod.Post, PlanPath(data), Plan(data.Environment.Version, "approver remains active"));
        using var created = await requester.SendAsync(create);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var plan = JsonDocument.Parse(await created.Content.ReadAsStringAsync()).RootElement;
        var planId = plan.GetProperty("id").GetGuid();
        using var approve = await reviewer.MutationAsync(HttpMethod.Post, ApprovalPath(data, planId), new { planHash = plan.GetProperty("planHash").GetString() });
        Assert.Equal(HttpStatusCode.OK, (await reviewer.SendAsync(approve)).StatusCode);
        await fixture.DisablePrincipalAsync(data.Reviewer.Id);

        using var execute = await requester.MutationAsync(HttpMethod.Post, ExecutionPath(data, planId), new { });
        using var response = await requester.SendAsync(execute);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Management_input_cannot_inject_owner_only_permission()
    {
        var data = await fixture.SeedAsync();
        using var client = fixture.Client(data.RequesterToken);
        var before = await fixture.PlanCountAsync(data.Environment.Id);
        var payload = new
        {
            change = new { kind = "role.create", name = "injected-role", permissions = new[] { PermissionCatalog.OwnerTransfer } },
            expectedVersion = data.Environment.Version,
            reason = "attempt owner permission injection"
        };
        using var request = await client.MutationAsync(HttpMethod.Post, PlanPath(data), payload);
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, await fixture.PlanCountAsync(data.Environment.Id));
    }

    private static object Plan(long version, string reason) => new
    {
        change = new { kind = "role.create", name = $"role-{Guid.NewGuid():N}", permissions = new[] { PermissionCatalog.UserView } },
        expectedVersion = version,
        reason
    };

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Null_plan_fields_are_validation_errors_without_mutation(bool missingChange)
    {
        var data = await fixture.SeedAsync();
        using var client = fixture.Client(data.RequesterToken);
        var body = missingChange
            ? new { change = (object?)null, reason = (string?)"valid reason", expectedVersion = 1 }
            : new { change = (object?)new { kind = "role.create", name = "test", permissions = new[] { PermissionCatalog.UserView } }, reason = (string?)null, expectedVersion = 1 };
        using var request = await client.MutationAsync(HttpMethod.Post, PlanPath(data), body);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, await fixture.PlanCountAsync(data.Environment.Id));
    }

    private static string PlanPath(TestData data) => $"/api/v1/environments/{data.Environment.Id}/change-plans";
    private static string ApprovalPath(TestData data, Guid planId) => $"{PlanPath(data)}/{planId}/approval";
    private static string ExecutionPath(TestData data, Guid planId) => $"{PlanPath(data)}/{planId}/execution";
}
