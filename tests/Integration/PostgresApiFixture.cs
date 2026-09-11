using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace ItManagement.IntegrationTests;

public sealed class PostgresApiFixture : IAsyncLifetime
{
    private readonly string _connectionString = Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")
        ?? throw new InvalidOperationException("CONSOLE_TEST_DB is required for PostgreSQL integration tests.");
    private readonly string _runtimeConnectionString = Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")
        ?? throw new InvalidOperationException("CONSOLE_TEST_RUNTIME_DB is required to verify the runtime RLS role.");
    private readonly string _marker = $"integration-{Guid.NewGuid():N}";
    private string? _previousRuntimeConnection;

    public ApiFactory Factory { get; private set; } = null!;
    public bool UsesRuntimeRole => true;

    public async Task InitializeAsync()
    {
        await using var db = CreateDb();
        await db.Database.MigrateAsync();
        await ProvisionRuntimeAsync(db);
        _previousRuntimeConnection = Environment.GetEnvironmentVariable("ConnectionStrings__Console");
        Environment.SetEnvironmentVariable("ConnectionStrings__Console", _runtimeConnectionString);
        Factory = new ApiFactory();
    }

    private async Task ProvisionRuntimeAsync(ConsoleDbContext db)
    {
        var owner = new Npgsql.NpgsqlConnectionStringBuilder(_connectionString);
        var runtime = new Npgsql.NpgsqlConnectionStringBuilder(_runtimeConnectionString);
        if (!string.Equals(owner.Database, runtime.Database, StringComparison.Ordinal) || string.IsNullOrWhiteSpace(runtime.Username))
            throw new InvalidOperationException("The integration runtime connection must target the owner database with a named role.");
        const string lockOwner = "console_enrollment_plan_locker";
        await db.Database.ExecuteSqlRawAsync("""
            DO $block$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='console_enrollment_plan_locker') THEN
                    CREATE ROLE console_enrollment_plan_locker NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
                END IF;
            END
            $block$;
            ALTER ROLE console_enrollment_plan_locker NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
            """);
        var restrictRuntimeRole = "ALTER ROLE " + QuoteIdentifier(runtime.Username!) +
            " LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION";
        await db.Database.ExecuteSqlRawAsync(restrictRuntimeRole);
        var script = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "provision-runtime.sql"));
        script = string.Join('\n', script.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Where(line => !line.TrimStart().StartsWith('\\')));
        script = script.Replace(":\"runtime_role\"", QuoteIdentifier(runtime.Username), StringComparison.Ordinal)
            .Replace(":'runtime_role'", QuoteLiteral(runtime.Username), StringComparison.Ordinal)
            .Replace(":\"enrollment_plan_lock_owner_role\"", QuoteIdentifier(lockOwner), StringComparison.Ordinal)
            .Replace(":'enrollment_plan_lock_owner_role'", QuoteLiteral(lockOwner), StringComparison.Ordinal)
            .Replace(":DBNAME", QuoteIdentifier(owner.Database!), StringComparison.Ordinal);
        if (script.Contains(":\"runtime_role\"", StringComparison.Ordinal) || script.Contains(":'runtime_role'", StringComparison.Ordinal) ||
            script.Contains(":\"enrollment_plan_lock_owner_role\"", StringComparison.Ordinal) || script.Contains(":'enrollment_plan_lock_owner_role'", StringComparison.Ordinal) ||
            script.Contains(":DBNAME", StringComparison.Ordinal))
            throw new InvalidOperationException("Runtime provisioning substitutions were incomplete.");
        await db.Database.ExecuteSqlRawAsync(script);
    }

    private static string QuoteIdentifier(string value) => $"\"{value.Replace("\"", "\"\"")}\"";
    private static string QuoteLiteral(string value) => $"'{value.Replace("'", "''")}'";

    public async Task<TestData> SeedAsync(bool sameOperator = false)
    {
        var now = DateTimeOffset.UtcNow;
        var environment = new ManagedEnvironment
        {
            Id = Guid.NewGuid(), Name = $"{_marker}-env", CanonicalDns = "example.test", DefaultLocale = "en-US", Version = 1
        };
        var otherEnvironment = new ManagedEnvironment
        {
            Id = Guid.NewGuid(), Name = $"{_marker}-other", CanonicalDns = "other.example.test", DefaultLocale = "en-US", Version = 1
        };
        var requester = Principal($"requester-{Guid.NewGuid():N}", Guid.NewGuid());
        var reviewer = Principal($"reviewer-{Guid.NewGuid():N}", sameOperator ? requester.OperatorId : Guid.NewGuid());
        var viewer = Principal($"viewer-{Guid.NewGuid():N}", Guid.NewGuid());
        var requesterRole = Role(environment.Id, "requester", BuiltInRoleKinds.Owner);
        var reviewerRole = Role(environment.Id, "reviewer");
        var viewerRole = Role(environment.Id, "viewer");
        var allScope = new Scope { EnvironmentId = environment.Id, Id = Guid.NewGuid(), Kind = ScopeKind.All };
        var requesterToken = Token();
        var reviewerToken = Token();
        var viewerToken = Token();

        await using var db = CreateDb();
        db.AddRange(environment, otherEnvironment, requester, reviewer, viewer, requesterRole, reviewerRole, viewerRole,
            Role(otherEnvironment.Id, "foreign"), allScope);
        db.AddRange(
            new EnvironmentMembership { EnvironmentId = environment.Id, PrincipalId = requester.Id, Active = true },
            new EnvironmentMembership { EnvironmentId = environment.Id, PrincipalId = reviewer.Id, Active = true },
            new EnvironmentMembership { EnvironmentId = environment.Id, PrincipalId = viewer.Id, Active = true });
        db.AddRange(
            new RolePermission { EnvironmentId = environment.Id, RoleId = requesterRole.Id, Permission = PermissionCatalog.RbacManage },
            new RolePermission { EnvironmentId = environment.Id, RoleId = requesterRole.Id, Permission = PermissionCatalog.ChangeApprove },
            new RolePermission { EnvironmentId = environment.Id, RoleId = reviewerRole.Id, Permission = PermissionCatalog.ChangeApprove },
            new RolePermission { EnvironmentId = environment.Id, RoleId = viewerRole.Id, Permission = PermissionCatalog.EnvironmentView },
            new RolePermission { EnvironmentId = environment.Id, RoleId = viewerRole.Id, Permission = PermissionCatalog.AuditView });
        db.AddRange(
            Assignment(environment.Id, requester.Id, requesterRole.Id, allScope.Id),
            Assignment(environment.Id, reviewer.Id, reviewerRole.Id, allScope.Id),
            Assignment(environment.Id, viewer.Id, viewerRole.Id, allScope.Id));
        db.AddRange(
            Session(requester.Id, requesterToken, now, stepUp: true),
            Session(reviewer.Id, reviewerToken, now, stepUp: true),
            Session(viewer.Id, viewerToken, now, stepUp: false));
        await db.SaveChangesAsync();
        return new TestData(environment, otherEnvironment, requester, reviewer, viewer, requesterRole.Id, allScope.Id, requesterToken, reviewerToken, viewerToken);
    }

    public async Task AddInvalidSessionAsync(Guid principalId, string token, bool revoked)
    {
        var now = DateTimeOffset.UtcNow;
        await using var db = CreateDb();
        db.Sessions.Add(new PlatformSession
        {
            IdHash = SessionTokens.Hash(token), PrincipalId = principalId, Method = "Test", CreatedAt = now.AddHours(-1), LastSeenAt = now,
            ExpiresAt = revoked ? now.AddHours(1) : now.AddMinutes(-1), RevokedAt = revoked ? now : null, SourceIp = "127.0.0.1", UserAgent = "integration"
        });
        await db.SaveChangesAsync();
    }

    public async Task<ChangePlan> GetPlanAsync(Guid environmentId, Guid planId)
    {
        await using var db = CreateDb();
        return await db.Plans.Include(x => x.Items).SingleAsync(x => x.EnvironmentId == environmentId && x.Id == planId);
    }

    public async Task<int> PlanCountAsync(Guid environmentId)
    {
        await using var db = CreateDb();
        return await db.Plans.CountAsync(x => x.EnvironmentId == environmentId);
    }

    public async Task BumpEnvironmentVersionAsync(Guid environmentId)
    {
        await using var db = CreateDb();
        await db.Environments.Where(x => x.Id == environmentId)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.Version, x => x.Version + 1));
    }

    public async Task DisablePrincipalAsync(Guid principalId)
    {
        await using var db = CreateDb();
        await db.Principals.Where(x => x.Id == principalId)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.Enabled, false));
    }

    public async Task<ExecutionEffects> ExecutionEffectsAsync(Guid environmentId, Guid planId)
    {
        await using var db = CreateDb();
        return new ExecutionEffects(
            await db.Roles.CountAsync(x => x.EnvironmentId == environmentId),
            await db.Audit.CountAsync(x => x.EnvironmentId == environmentId && x.Action == "ChangePlan.Executed"),
            await db.Outbox.CountAsync(x => x.EnvironmentId == environmentId && x.EventType == "EnvironmentChanged"),
            await db.Plans.Where(x => x.EnvironmentId == environmentId && x.Id == planId).Select(x => x.State).SingleAsync());
    }

    public async Task<int> RuntimeRoleCountAsync(Guid? environmentId, Guid? principalId)
    {
        await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(_runtimeConnectionString).Options);
        if (environmentId is { } environment && principalId is { } principal)
        {
            await using var transaction = await db.BeginEnvironment(environment, principal, CancellationToken.None);
            return await db.Roles.CountAsync();
        }
        return await db.Roles.CountAsync();
    }

    public async Task<IReadOnlyList<Guid>> SeedSameTimestampAuditAsync(TestData data, int count)
    {
        var occurredAt = new DateTimeOffset(DateTime.UtcNow.Ticks - DateTime.UtcNow.Ticks % 10, TimeSpan.Zero);
        var rows = Enumerable.Range(0, count).Select(i => new AuditRecord
        {
            EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), ActorId = data.Viewer.Id, Action = "Pagination.Test",
            TargetId = i.ToString(), Result = "Success", OccurredAt = occurredAt, SourceIp = "127.0.0.1", CorrelationId = _marker
        }).ToList();
        await using var db = CreateDb();
        db.Audit.AddRange(rows);
        await db.SaveChangesAsync();
        return rows.Select(x => x.Id).ToList();
    }

    public async Task<string> RuntimeAuditMutationErrorAsync(TestData data, Guid auditId, bool delete)
    {
        await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(_runtimeConnectionString).Options);
        await using var transaction = await db.BeginEnvironment(data.Environment.Id, data.Viewer.Id, CancellationToken.None);
        try
        {
            if (delete)
                await db.Audit.Where(x => x.EnvironmentId == data.Environment.Id && x.Id == auditId).ExecuteDeleteAsync();
            else
                await db.Audit.Where(x => x.EnvironmentId == data.Environment.Id && x.Id == auditId)
                    .ExecuteUpdateAsync(s => s.SetProperty(x => x.Result, "Tampered"));
            return "allowed";
        }
        catch (Npgsql.PostgresException error)
        {
            return error.SqlState;
        }
        catch (DbUpdateException error) when (error.InnerException is Npgsql.PostgresException postgres)
        {
            return postgres.SqlState;
        }
    }

    public async Task<string> RuntimeOwnerMappingErrorAsync(TestData data)
    {
        await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(_runtimeConnectionString).Options);
        await using var transaction = await db.BeginEnvironment(data.Environment.Id, data.Requester.Id, CancellationToken.None);
        db.GroupMappings.Add(new DirectoryGroupMapping
        {
            EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), GroupSid = "S-1-5-21-1-2-3-4", RoleId = data.RequesterRoleId, ScopeId = data.AllScopeId
        });
        try
        {
            await db.SaveChangesAsync();
            return "allowed";
        }
        catch (Npgsql.PostgresException error)
        {
            return error.SqlState;
        }
        catch (DbUpdateException error) when (error.InnerException is Npgsql.PostgresException postgres)
        {
            return postgres.SqlState;
        }
    }

    public HttpClient Client(string? sessionToken = null) => Factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost:7443"), AllowAutoRedirect = false, HandleCookies = false
    }).WithSession(sessionToken);

    public async Task DisposeAsync()
    {
        if (Factory is not null) await Factory.DisposeAsync();
        Environment.SetEnvironmentVariable("ConnectionStrings__Console", _previousRuntimeConnection);
        // Audit and security-event tables are append-only by design. Test rows retain the run marker and must be
        // removed only by rebuilding the isolated console_test database, never by disabling its safeguards.
    }

    private ConsoleDbContext CreateDb() => new(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(_connectionString).Options);
    private Principal Principal(string subject, Guid operatorId) => new()
    { Id = Guid.NewGuid(), OperatorId = operatorId, Issuer = _marker, Subject = subject, DisplayName = subject, Enabled = true };
    private static Role Role(Guid environmentId, string name, string? builtInKind = null) => new()
    { EnvironmentId = environmentId, Id = Guid.NewGuid(), Name = name, BuiltInKind = builtInKind };
    private static RoleAssignment Assignment(Guid environmentId, Guid principalId, Guid roleId, Guid scopeId) => new()
    { EnvironmentId = environmentId, Id = Guid.NewGuid(), PrincipalId = principalId, RoleId = roleId, ScopeId = scopeId };
    private static string Token() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    private static PlatformSession Session(Guid principalId, string token, DateTimeOffset now, bool stepUp) => new()
    { IdHash = SessionTokens.Hash(token), PrincipalId = principalId, Method = "Test", CreatedAt = now, LastSeenAt = now, ExpiresAt = now.AddHours(1), StepUpAt = stepUp ? now : null, SourceIp = "127.0.0.1", UserAgent = "integration" };
}

public sealed class ApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder) => builder.ConfigureAppConfiguration((_, config) =>
        config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Console:Origin"] = "https://localhost:7443",
            ["Console:RelyingPartyId"] = "localhost",
            ["Console:WindowsAuthentication"] = "false",
            ["Console:EmergencyLogin"] = "false"
        }));
}

public sealed record TestData(ManagedEnvironment Environment, ManagedEnvironment OtherEnvironment, Principal Requester,
    Principal Reviewer, Principal Viewer, Guid RequesterRoleId, Guid AllScopeId, string RequesterToken, string ReviewerToken, string ViewerToken);

public sealed record ExecutionEffects(int RoleCount, int ExecutionAuditCount, int EnvironmentChangedOutboxCount, ChangePlanState PlanState);

public static class IntegrationHttpExtensions
{
    public static HttpClient WithSession(this HttpClient client, string? token)
    {
        if (token is not null) client.DefaultRequestHeaders.Add("Cookie", $"{SessionTokens.Cookie}={token}");
        return client;
    }

    public static async Task<HttpRequestMessage> MutationAsync(this HttpClient client, HttpMethod method, string path, object body, string origin = "https://localhost:7443")
    {
        var csrf = await client.GetAsync("/api/v1/session/csrf");
        csrf.EnsureSuccessStatusCode();
        var token = JsonDocument.Parse(await csrf.Content.ReadAsStringAsync()).RootElement.GetProperty("token").GetString()!;
        var cookie = csrf.Headers.GetValues("Set-Cookie").Single().Split(';')[0];
        var request = new HttpRequestMessage(method, path) { Content = JsonContent.Create(body) };
        request.Headers.Add("Origin", origin);
        request.Headers.Add("X-CSRF-TOKEN", token);
        request.Headers.Add("Cookie", $"{client.DefaultRequestHeaders.GetValues("Cookie").Single()}; {cookie}");
        return request;
    }
}
