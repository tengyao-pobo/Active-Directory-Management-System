using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using ItManagement.AgentEnrollmentTargets;
using ItManagement.Api;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed partial class EnrollmentGrantPlanTests
{
    private readonly PostgresApiFixture _fixture;

    public EnrollmentGrantPlanTests(PostgresApiFixture fixture) => _fixture = fixture;
    private static ConsoleDbContext Db() => new(new DbContextOptionsBuilder<ConsoleDbContext>()
        .UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Options);
    private static DateTimeOffset Canonical(DateTimeOffset value) => new(value.UtcTicks - value.UtcTicks % 10, TimeSpan.Zero);
    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class Reader(Func<Guid, Guid, EnrollmentTargetResult> read) : IEnrollmentTargetReader
    {
        public int Calls { get; private set; }
        public Task<EnrollmentTargetResult> ReadAsync(Guid environmentId, Guid directoryObjectId, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(read(environmentId, directoryObjectId));
        }
    }

    private sealed class AsyncReader(Func<Guid, Guid, Task<EnrollmentTargetResult>> read) : IEnrollmentTargetReader
    {
        public int Calls { get; private set; }
        public async Task<EnrollmentTargetResult> ReadAsync(Guid environmentId, Guid directoryObjectId, CancellationToken cancellationToken)
        {
            Calls++;
            return await read(environmentId, directoryObjectId);
        }
    }

    private WebApplicationFactory<Program> Factory(IEnrollmentTargetReader reader, DateTimeOffset now) =>
        Factory(reader, new Clock(now));

    private WebApplicationFactory<Program> Factory(IEnrollmentTargetReader reader, TimeProvider time) =>
        _fixture.Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IEnrollmentTargetReader>(); services.AddSingleton(reader);
            services.RemoveAll<TimeProvider>(); services.AddSingleton(time);
        }));

    private static HttpClient Client(WebApplicationFactory<Program> factory, string token) => factory.CreateClient(new()
        { BaseAddress = new Uri("https://localhost:7443"), HandleCookies = false }).WithSession(token);

    private async Task<Seeded> Seed(bool sameOperator = false)
    {
        var data = await _fixture.SeedAsync(sameOperator); var now = Canonical(DateTimeOffset.UtcNow);
        var directoryId = Guid.NewGuid(); var generation = Guid.NewGuid(); var ou = Guid.NewGuid();
        await using var db = Db();
        db.DirectorySync.Add(new DirectorySyncState { EnvironmentId = data.Environment.Id, Id = Guid.NewGuid(), Generation = generation,
            Status = "Ready", AttemptedAt = now, CompletedAt = now, SourceServer = "synthetic", NamingContext = "DC=test" });
        db.DirectoryObjects.Add(new DirectoryObjectRecord { EnvironmentId = data.Environment.Id, Id = directoryId, Generation = generation,
            Kind = "Computer", Name = "synthetic-device", DistinguishedName = "CN=device,DC=test", ParentOuId = ou, OuAncestry = [ou] });
        var reviewerRole = await db.Roles.SingleAsync(x => x.EnvironmentId == data.Environment.Id && x.Name == "reviewer");
        db.RolePermissions.AddRange(
            new RolePermission { EnvironmentId = data.Environment.Id, RoleId = data.RequesterRoleId, Permission = PermissionCatalog.ComputerView },
            new RolePermission { EnvironmentId = data.Environment.Id, RoleId = data.RequesterRoleId, Permission = PermissionCatalog.AgentEnrollmentGrantManage },
            new RolePermission { EnvironmentId = data.Environment.Id, RoleId = reviewerRole.Id, Permission = PermissionCatalog.ComputerView });
        await db.SaveChangesAsync();
        using var rsa = RSA.Create(3072);
        var spki = Base64Url(rsa.ExportSubjectPublicKeyInfo());
        return new(data, directoryId, generation, Guid.NewGuid(), now, spki);
    }

    [Fact]
    public async Task CreateReadAndIndependentApprovalAreAtomicAndDoNotCreateExecutionEffects()
    {
        var seeded = await Seed(); var requestId = Guid.NewGuid();
        var reader = ResolvedReader(seeded); using var factory = Factory(reader, seeded.Now); using var requester = Client(factory, seeded.Data.RequesterToken);
        using var created = await requester.SendAsync(await requester.MutationAsync(HttpMethod.Post, CreatePath(seeded), Body(seeded, requestId)));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var dto = await created.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["canApprove", "canRequest", "directoryGeneration", "directoryObjectId", "environmentId", "expiresAt", "id", "planHash", "policyVersion", "queriedAt", "reason", "recipientKeyFingerprint", "requesterId", "requestId", "state"],
            dto.EnumerateObject().Select(x => x.Name).Order().ToArray());
        Assert.True(dto.GetProperty("canRequest").GetBoolean()); Assert.False(dto.GetProperty("canApprove").GetBoolean());
        Assert.Equal("PendingApproval", dto.GetProperty("state").GetString());
        Assert.DoesNotContain(seeded.DeviceId.ToString(), dto.GetRawText()); Assert.DoesNotContain(seeded.SubjectPublicKeyInfo, dto.GetRawText());
        var planId = dto.GetProperty("id").GetGuid(); var hash = dto.GetProperty("planHash").GetString()!;

        using var reviewer = Client(factory, seeded.Data.ReviewerToken);
        using var read = await reviewer.GetAsync(ReadPath(seeded, planId));
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        var readDto = await read.Content.ReadFromJsonAsync<JsonElement>(); Assert.True(readDto.GetProperty("canApprove").GetBoolean());
        using var approved = await reviewer.SendAsync(await reviewer.MutationAsync(HttpMethod.Post, ApprovalPath(seeded, planId), new { planHash = hash }));
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        using var replay = await reviewer.SendAsync(await reviewer.MutationAsync(HttpMethod.Post, ApprovalPath(seeded, planId), new { planHash = hash }));
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);

        await using var db = Db();
        Assert.Equal(1, await db.EnrollmentGrantRecipientReservations.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.PlanId == planId));
        Assert.Equal(1, await db.Approvals.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.PlanId == planId));
        Assert.Equal(1, await db.Audit.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == "EnrollmentGrantPlan.Created" && x.TargetId == planId.ToString()));
        Assert.Equal(1, await db.Audit.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == "EnrollmentGrantPlan.Approved" && x.TargetId == planId.ToString()));
        Assert.False(await db.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
    }

    [Fact]
    public async Task ExactRequestRetryReturnsTheSamePlanWithoutASecondAuditButAnyDeltaConflicts()
    {
        var seeded = await Seed(); var requestId = Guid.NewGuid(); var reader = ResolvedReader(seeded);
        using var factory = Factory(reader, seeded.Now); using var client = Client(factory, seeded.Data.RequesterToken);
        var first = await Post(client, CreatePath(seeded), Body(seeded, requestId)); Assert.Equal(HttpStatusCode.Created, first.Status);
        var retry = await Post(client, CreatePath(seeded), Body(seeded, requestId)); Assert.Equal(HttpStatusCode.OK, retry.Status);
        Assert.Equal(first.Json.GetProperty("id").GetGuid(), retry.Json.GetProperty("id").GetGuid());
        var changed = await Post(client, CreatePath(seeded), Body(seeded, requestId, reason: "different authorized reason"));
        Assert.Equal(HttpStatusCode.Conflict, changed.Status);
        await using var db = Db();
        Assert.Equal(1, await db.Plans.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == EnrollmentGrantPlanContract.Action));
        Assert.Equal(1, await db.Audit.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == "EnrollmentGrantPlan.Created"));
    }

    [Theory]
    [InlineData("extra")]
    [InlineData("bad-reason")]
    [InlineData("bad-request")]
    [InlineData("bad-generation")]
    [InlineData("bad-spki")]
    public async Task StrictRequestRejectsUnknownOrMalformedFieldsBeforeResolverOrWrites(string fault)
    {
        var seeded = await Seed(); var reader = ResolvedReader(seeded); using var factory = Factory(reader, seeded.Now); using var client = Client(factory, seeded.Data.RequesterToken);
        object body = fault switch
        {
            "extra" => new { requestId = Guid.NewGuid(), expectedEnvironmentVersion = 1, expectedDirectoryGeneration = seeded.Generation, recipientSpki = seeded.SubjectPublicKeyInfo, reason = "valid reason", serverDeviceId = seeded.DeviceId },
            "bad-reason" => new { requestId = Guid.NewGuid(), expectedEnvironmentVersion = 1, expectedDirectoryGeneration = seeded.Generation, recipientSpki = seeded.SubjectPublicKeyInfo, reason = "bad\nreason" },
            "bad-request" => new { requestId = Guid.Empty, expectedEnvironmentVersion = 1, expectedDirectoryGeneration = seeded.Generation, recipientSpki = seeded.SubjectPublicKeyInfo, reason = "valid reason" },
            "bad-generation" => new { requestId = Guid.NewGuid(), expectedEnvironmentVersion = 1, expectedDirectoryGeneration = Guid.Empty, recipientSpki = seeded.SubjectPublicKeyInfo, reason = "valid reason" },
            _ => new { requestId = Guid.NewGuid(), expectedEnvironmentVersion = 1, expectedDirectoryGeneration = seeded.Generation, recipientSpki = "AA", reason = "valid reason" },
        };
        var response = await Post(client, CreatePath(seeded), body);
        Assert.Equal(HttpStatusCode.BadRequest, response.Status); Assert.Equal(0, reader.Calls);
        await using var db = Db(); Assert.False(await db.Plans.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == EnrollmentGrantPlanContract.Action));
    }

    [Fact]
    public async Task PublicVersionDriftDuringResolverRollsBackTheProposal()
    {
        var seeded = await Seed();
        var reader = new AsyncReader(async (env, directory) =>
        {
            await using var db = Db();
            await db.Environments.Where(x => x.Id == env).ExecuteUpdateAsync(x => x.SetProperty(e => e.Version, e => e.Version + 1));
            return EnrollmentTargetResult.Resolved(env, directory, seeded.DeviceId, seeded.Now.AddMinutes(-1));
        });
        using var factory = Factory(reader, seeded.Now); using var client = Client(factory, seeded.Data.RequesterToken);
        var response = await Post(client, CreatePath(seeded), Body(seeded, Guid.NewGuid()));
        Assert.Equal(HttpStatusCode.Conflict, response.Status); Assert.Equal(1, reader.Calls);
        await using var verify = Db(); Assert.False(await verify.Plans.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == EnrollmentGrantPlanContract.Action));
    }

    [Fact]
    public async Task RecipientFingerprintIsAGlobalPermanentTombstone()
    {
        var first = await Seed(); var second = await Seed();
        second = second with { SubjectPublicKeyInfo = first.SubjectPublicKeyInfo };
        using var firstFactory = Factory(ResolvedReader(first), first.Now); using var firstClient = Client(firstFactory, first.Data.RequesterToken);
        var created = await Post(firstClient, CreatePath(first), Body(first, Guid.NewGuid())); Assert.Equal(HttpStatusCode.Created, created.Status);
        var planId = created.Json.GetProperty("id").GetGuid();
        await using (var db = Db()) await db.Plans.Where(x => x.EnvironmentId == first.Data.Environment.Id && x.Id == planId)
            .ExecuteUpdateAsync(x => x.SetProperty(p => p.State, ChangePlanState.Rejected));
        using var secondFactory = Factory(ResolvedReader(second), second.Now); using var secondClient = Client(secondFactory, second.Data.RequesterToken);
        var conflict = await Post(secondClient, CreatePath(second), Body(second, Guid.NewGuid()));
        Assert.Equal(HttpStatusCode.Conflict, conflict.Status);
        await using var verify = Db();
        var fingerprint = created.Json.GetProperty("recipientKeyFingerprint").GetString()!;
        var bytes = Convert.FromBase64String(fingerprint.Replace('-', '+').Replace('_', '/') + "=");
        Assert.Equal(1, await verify.EnrollmentGrantRecipientReservations.CountAsync(x => x.Fingerprint == bytes));
    }

    [Fact]
    public async Task SameOperatorCannotApproveAndCompetingApprovalIsRejected()
    {
        var seeded = await Seed(sameOperator: true); using var factory = Factory(ResolvedReader(seeded), seeded.Now); using var requester = Client(factory, seeded.Data.RequesterToken);
        var created = await Post(requester, CreatePath(seeded), Body(seeded, Guid.NewGuid())); var id = created.Json.GetProperty("id").GetGuid(); var hash = created.Json.GetProperty("planHash").GetString()!;
        using var reviewer = Client(factory, seeded.Data.ReviewerToken);
        var denied = await Post(reviewer, ApprovalPath(seeded, id), new { planHash = hash }); Assert.Equal(HttpStatusCode.NotFound, denied.Status);
    }

    [Fact]
    public async Task GenericPlanRoutesHideDedicatedActionAndNeverExecuteIt()
    {
        var seeded = await Seed(); using var factory = Factory(ResolvedReader(seeded), seeded.Now); using var requester = Client(factory, seeded.Data.RequesterToken);
        var created = await Post(requester, CreatePath(seeded), Body(seeded, Guid.NewGuid())); var id = created.Json.GetProperty("id").GetGuid(); var hash = created.Json.GetProperty("planHash").GetString()!;
        using var get = await requester.GetAsync($"/api/v1/environments/{seeded.Data.Environment.Id}/change-plans/{id}"); Assert.Equal(HttpStatusCode.NotFound, get.StatusCode);
        var approve = await Post(requester, $"/api/v1/environments/{seeded.Data.Environment.Id}/change-plans/{id}/approval", new { planHash = hash }); Assert.Equal(HttpStatusCode.NotFound, approve.Status);
        var execute = await Post(requester, $"/api/v1/environments/{seeded.Data.Environment.Id}/change-plans/{id}/execution", new { }); Assert.Equal(HttpStatusCode.NotFound, execute.Status);
        await using var db = Db(); Assert.Equal(ChangePlanState.PendingApproval, await db.Plans.Where(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Id == id).Select(x => x.State).SingleAsync());
        Assert.False(await db.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
    }

    [Fact]
    public async Task StoredPayloadHashAndReservationTamperingFailsClosed()
    {
        var seeded = await Seed(); using var factory = Factory(ResolvedReader(seeded), seeded.Now); using var requester = Client(factory, seeded.Data.RequesterToken);
        var created = await Post(requester, CreatePath(seeded), Body(seeded, Guid.NewGuid())); var id = created.Json.GetProperty("id").GetGuid();
        await using (var db = Db()) await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE public."Plans" SET "ImmutablePlanJson"=
                pg_catalog.replace("ImmutablePlanJson"::text,'authorized initial enrollment','tampered initial enrollment')::jsonb
            WHERE "EnvironmentId"={seeded.Data.Environment.Id} AND "Id"={id}
            """);
        using var response = await requester.GetAsync(ReadPath(seeded, id)); Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);

        await using var owner = Db(); var reservation = await owner.EnrollmentGrantRecipientReservations.SingleAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.PlanId == id);
        reservation.RequestDigest = RandomNumberGenerator.GetBytes(32);
        var error = await Assert.ThrowsAnyAsync<Exception>(() => owner.SaveChangesAsync());
        Assert.Contains("immutable", error.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FinalContextLockRechecksStepUpAtTheActualCommitTime()
    {
        var seeded = await Seed(); var reader = ResolvedReader(seeded); var clock = new Clock(seeded.Now);
        using var factory = Factory(reader, clock); using var client = Client(factory, seeded.Data.RequesterToken);
        await using var blocker = Db(); await using var blockerTx = await blocker.Database.BeginTransactionAsync();
        await blocker.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM public.\"Environments\" WHERE \"Id\"={seeded.Data.Environment.Id} FOR UPDATE");

        var pending = Post(client, CreatePath(seeded), Body(seeded, Guid.NewGuid()));
        for (var i = 0; i < 100 && reader.Calls == 0; i++) await Task.Delay(10);
        Assert.Equal(1, reader.Calls); Assert.False(pending.IsCompleted);
        clock.Now = seeded.Now.AddMinutes(20);
        await blockerTx.CommitAsync();

        var response = await pending;
        Assert.Equal(HttpStatusCode.Forbidden, response.Status);
        await using var verify = Db();
        Assert.False(await verify.Plans.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == EnrollmentGrantPlanContract.Action));
    }

    [Fact]
    public async Task ApprovalRechecksExpiryAfterWaitingForThePlanLock()
    {
        var seeded = await Seed(); var clock = new Clock(seeded.Now); var reader = ResolvedReader(seeded);
        using var factory = Factory(reader, clock); using var requester = Client(factory, seeded.Data.RequesterToken);
        var created = await Post(requester, CreatePath(seeded), Body(seeded, Guid.NewGuid()));
        var planId = created.Json.GetProperty("id").GetGuid(); var hash = created.Json.GetProperty("planHash").GetString()!;
        using var reviewer = Client(factory, seeded.Data.ReviewerToken);
        using var approvalRequest = await reviewer.MutationAsync(HttpMethod.Post, ApprovalPath(seeded, planId), new { planHash = hash });
        await using var blocker = Db(); await using var blockerTx = await blocker.Database.BeginTransactionAsync();
        await blocker.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM public.\"Plans\" WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={planId} FOR UPDATE");

        var pending = reviewer.SendAsync(approvalRequest);
        for (var i = 0; i < 100 && reader.Calls < 2; i++) await Task.Delay(10);
        Assert.Equal(2, reader.Calls); Assert.False(pending.IsCompleted);
        clock.Now = seeded.Now.AddMinutes(11);
        await blockerTx.CommitAsync();

        using var response = await pending;
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        await using var verify = Db();
        Assert.False(await verify.Approvals.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.PlanId == planId));
    }

    [Theory]
    [InlineData("runtime-update")]
    [InlineData("public-column")]
    [InlineData("no-force-rls")]
    [InlineData("disabled-trigger")]
    [InlineData("extra-policy")]
    [InlineData("extra-trigger")]
    [InlineData("duplicate-unique")]
    [InlineData("runtime-inherit")]
    [InlineData("locker-other-schema")]
    [InlineData("dependency-grant-option")]
    [InlineData("public-helper-execute")]
    [InlineData("runtime-other-schema")]
    [InlineData("runtime-directory-column-update")]
    [InlineData("runtime-directory-table-insert")]
    [InlineData("runtime-directory-column-insert")]
    [InlineData("runtime-database-create")]
    [InlineData("locker-database-create")]
    [InlineData("runtime-public-schema-create")]
    public async Task StartupProfileRejectsBroadenedReservationPrivileges(string drift)
    {
        await using var db = Db();
        var apply = drift switch
        {
            "runtime-update" => "GRANT UPDATE ON public.\"EnrollmentGrantRecipientReservations\" TO console_runtime",
            "public-column" => "GRANT SELECT (\"RequestDigest\") ON public.\"EnrollmentGrantRecipientReservations\" TO PUBLIC",
            "no-force-rls" => "ALTER TABLE public.\"EnrollmentGrantRecipientReservations\" NO FORCE ROW LEVEL SECURITY",
            "disabled-trigger" => "ALTER TABLE public.\"EnrollmentGrantRecipientReservations\" DISABLE TRIGGER enrollment_grant_recipient_reservations_immutable",
            "extra-policy" => "CREATE POLICY enrollment_grant_recipient_extra ON public.\"EnrollmentGrantRecipientReservations\" USING (true) WITH CHECK (true)",
            "extra-trigger" => "CREATE TRIGGER enrollment_grant_recipient_extra BEFORE INSERT ON public.\"EnrollmentGrantRecipientReservations\" FOR EACH ROW EXECUTE FUNCTION public.reject_enrollment_grant_reservation_mutation()",
            "duplicate-unique" => "DROP INDEX public.\"IX_EnrollmentGrantRecipientReservations_EnvironmentId_Requeste~\"; CREATE UNIQUE INDEX enrollment_grant_duplicate_plan ON public.\"EnrollmentGrantRecipientReservations\" (\"EnvironmentId\",\"PlanId\")",
            "runtime-inherit" => "ALTER ROLE console_runtime INHERIT",
            "dependency-grant-option" => "GRANT EXECUTE ON FUNCTION public.directory_database_access(uuid,uuid) TO console_enrollment_plan_locker WITH GRANT OPTION",
            "public-helper-execute" => "GRANT EXECUTE ON FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) TO PUBLIC",
            "runtime-other-schema" => "CREATE SCHEMA enrollment_plan_runtime_drift; CREATE TABLE enrollment_plan_runtime_drift.hidden(value integer); GRANT SELECT ON enrollment_plan_runtime_drift.hidden TO console_runtime",
            "runtime-directory-column-update" => "GRANT UPDATE (\"Generation\") ON public.\"DirectorySync\" TO console_runtime",
            "runtime-directory-table-insert" => "GRANT INSERT ON public.\"DirectoryObjects\" TO console_runtime",
            "runtime-directory-column-insert" => "GRANT INSERT (\"Generation\") ON public.\"DirectorySync\" TO console_runtime",
            "runtime-database-create" => "GRANT CREATE ON DATABASE console_test TO console_runtime",
            "locker-database-create" => "GRANT CREATE ON DATABASE console_test TO console_enrollment_plan_locker",
            "runtime-public-schema-create" => "GRANT CREATE ON SCHEMA public TO console_runtime",
            _ => "CREATE SCHEMA enrollment_plan_audit_drift; GRANT USAGE ON SCHEMA enrollment_plan_audit_drift TO console_enrollment_plan_locker",
        };
        var restore = drift switch
        {
            "runtime-update" => "REVOKE UPDATE ON public.\"EnrollmentGrantRecipientReservations\" FROM console_runtime",
            "public-column" => "REVOKE SELECT (\"RequestDigest\") ON public.\"EnrollmentGrantRecipientReservations\" FROM PUBLIC",
            "no-force-rls" => "ALTER TABLE public.\"EnrollmentGrantRecipientReservations\" FORCE ROW LEVEL SECURITY",
            "disabled-trigger" => "ALTER TABLE public.\"EnrollmentGrantRecipientReservations\" ENABLE TRIGGER enrollment_grant_recipient_reservations_immutable",
            "extra-policy" => "DROP POLICY enrollment_grant_recipient_extra ON public.\"EnrollmentGrantRecipientReservations\"",
            "extra-trigger" => "DROP TRIGGER enrollment_grant_recipient_extra ON public.\"EnrollmentGrantRecipientReservations\"",
            "duplicate-unique" => "DROP INDEX public.enrollment_grant_duplicate_plan; CREATE UNIQUE INDEX \"IX_EnrollmentGrantRecipientReservations_EnvironmentId_Requeste~\" ON public.\"EnrollmentGrantRecipientReservations\" (\"EnvironmentId\",\"RequesterId\",\"RequestId\")",
            "runtime-inherit" => "ALTER ROLE console_runtime NOINHERIT",
            "dependency-grant-option" => "REVOKE ALL ON FUNCTION public.directory_database_access(uuid,uuid) FROM console_enrollment_plan_locker; GRANT EXECUTE ON FUNCTION public.directory_database_access(uuid,uuid) TO console_enrollment_plan_locker",
            "public-helper-execute" => "REVOKE ALL ON FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) FROM PUBLIC",
            "runtime-other-schema" => "REVOKE ALL ON enrollment_plan_runtime_drift.hidden FROM console_runtime; DROP SCHEMA enrollment_plan_runtime_drift CASCADE",
            "runtime-directory-column-update" => "REVOKE UPDATE (\"Generation\") ON public.\"DirectorySync\" FROM console_runtime",
            "runtime-directory-table-insert" => "REVOKE INSERT ON public.\"DirectoryObjects\" FROM console_runtime",
            "runtime-directory-column-insert" => "REVOKE INSERT (\"Generation\") ON public.\"DirectorySync\" FROM console_runtime",
            "runtime-database-create" => "REVOKE CREATE ON DATABASE console_test FROM console_runtime",
            "locker-database-create" => "REVOKE CREATE ON DATABASE console_test FROM console_enrollment_plan_locker",
            "runtime-public-schema-create" => "REVOKE CREATE ON SCHEMA public FROM console_runtime",
            _ => "REVOKE USAGE ON SCHEMA enrollment_plan_audit_drift FROM console_enrollment_plan_locker; DROP SCHEMA enrollment_plan_audit_drift",
        };
        await db.Database.ExecuteSqlRawAsync(apply);
        try
        {
            using var factory = _fixture.Factory.WithWebHostBuilder(_ => { });
            var error = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
            Assert.Contains("privilege audit failed", error.ToString(), StringComparison.OrdinalIgnoreCase);
        }
        finally { await db.Database.ExecuteSqlRawAsync(restore); }
    }

    [Fact]
    public async Task MigrationRollbackRefusesToRemovePermanentRecipientReservations()
    {
        var seeded = await Seed(); using var factory = Factory(ResolvedReader(seeded), seeded.Now); using var client = Client(factory, seeded.Data.RequesterToken);
        var created = await Post(client, CreatePath(seeded), Body(seeded, Guid.NewGuid()));
        Assert.Equal(HttpStatusCode.Created, created.Status);
        await using var db = Db();
        var migrator = db.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>();
        var error = await Assert.ThrowsAnyAsync<Exception>(() => migrator.MigrateAsync("20260911205500_EnrollmentGrantPermission"));
        Assert.Contains("reservations prevent rollback", error.ToString(), StringComparison.OrdinalIgnoreCase);
        await using var verify = Db();
        Assert.True(await verify.EnrollmentGrantRecipientReservations.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.True(await verify.Database.SqlQueryRaw<bool>("SELECT to_regclass('public.\"EnrollmentGrantRecipientReservations\"') IS NOT NULL AS \"Value\"").SingleAsync());
    }

    private static Reader ResolvedReader(Seeded seeded) => new((env, directory) =>
        EnrollmentTargetResult.Resolved(env, directory, seeded.DeviceId, seeded.Now.AddMinutes(-1)));
    private static object Body(Seeded seeded, Guid requestId, string reason = "authorized initial enrollment") => new
        { requestId, expectedEnvironmentVersion = seeded.Data.Environment.Version, expectedDirectoryGeneration = seeded.Generation, recipientSpki = seeded.SubjectPublicKeyInfo, reason };
    private static string CreatePath(Seeded seeded) => $"/api/v1/environments/{seeded.Data.Environment.Id}/devices/{seeded.DirectoryObjectId}/enrollment-grant-plans";
    private static string ReadPath(Seeded seeded, Guid plan) => $"/api/v1/environments/{seeded.Data.Environment.Id}/enrollment-grant-plans/{plan}";
    private static string ApprovalPath(Seeded seeded, Guid plan) => $"{ReadPath(seeded, plan)}/approval";
    private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static async Task<(HttpStatusCode Status, JsonElement Json)> Post(HttpClient client, string path, object body)
    {
        using var response = await client.SendAsync(await client.MutationAsync(HttpMethod.Post, path, body));
        var text = await response.Content.ReadAsStringAsync();
        return (response.StatusCode, string.IsNullOrWhiteSpace(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }
    private sealed record Seeded(TestData Data, Guid DirectoryObjectId, Guid Generation, Guid DeviceId, DateTimeOffset Now, string SubjectPublicKeyInfo);
}
