using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using ItManagement.AgentEnrollmentTargets;
using ItManagement.Api;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    private sealed class ExecutionReady : IEnrollmentGrantExecutionReadiness
    {
        public bool IsReady(Guid environmentId) => true;
    }

    private sealed class MutableExecutionReadiness : IEnrollmentGrantExecutionReadiness
    {
        private int _ready = 1;
        public void Close() => Volatile.Write(ref _ready, 0);
        public bool IsReady(Guid environmentId) => Volatile.Read(ref _ready) == 1;
    }

    private WebApplicationFactory<Program> ExecutionFactory(Seeded seeded, Clock clock) =>
        Factory(ResolvedReader(seeded), clock).WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IEnrollmentGrantExecutionReadiness>();
            services.AddSingleton<IEnrollmentGrantExecutionReadiness, ExecutionReady>();
        }));

    private static async Task<(Guid Id, string Hash)> ApprovedExecutionPlan(Seeded seeded, WebApplicationFactory<Program> factory)
    {
        using var requester = Client(factory, seeded.Data.RequesterToken);
        var created = await Post(requester, CreatePath(seeded), Body(seeded, Guid.NewGuid()));
        Assert.Equal(HttpStatusCode.Created, created.Status);
        var id = created.Json.GetProperty("id").GetGuid();
        var hash = created.Json.GetProperty("planHash").GetString()!;
        using var reviewer = Client(factory, seeded.Data.ReviewerToken);
        Assert.Equal(HttpStatusCode.OK, (await Post(reviewer, ApprovalPath(seeded, id), new { planHash = hash })).Status);
        return (id, hash);
    }

    [Fact]
    public async Task ExecutionRechecksProcessorAfterWaitingForProfileLock()
    {
        var seeded = await Seed();
        var readiness = new MutableExecutionReadiness();
        using var factory = ExecutionFactory(seeded, new Clock(seeded.Now)).WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IEnrollmentGrantExecutionReadiness>();
            services.AddSingleton<IEnrollmentGrantExecutionReadiness>(readiness);
        }));
        var plan = await ApprovedExecutionPlan(seeded, factory);
        using var client = Client(factory, seeded.Data.RequesterToken);
        using var request = await client.MutationAsync(HttpMethod.Post, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        await using var blocker = Db();
        await using var transaction = await blocker.Database.BeginTransactionAsync();
        await blocker.Database.ExecuteSqlRawAsync("SELECT pg_catalog.pg_advisory_xact_lock(1162235478,1)");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var pending = client.SendAsync(request, cancellation.Token);
        try
        {
            var blocked = false;
            for (var i = 0; i < 500 && !blocked; i++)
            {
                blocked = await blocker.Database.SqlQueryRaw<bool>("""
                    SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l
                      WHERE l.locktype='advisory' AND l.classid=1162235478 AND l.objid=1 AND l.objsubid=2
                        AND l.mode='ShareLock' AND NOT l.granted
                        AND pg_catalog.pg_backend_pid()=ANY(pg_catalog.pg_blocking_pids(l.pid))) AS "Value"
                    """).SingleAsync(cancellation.Token);
                if (!blocked) await Task.Delay(20, cancellation.Token);
            }
            Assert.True(blocked);
            Assert.False(pending.IsCompleted);
            readiness.Close();
            await transaction.CommitAsync(cancellation.Token);
            using var response = await pending;
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            await using var verify = Db();
            Assert.False(await verify.EnrollmentGrantOperations.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
            Assert.False(await verify.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
            Assert.Equal(ChangePlanState.Approved, await verify.Plans.Where(x => x.Id == plan.Id).Select(x => x.State).SingleAsync());
        }
        finally
        {
            await cancellation.CancelAsync();
            try { if (blocker.Database.CurrentTransaction is not null) await transaction.RollbackAsync(CancellationToken.None); }
            finally { await ObserveExecutionRequests(pending); }
        }
    }

    [Fact]
    public async Task ExecutionQueuesExactlyOnceAndNeverReturnsPrivateGrantMaterial()
    {
        var seeded = await Seed(); var clock = new Clock(seeded.Now);
        using var factory = ExecutionFactory(seeded, clock);
        var plan = await ApprovedExecutionPlan(seeded, factory);
        using var requester = Client(factory, seeded.Data.RequesterToken);
        var queued = await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(HttpStatusCode.Accepted, queued.Status);
        Assert.Equal(new[] { "authorizationNotAfter", "directoryObjectId", "environmentId", "id", "planId", "queriedAt", "queuedAt", "state" },
            queued.Json.EnumerateObject().Select(x => x.Name).Order().ToArray());
        Assert.Equal("Queued", queued.Json.GetProperty("state").GetString());
        Assert.DoesNotContain(seeded.DeviceId.ToString(), queued.Json.GetRawText());
        Assert.DoesNotContain(seeded.SubjectPublicKeyInfo, queued.Json.GetRawText());
        var retry = await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(HttpStatusCode.OK, retry.Status);
        Assert.Equal(queued.Json, retry.Json, new JsonValueComparer());
        await using var db = Db();
        var operation = await db.EnrollmentGrantOperations.SingleAsync(x => x.EnvironmentId == seeded.Data.Environment.Id);
        Assert.Equal(ChangePlanState.Queued, await db.Plans.Where(x => x.Id == plan.Id).Select(x => x.State).SingleAsync());
        Assert.Equal(1, await db.Outbox.CountAsync(x => x.EnvironmentId == operation.EnvironmentId && x.Id == operation.Id));
        Assert.Equal(1, await db.Audit.CountAsync(x => x.EnvironmentId == operation.EnvironmentId && x.Action == "EnrollmentGrantExecution.Queued"));
        var session = await db.Sessions.SingleAsync(x => x.IdHash == SessionTokens.Hash(seeded.Data.RequesterToken));
        Assert.Equal(Canonical(session.StepUpAt!.Value.AddMinutes(5)), operation.AuthorizationNotAfter);
        Assert.True(operation.AuthorizationNotAfter > operation.QueuedAt);
    }

    [Fact]
    public async Task ExecutionRemainsUnavailableWithoutConfiguredProcessorAndCreatesNoQueue()
    {
        var seeded = await Seed(); using var factory = Factory(ResolvedReader(seeded), seeded.Now);
        var plan = await ApprovedExecutionPlan(seeded, factory);
        using var requester = Client(factory, seeded.Data.RequesterToken);
        var response = await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.Status);
        await using var db = Db();
        Assert.False(await db.EnrollmentGrantOperations.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.False(await db.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.Equal(ChangePlanState.Approved, await db.Plans.Where(x => x.Id == plan.Id).Select(x => x.State).SingleAsync());
    }

    [Fact]
    public async Task ExecutionRetryAfterOriginalExpiryUsesSameOperationAndCurrentScope()
    {
        var seeded = await Seed(); var clock = new Clock(seeded.Now);
        using var factory = ExecutionFactory(seeded, clock); var plan = await ApprovedExecutionPlan(seeded, factory);
        using var requester = Client(factory, seeded.Data.RequesterToken);
        var queued = await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(HttpStatusCode.Accepted, queued.Status);
        clock.Now = seeded.Now.AddMinutes(11);
        var generation = Guid.NewGuid();
        await using (var db = Db())
        {
            await db.Sessions.Where(x => x.IdHash == SessionTokens.Hash(seeded.Data.RequesterToken))
                .ExecuteUpdateAsync(x => x.SetProperty(p => p.StepUpAt, clock.Now).SetProperty(p => p.LastSeenAt, clock.Now));
            await db.Environments.Where(x => x.Id == seeded.Data.Environment.Id).ExecuteUpdateAsync(x => x.SetProperty(p => p.Version, p => p.Version + 1));
            await db.DirectorySync.Where(x => x.EnvironmentId == seeded.Data.Environment.Id)
                .ExecuteUpdateAsync(x => x.SetProperty(p => p.Generation, generation).SetProperty(p => p.CompletedAt, clock.Now));
            await db.DirectoryObjects.Where(x => x.EnvironmentId == seeded.Data.Environment.Id)
                .ExecuteUpdateAsync(x => x.SetProperty(p => p.Generation, generation));
        }
        using var recoveryFactory = Factory(new Reader((_, _) => throw new InvalidOperationException("Historical recovery must not resolve private mapping.")), clock);
        using var recoveryClient = Client(recoveryFactory, seeded.Data.RequesterToken);
        var retry = await Post(recoveryClient, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(HttpStatusCode.OK, retry.Status);
        Assert.Equal(queued.Json.GetProperty("id").GetGuid(), retry.Json.GetProperty("id").GetGuid());
        Assert.Equal(queued.Json.GetProperty("authorizationNotAfter").GetDateTimeOffset(), retry.Json.GetProperty("authorizationNotAfter").GetDateTimeOffset());
        using var read = await recoveryClient.GetAsync(OperationPath(seeded, queued.Json.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        using var historicalPlan = await recoveryClient.GetAsync(ReadPath(seeded, plan.Id));
        Assert.Equal(HttpStatusCode.OK, historicalPlan.StatusCode);
        var historical = await historicalPlan.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Queued", historical.GetProperty("state").GetString());
        Assert.False(historical.GetProperty("canApprove").GetBoolean());
        Assert.False(historical.GetProperty("canRequest").GetBoolean());
    }

    [Fact]
    public async Task ExecutionOutboxAnchorCannotBeDeletedAndQueuedHistoryRemainsReadable()
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var plan = await ApprovedExecutionPlan(seeded, factory); using var requester = Client(factory, seeded.Data.RequesterToken);
        var queued = await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(HttpStatusCode.Accepted, queued.Status);
        var operation = queued.Json.GetProperty("id").GetGuid();
        await using (var db = Db())
        {
            var error = await Assert.ThrowsAsync<Npgsql.PostgresException>(() =>
                db.Database.ExecuteSqlInterpolatedAsync(
                    $"DELETE FROM public.\"Outbox\" WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={operation}"));
            Assert.Equal("55000", error.SqlState);
        }
        var retry = await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(HttpStatusCode.OK, retry.Status);
        await using var verify = Db();
        Assert.True(await verify.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.Equal(1, await verify.EnrollmentGrantOperations.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.Equal(1, await verify.Audit.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == "EnrollmentGrantExecution.Queued"));
        using var queuedPlan = await requester.GetAsync(ReadPath(seeded, plan.Id));
        Assert.Equal(HttpStatusCode.OK, queuedPlan.StatusCode);
    }

    [Fact]
    public async Task ExecutionQueuedDuringReadRecoversHistoryWhenPrivateMappingBecomesUnavailable()
    {
        var seeded = await Seed(); var clock = new Clock(seeded.Now);
        using var setup = ExecutionFactory(seeded, clock);
        var plan = await ApprovedExecutionPlan(seeded, setup);
        using var requester = Client(setup, seeded.Data.RequesterToken);
        var reader = new AsyncReader(async (env, directory) =>
        {
            Assert.Equal(HttpStatusCode.Accepted,
                (await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash })).Status);
            return EnrollmentTargetResult.Unavailable(env, directory, EnrollmentTargetDiagnostic.ConnectionUnavailable);
        });
        using var reading = setup.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IEnrollmentTargetReader>(); services.AddSingleton<IEnrollmentTargetReader>(reader);
        }));
        using var client = Client(reading, seeded.Data.RequesterToken);
        using var response = await client.GetAsync(ReadPath(seeded, plan.Id));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Queued", body.GetProperty("state").GetString());
        Assert.False(body.GetProperty("canApprove").GetBoolean()); Assert.False(body.GetProperty("canRequest").GetBoolean());
        Assert.Equal(1, reader.Calls);
    }

    [Theory]
    [InlineData("Environments")]
    [InlineData("Plans")]
    [InlineData("Sessions")]
    [InlineData("Profile")]
    public async Task ExecutionRechecksStepUpAfterWaitingForFinalLocks(string lockedTable)
    {
        var seeded = await Seed(); var clock = new Clock(seeded.Now);
        using var setup = ExecutionFactory(seeded, clock);
        var plan = await ApprovedExecutionPlan(seeded, setup);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reader = new AsyncReader(async (env, directory) =>
        {
            entered.TrySetResult();
            await resume.Task.WaitAsync(TimeSpan.FromSeconds(10));
            return ItManagement.AgentEnrollmentTargets.EnrollmentTargetResult.Resolved(env, directory, seeded.DeviceId, seeded.Now.AddMinutes(-1));
        });
        using var factory = setup.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<ItManagement.AgentEnrollmentTargets.IEnrollmentTargetReader>();
            services.AddSingleton<ItManagement.AgentEnrollmentTargets.IEnrollmentTargetReader>(reader);
        }));
        using var client = Client(factory, seeded.Data.RequesterToken);
        using var request = await client.MutationAsync(HttpMethod.Post, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        await using var blocker = Db(); await using var transaction = await blocker.Database.BeginTransactionAsync();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var pending = client.SendAsync(request, cancellation.Token);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            if (lockedTable == "Profile")
                await blocker.Database.ExecuteSqlRawAsync("SELECT pg_catalog.pg_advisory_xact_lock(1162235478,1)");
            else if (lockedTable == "Sessions")
                await blocker.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM public.\"Sessions\" WHERE \"IdHash\"={SessionTokens.Hash(seeded.Data.RequesterToken)} FOR UPDATE");
            else if (lockedTable == "Plans")
                await blocker.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM public.\"Plans\" WHERE \"Id\"={plan.Id} FOR UPDATE");
            else
                await blocker.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM public.\"Environments\" WHERE \"Id\"={seeded.Data.Environment.Id} FOR UPDATE");
            resume.TrySetResult();
            var blocked = false;
            for (var i = 0; i < 200 && !blocked; i++)
            {
                blocked = await blocker.Database.SqlQueryRaw<bool>("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity a WHERE pg_catalog.pg_backend_pid()=ANY(pg_catalog.pg_blocking_pids(a.pid))) AS \"Value\"").SingleAsync();
                if (!blocked) await Task.Delay(10);
            }
            Assert.True(blocked); Assert.False(pending.IsCompleted);
            clock.Now = seeded.Now.AddMinutes(6);
            await transaction.CommitAsync();
            using var response = await pending;
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            await using var verify = Db();
            Assert.False(await verify.EnrollmentGrantOperations.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
            Assert.False(await verify.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
            Assert.Equal(ChangePlanState.Approved, await verify.Plans.Where(x => x.Id == plan.Id).Select(x => x.State).SingleAsync());
        }
        finally
        {
            try { await cancellation.CancelAsync(); }
            finally
            {
                resume.TrySetResult();
                try { if (blocker.Database.CurrentTransaction is not null) await transaction.RollbackAsync(CancellationToken.None); }
                finally { await ObserveExecutionRequests(pending); }
            }
        }
    }

    [Fact]
    public async Task ExecutionConcurrentRequestsCommitOneOperationAndRecoverTheSameReceipt()
    {
        var seeded = await Seed(); var clock = new Clock(seeded.Now); var reader = ResolvedReader(seeded);
        using var factory = ExecutionFactory(seeded, clock).WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<ItManagement.AgentEnrollmentTargets.IEnrollmentTargetReader>();
            services.AddSingleton<ItManagement.AgentEnrollmentTargets.IEnrollmentTargetReader>(reader);
        }));
        var plan = await ApprovedExecutionPlan(seeded, factory);
        using var first = Client(factory, seeded.Data.RequesterToken);
        using var second = Client(factory, seeded.Data.RequesterToken);
        using var firstRequest = await first.MutationAsync(HttpMethod.Post, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        using var secondRequest = await second.MutationAsync(HttpMethod.Post, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        var calls = reader.Calls;
        await using var blocker = Db(); await using var transaction = await blocker.Database.BeginTransactionAsync();
        await blocker.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM public.\"Environments\" WHERE \"Id\"={seeded.Data.Environment.Id} FOR UPDATE");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var pendingFirst = first.SendAsync(firstRequest, cancellation.Token); var pendingSecond = second.SendAsync(secondRequest, cancellation.Token);
        try
        {
            for (var i = 0; i < 200 && reader.Calls < calls + 2; i++) await Task.Delay(10);
            Assert.Equal(calls + 2, reader.Calls); Assert.False(pendingFirst.IsCompleted); Assert.False(pendingSecond.IsCompleted);
            await transaction.CommitAsync();
            using var responseFirst = await pendingFirst; using var responseSecond = await pendingSecond;
            foreach (var response in new[] { responseFirst, responseSecond })
            {
                if (response.StatusCode is HttpStatusCode.OK or HttpStatusCode.Accepted) continue;
                var problem = await response.Content.ReadFromJsonAsync<JsonElement>();
                var title = problem.TryGetProperty("title", out var value) ? value.GetString() : "Missing problem title";
                Assert.Fail($"Concurrent execution returned {(int)response.StatusCode}: {title}");
            }
            Assert.Equal(new[] { HttpStatusCode.OK, HttpStatusCode.Accepted }, new[] { responseFirst.StatusCode, responseSecond.StatusCode }.Order().ToArray());
            var bodyFirst = await responseFirst.Content.ReadFromJsonAsync<JsonElement>();
            var bodySecond = await responseSecond.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(bodyFirst.GetProperty("id").GetGuid(), bodySecond.GetProperty("id").GetGuid());
            await using var verify = Db();
            Assert.Equal(1, await verify.EnrollmentGrantOperations.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
            Assert.Equal(1, await verify.Outbox.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
            Assert.Equal(1, await verify.Audit.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == "EnrollmentGrantExecution.Queued"));
        }
        finally
        {
            try { await cancellation.CancelAsync(); }
            finally
            {
                try { if (blocker.Database.CurrentTransaction is not null) await transaction.RollbackAsync(CancellationToken.None); }
                finally { await ObserveExecutionRequests(pendingFirst, pendingSecond); }
            }
        }
    }

    [Theory]
    [InlineData(2, false, HttpStatusCode.Accepted)]
    [InlineData(3, false, HttpStatusCode.Conflict)]
    [InlineData(1, true, HttpStatusCode.Forbidden)]
    public async Task ExecutionSerializationRetriesAreBoundedAndRevalidateSession(int failures, bool revokeSession, HttpStatusCode expected)
    {
        var seeded = await Seed();
        var armed = false;
        var attempts = 0;
        var reader = new AsyncReader(async (environment, directory) =>
        {
            if (armed && ++attempts <= failures)
            {
                if (revokeSession)
                {
                    await using var owner = Db();
                    await owner.Sessions.Where(x => x.IdHash == SessionTokens.Hash(seeded.Data.RequesterToken))
                        .ExecuteUpdateAsync(x => x.SetProperty(s => s.RevokedAt, seeded.Now));
                }
                throw new Npgsql.PostgresException("Synthetic target-read serialization failure", "ERROR", "ERROR", "40001");
            }
            return EnrollmentTargetResult.Resolved(environment, directory, seeded.DeviceId, seeded.Now.AddMinutes(-1));
        });
        using var factory = ExecutionFactory(seeded, new Clock(seeded.Now)).WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IEnrollmentTargetReader>();
            services.AddSingleton<IEnrollmentTargetReader>(reader);
        }));
        var plan = await ApprovedExecutionPlan(seeded, factory);
        using var client = Client(factory, seeded.Data.RequesterToken);
        armed = true;
        var response = await Post(client, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(expected, response.Status);
        Assert.Equal(Math.Min(failures + 1, 3), attempts);
        if (expected == HttpStatusCode.Conflict) Assert.Equal("ConcurrentChange", response.Json.GetProperty("title").GetString());
        if (expected == HttpStatusCode.Forbidden) Assert.Equal("StepUpRequired", response.Json.GetProperty("title").GetString());
        await using var verify = Db();
        var expectedWrites = expected == HttpStatusCode.Accepted ? 1 : 0;
        Assert.Equal(expectedWrites, await verify.EnrollmentGrantOperations.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.Equal(expectedWrites, await verify.Outbox.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.Equal(expectedWrites, await verify.Audit.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == "EnrollmentGrantExecution.Queued"));
        Assert.Equal(expectedWrites == 1 ? ChangePlanState.Queued : ChangePlanState.Approved,
            await verify.Plans.Where(x => x.Id == plan.Id).Select(x => x.State).SingleAsync());
    }

    private static async Task ObserveExecutionRequests(params Task<HttpResponseMessage>[] pending)
    {
        foreach (var task in pending)
        {
            try { (await task).Dispose(); }
            catch (Exception) { /* The main test path asserts results; cleanup must drain every started request. */ }
        }
    }

    [Fact]
    public async Task ExecutionAndHistoricalReadAreHiddenFromApproverAndGenericRoutes()
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var plan = await ApprovedExecutionPlan(seeded, factory);
        using var reviewer = Client(factory, seeded.Data.ReviewerToken);
        Assert.Equal(HttpStatusCode.NotFound, (await Post(reviewer, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash })).Status);
        using var requester = Client(factory, seeded.Data.RequesterToken);
        var queued = await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(HttpStatusCode.Accepted, queued.Status);
        using var read = await reviewer.GetAsync(OperationPath(seeded, queued.Json.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Post(requester, $"/api/v1/environments/{seeded.Data.Environment.Id}/plans/{plan.Id}/execute", new { planHash = plan.Hash })).Status);
    }

    [Theory]
    [InlineData("approver-disabled")]
    [InlineData("approver-membership")]
    [InlineData("version")]
    public async Task ExecutionRevalidatesApprovalAndEnvironmentBeforeQueue(string change)
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var plan = await ApprovedExecutionPlan(seeded, factory);
        await using (var db = Db())
        {
            var approval = await db.Approvals.SingleAsync(x => x.PlanId == plan.Id);
            if (change == "approver-disabled")
                await db.Principals.Where(x => x.Id == approval.ApproverId).ExecuteUpdateAsync(x => x.SetProperty(p => p.Enabled, false));
            else if (change == "approver-membership")
                await db.Memberships.Where(x => x.EnvironmentId == seeded.Data.Environment.Id && x.PrincipalId == approval.ApproverId)
                    .ExecuteUpdateAsync(x => x.SetProperty(p => p.Active, false));
            else await db.Environments.Where(x => x.Id == seeded.Data.Environment.Id).ExecuteUpdateAsync(x => x.SetProperty(p => p.Version, p => p.Version + 1));
        }
        using var client = Client(factory, seeded.Data.RequesterToken);
        Assert.Equal(HttpStatusCode.Conflict, (await Post(client, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash })).Status);
        await using var verify = Db();
        Assert.False(await verify.EnrollmentGrantOperations.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
    }

    [Fact]
    public async Task ExecutionHistoryPreventsMigrationRollbackWithoutRemovingReservations()
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var plan = await ApprovedExecutionPlan(seeded, factory);
        using var requester = Client(factory, seeded.Data.RequesterToken);
        Assert.Equal(HttpStatusCode.Accepted, (await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash })).Status);
        await using var db = Db();
        var migrator = db.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>();
        var error = await Assert.ThrowsAnyAsync<Exception>(() => migrator.MigrateAsync("20260911214940_EnrollmentGrantPlans"));
        Assert.Contains("reviewed forward migration", error.ToString(), StringComparison.OrdinalIgnoreCase);
        // The new journal is forward-only. Exercise the earlier execution-history guard independently
        // so a newer migration cannot accidentally hide a regression in the original data protection.
        var migrations = db.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrationsAssembly>();
        var executionMigration = migrations.CreateMigration(migrations.Migrations["20260912003114_EnrollmentGrantOperations"], db.Database.ProviderName!);
        var guard = executionMigration.DownOperations.OfType<Microsoft.EntityFrameworkCore.Migrations.Operations.SqlOperation>().First().Sql;
        var historyError = await Assert.ThrowsAsync<Npgsql.PostgresException>(() => db.Database.ExecuteSqlRawAsync(guard));
        Assert.Contains("execution history prevents downgrade", historyError.MessageText, StringComparison.OrdinalIgnoreCase);
        await using var verify = Db();
        Assert.True(await verify.EnrollmentGrantRecipientReservations.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.True(await verify.EnrollmentGrantOperations.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.True(await verify.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
    }

    private static string ExecutionPath(Seeded seeded, Guid plan) => $"{ReadPath(seeded, plan)}/execution";
    private static string OperationPath(Seeded seeded, Guid operation) => $"/api/v1/environments/{seeded.Data.Environment.Id}/enrollment-grant-operations/{operation}";

    private sealed class JsonValueComparer : IEqualityComparer<JsonElement>
    {
        public bool Equals(JsonElement x, JsonElement y) => x.GetRawText() == y.GetRawText();
        public int GetHashCode(JsonElement obj) => obj.GetRawText().GetHashCode(StringComparison.Ordinal);
    }
}
