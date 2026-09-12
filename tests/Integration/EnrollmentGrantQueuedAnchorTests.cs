using System.Net;
using System.Text.Json;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Fact]
    public async Task QueueCommitsExactAnchorsAndFreezesPlanChildrenAndOutboxIdentity()
    {
        var (seeded, planId, operationId) = await QueueAnchoredPlan();
        await using var db = Db();
        var operation = await db.EnrollmentGrantOperations.SingleAsync(x => x.Id == operationId);
        var outbox = await db.Outbox.SingleAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Id == operationId);
        Assert.Equal(ChangePlanState.Queued, await db.Plans.Where(x => x.Id == planId).Select(x => x.State).SingleAsync());
        Assert.Equal(operation.QueuedAt, outbox.CreatedAt);

        await AssertSqlState("55000", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Plans\" SET \"Reason\"='changed' WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={planId}"));
        await AssertSqlState("55000", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"DELETE FROM public.\"Approvals\" WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"PlanId\"={planId}"));
        await AssertSqlState("55000", () => db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."PlanItems"("EnvironmentId","PlanId","Id","TargetId","ExpectedVersion")
            VALUES ({seeded.Data.Environment.Id},{planId},{Guid.NewGuid()},'late',1)
            """));
        await AssertSqlState("55000", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Outbox\" SET \"Payload\"='{{}}'::jsonb WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={operationId}"));
        await AssertSqlState("55000", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Outbox\" SET \"EventType\"='Other' WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={operationId}"));
        await AssertSqlState("55000", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Outbox\" SET \"Id\"={Guid.NewGuid()} WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={operationId}"));
        await AssertSqlState("55000", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Outbox\" SET \"EnvironmentId\"={Guid.NewGuid()} WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={operationId}"));
        await AssertSqlState("55000", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Outbox\" SET \"Version\"=2 WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={operationId}"));
        await AssertSqlState("55000", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Outbox\" SET \"CreatedAt\"=\"CreatedAt\"+interval '1 microsecond' WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={operationId}"));
        await AssertSqlState("55000", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"DELETE FROM public.\"Outbox\" WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={operationId}"));

        var unrelated = Guid.NewGuid();
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."Outbox"("EnvironmentId","Id","EventType","Version","Payload","CreatedAt","DeliveredAt","Attempts")
            VALUES ({seeded.Data.Environment.Id},{unrelated},'Other',1,pg_catalog.jsonb_build_object(),{seeded.Now},NULL,0)
            """);
        await AssertSqlState("55000", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Outbox\" SET \"EventType\"='EnrollmentGrantExecutionRequested' WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={unrelated}"));
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"DELETE FROM public.\"Outbox\" WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={unrelated}");

        Assert.Equal(1, await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Outbox\" SET \"Attempts\"=\"Attempts\"+1 WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={operationId}"));
        Assert.Null(await db.Outbox.Where(x => x.Id == operationId).Select(x => x.DeliveredAt).SingleAsync());
    }

    [Fact]
    public async Task QueuedTransitionWithoutOperationAndOutboxRollsBackAtCommit()
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var plan = await ApprovedExecutionPlan(seeded, factory);
        await using (var db = Db())
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE public.\"Plans\" SET \"State\"=5 WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={plan.Id}");
            await AssertSqlState("23514", () => tx.CommitAsync());
        }
        await using var verify = Db();
        Assert.Equal(ChangePlanState.Approved, await verify.Plans.Where(x => x.Id == plan.Id).Select(x => x.State).SingleAsync());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task DedicatedPlanCanOnlyTransitionFromApprovedToQueued(int sourceState)
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        using var requester = Client(factory, seeded.Data.RequesterToken);
        var created = await Post(requester, CreatePath(seeded), Body(seeded, Guid.NewGuid()));
        var planId = created.Json.GetProperty("id").GetGuid(); await using var db = Db();
        if (sourceState != 0) await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Plans\" SET \"State\"={sourceState} WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={planId}");
        await AssertSqlState("23514", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Plans\" SET \"State\"=5 WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={planId}"));
        await AssertSqlState("23514", () => db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."Plans"("EnvironmentId","Id","RequesterId","Action","ImmutablePlanJson","PlanHash","PolicyVersion","ExpiresAt","State","Reason")
            SELECT "EnvironmentId",{Guid.NewGuid()},"RequesterId","Action","ImmutablePlanJson","PlanHash","PolicyVersion","ExpiresAt",5,"Reason"
            FROM public."Plans" WHERE "EnvironmentId"={seeded.Data.Environment.Id} AND "Id"={planId}
            """));
    }

    [Fact]
    public async Task ApprovedQueueTransitionCannotChangeAnyOtherPlanField()
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var plan = await ApprovedExecutionPlan(seeded, factory); await using var db = Db();
        await AssertSqlState("23514", () => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Plans\" SET \"State\"=5,\"Reason\"='changed' WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={plan.Id}"));
    }

    [Fact]
    public async Task RelevantOutboxWithoutOperationRollsBackAtCommit()
    {
        var seeded = await Seed(); var id = Guid.NewGuid();
        await using var db = Db(); await using var tx = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."Outbox"("EnvironmentId","Id","EventType","Version","Payload","CreatedAt","DeliveredAt","Attempts")
            VALUES ({seeded.Data.Environment.Id},{id},'EnrollmentGrantExecutionRequested',1,
                pg_catalog.jsonb_build_object('version',1),
                {seeded.Now},NULL,0)
            """);
        await AssertSqlState("23514", () => tx.CommitAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task QueuedPlanRequiresMissingOrWrongOutboxToFailAtCommit(bool wrongOutbox)
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var approved = await ApprovedExecutionPlan(seeded, factory);
        await using var db = Db(); await using var tx = await db.Database.BeginTransactionAsync();
        var plan = await db.Plans.SingleAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Id == approved.Id);
        var payload = JsonSerializer.Deserialize<EnrollmentGrantPlanPayload>(plan.ImmutablePlanJson,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
        var approval = await db.Approvals.SingleAsync(x => x.EnvironmentId == plan.EnvironmentId && x.PlanId == plan.Id);
        var requesterOperator = await db.Principals.Where(x => x.Id == plan.RequesterId).Select(x => x.OperatorId).SingleAsync();
        var approverOperator = await db.Principals.Where(x => x.Id == approval.ApproverId).Select(x => x.OperatorId).SingleAsync();
        var operation = new EnrollmentGrantOperation
        {
            EnvironmentId = plan.EnvironmentId, Id = payload.OperationId, PlanId = plan.Id, RequestId = payload.RequestId,
            ApprovalId = approval.Id, RequesterId = plan.RequesterId, ApproverId = approval.ApproverId,
            RequesterOperatorId = requesterOperator, ApproverOperatorId = approverOperator, PlanHash = plan.PlanHash,
            DirectoryObjectId = payload.DirectoryObjectId, ServerDeviceId = payload.ServerDeviceId,
            MappingCreatedAt = payload.MappingCreatedAt, DirectoryGeneration = payload.DirectoryGeneration,
            EnvironmentVersion = payload.EnvironmentVersion, RecipientSpki = Decode(payload.RecipientSpki),
            RecipientKeyFingerprint = Decode(payload.RecipientKeyFingerprint), QueuedAt = seeded.Now,
            AuthorizationNotAfter = seeded.Now.AddMinutes(1)
        };
        plan.State = ChangePlanState.Queued; await db.SaveChangesAsync();
        db.EnrollmentGrantOperations.Add(operation);
        if (wrongOutbox) db.Outbox.Add(new OutboxMessage
        {
            EnvironmentId = operation.EnvironmentId, Id = operation.Id, EventType = EnrollmentGrantOperationContract.OutboxEvent,
            Version = 1, Payload = "{}", CreatedAt = operation.QueuedAt
        });
        await db.SaveChangesAsync();
        await AssertSqlState("23514", () => tx.CommitAsync());
    }

    [Fact]
    public async Task MissingPlanParentIsRejectedBeforeChildWrite()
    {
        var seeded = await Seed(); await using var db = Db();
        await AssertSqlState("23514", () => db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."PlanItems"("EnvironmentId","PlanId","Id","TargetId","ExpectedVersion")
            VALUES ({seeded.Data.Environment.Id},{Guid.NewGuid()},{Guid.NewGuid()},'missing',1)
            """));
    }

    [Fact]
    public async Task RestrictedRuntimeCannotUseAnRlsInvisibleParentForChildWrites()
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var approved = await ApprovedExecutionPlan(seeded, factory); var item = Guid.NewGuid();
        await using (var owner = Db())
        {
            owner.PlanItems.Add(new ChangePlanItem { EnvironmentId = seeded.Data.Environment.Id, PlanId = approved.Id,
                Id = item, TargetId = "original", ExpectedVersion = 1 });
            await owner.SaveChangesAsync();
            await owner.Memberships.Where(x => x.EnvironmentId == seeded.Data.Environment.Id && x.PrincipalId == seeded.Data.Requester.Id)
                .ExecuteUpdateAsync(update => update.SetProperty(x => x.Active, false));
        }
        try
        {
            var connectionString = Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")
                ?? throw new InvalidOperationException("Runtime test connection is unavailable.");
            await using var runtime = new NpgsqlConnection(connectionString); await runtime.OpenAsync();
            await using var tx = await runtime.BeginTransactionAsync();
            await using (var context = new NpgsqlCommand("SELECT set_config('app.environment_id',@environment,true),set_config('app.principal_id',@principal,true)", runtime, tx))
            {
                context.Parameters.AddWithValue("environment", seeded.Data.Environment.Id.ToString("D"));
                context.Parameters.AddWithValue("principal", seeded.Data.Requester.Id.ToString("D"));
                await context.ExecuteNonQueryAsync();
            }
            await using (var update = new NpgsqlCommand("UPDATE public.\"PlanItems\" SET \"TargetId\"='hidden' WHERE \"EnvironmentId\"=@environment AND \"Id\"=@id", runtime, tx))
            {
                update.Parameters.AddWithValue("environment", seeded.Data.Environment.Id); update.Parameters.AddWithValue("id", item);
                Assert.Equal(0, await update.ExecuteNonQueryAsync());
            }
            await using (var insert = new NpgsqlCommand("INSERT INTO public.\"PlanItems\"(\"EnvironmentId\",\"PlanId\",\"Id\",\"TargetId\",\"ExpectedVersion\") VALUES (@environment,@plan,@id,'hidden',1)", runtime, tx))
            {
                insert.Parameters.AddWithValue("environment", seeded.Data.Environment.Id);
                insert.Parameters.AddWithValue("plan", approved.Id); insert.Parameters.AddWithValue("id", Guid.NewGuid());
                var error = await Assert.ThrowsAsync<PostgresException>(() => insert.ExecuteNonQueryAsync());
                Assert.Contains(error.SqlState, new[] { "23514", "42501" });
            }
        }
        finally
        {
            await using var owner = Db();
            await owner.Memberships.Where(x => x.EnvironmentId == seeded.Data.Environment.Id && x.PrincipalId == seeded.Data.Requester.Id)
                .ExecuteUpdateAsync(update => update.SetProperty(x => x.Active, true));
        }
        await using var verify = Db();
        Assert.Equal("original", await verify.PlanItems.Where(x => x.Id == item).Select(x => x.TargetId).SingleAsync());
    }

    [Fact]
    public async Task NonEnrollmentPlanChildrenRemainMutable()
    {
        var seeded = await Seed(); var planId = Guid.NewGuid(); var itemId = Guid.NewGuid(); var approvalId = Guid.NewGuid();
        await using var db = Db();
        db.Plans.Add(new ChangePlan { EnvironmentId = seeded.Data.Environment.Id, Id = planId,
            RequesterId = seeded.Data.Requester.Id, Action = "test.other", ImmutablePlanJson = "{}",
            PlanHash = new string('b', 64), PolicyVersion = 1, ExpiresAt = seeded.Now.AddMinutes(5), State = ChangePlanState.Approved });
        db.PlanItems.Add(new ChangePlanItem { EnvironmentId = seeded.Data.Environment.Id, PlanId = planId,
            Id = itemId, TargetId = "before", ExpectedVersion = 1 });
        db.Approvals.Add(new ChangeApproval { EnvironmentId = seeded.Data.Environment.Id, PlanId = planId,
            Id = approvalId, PlanHash = new string('b', 64), ApproverId = Guid.NewGuid(), ApprovedAt = seeded.Now,
            ExpiresAt = seeded.Now.AddMinutes(5) });
        await db.SaveChangesAsync();
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"PlanItems\" SET \"TargetId\"='after' WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={itemId}");
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"Approvals\" SET \"ExpiresAt\"={seeded.Now.AddMinutes(4)} WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={approvalId}");
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"DELETE FROM public.\"PlanItems\" WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={itemId}");
    }

    [Fact]
    public async Task OperationInsertRequiresQueuedEnrollmentPlanParent()
    {
        var (seeded, _, existingOperationId) = await QueueAnchoredPlan();
        var approvedPlanId = Guid.NewGuid();
        await using var db = Db();
        var requester = await db.EnrollmentGrantOperations.Where(x => x.Id == existingOperationId)
            .Select(x => x.RequesterId).SingleAsync();
        db.Plans.Add(new ChangePlan
        {
            EnvironmentId = seeded.Data.Environment.Id,
            Id = approvedPlanId,
            RequesterId = requester,
            Action = EnrollmentGrantPlanContract.Action,
            ImmutablePlanJson = "{}",
            PlanHash = new string('b', 64),
            PolicyVersion = 1,
            ExpiresAt = seeded.Now.AddMinutes(5),
            State = ChangePlanState.Approved,
            Reason = "not queued"
        });
        await db.SaveChangesAsync();

        await AssertSqlState("23514", () => db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."EnrollmentGrantOperations"(
                "EnvironmentId","Id","PlanId","RequestId","ApprovalId","RequesterId","ApproverId",
                "RequesterOperatorId","ApproverOperatorId","PlanHash","DirectoryObjectId","ServerDeviceId",
                "MappingCreatedAt","DirectoryGeneration","EnvironmentVersion","RecipientSpki",
                "RecipientKeyFingerprint","QueuedAt","AuthorizationNotAfter")
            SELECT "EnvironmentId",{Guid.NewGuid()},{approvedPlanId},"RequestId","ApprovalId","RequesterId","ApproverId",
                "RequesterOperatorId","ApproverOperatorId","PlanHash","DirectoryObjectId","ServerDeviceId",
                "MappingCreatedAt","DirectoryGeneration","EnvironmentVersion","RecipientSpki",
                "RecipientKeyFingerprint","QueuedAt","AuthorizationNotAfter"
            FROM public."EnrollmentGrantOperations"
            WHERE "EnvironmentId"={seeded.Data.Environment.Id} AND "Id"={existingOperationId}
            """));
    }

    [Fact]
    public async Task ChildUpdatesInspectBothOldAndNewQueuedParentKeys()
    {
        var (seeded, queuedPlan, _, queuedItem) = await QueueAnchoredPlanWithItem();
        var otherPlan = Guid.NewGuid(); var otherItem = Guid.NewGuid(); var otherApproval = Guid.NewGuid();
        await using var db = Db(); var requester = await db.Plans.Where(x => x.Id == queuedPlan).Select(x => x.RequesterId).SingleAsync();
        db.Plans.Add(new ChangePlan { EnvironmentId = seeded.Data.Environment.Id, Id = otherPlan, RequesterId = requester,
            Action = "test.other", ImmutablePlanJson = "{}", PlanHash = new string('b', 64), PolicyVersion = 1,
            ExpiresAt = seeded.Now.AddMinutes(5), State = ChangePlanState.Approved });
        db.PlanItems.Add(new ChangePlanItem { EnvironmentId = seeded.Data.Environment.Id, PlanId = otherPlan,
            Id = otherItem, TargetId = "other", ExpectedVersion = 1 });
        db.Approvals.Add(new ChangeApproval { EnvironmentId = seeded.Data.Environment.Id, PlanId = otherPlan,
            Id = otherApproval, PlanHash = new string('b', 64), ApproverId = Guid.NewGuid(), ApprovedAt = seeded.Now,
            ExpiresAt = seeded.Now.AddMinutes(5) });
        await db.SaveChangesAsync();
        var queuedApproval = await db.Approvals.Where(x => x.PlanId == queuedPlan).Select(x => x.Id).SingleAsync();

        foreach (var sql in new[]
        {
            $"UPDATE public.\"PlanItems\" SET \"PlanId\"='{otherPlan:D}' WHERE \"EnvironmentId\"='{seeded.Data.Environment.Id:D}' AND \"Id\"='{queuedItem:D}'",
            $"UPDATE public.\"PlanItems\" SET \"PlanId\"='{queuedPlan:D}' WHERE \"EnvironmentId\"='{seeded.Data.Environment.Id:D}' AND \"Id\"='{otherItem:D}'",
            $"UPDATE public.\"Approvals\" SET \"PlanId\"='{otherPlan:D}' WHERE \"EnvironmentId\"='{seeded.Data.Environment.Id:D}' AND \"Id\"='{queuedApproval:D}'",
            $"UPDATE public.\"Approvals\" SET \"PlanId\"='{queuedPlan:D}' WHERE \"EnvironmentId\"='{seeded.Data.Environment.Id:D}' AND \"Id\"='{otherApproval:D}'"
        })
            await AssertSqlState("55000", () => db.Database.ExecuteSqlRawAsync(sql));
    }

    [Fact]
    public async Task ChildEditAndQueuedTransitionSerializeOnTheParentInBothDirections()
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var plan = await ApprovedExecutionPlan(seeded, factory);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        await using (var child = Db())
        await using (var queue = Db())
        await using (var childTx = await child.Database.BeginTransactionAsync(timeout.Token))
        await using (var queueTx = await queue.Database.BeginTransactionAsync(timeout.Token))
        {
            Task<int>? pendingQueue = null;
            await child.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO public."PlanItems"("EnvironmentId","PlanId","Id","TargetId","ExpectedVersion")
                VALUES ({seeded.Data.Environment.Id},{plan.Id},{Guid.NewGuid()},'held',1)
                """, timeout.Token);
            var queuePid = await queue.Database.SqlQueryRaw<int>("SELECT pg_catalog.pg_backend_pid() AS \"Value\"").SingleAsync(timeout.Token);
            try
            {
                pendingQueue = queue.Database.ExecuteSqlInterpolatedAsync(
                    $"UPDATE public.\"Plans\" SET \"State\"=5 WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={plan.Id}", timeout.Token);
                await WaitUntilBlocked(queuePid, timeout.Token); Assert.False(pendingQueue.IsCompleted);
                await childTx.RollbackAsync(CancellationToken.None); Assert.Equal(1, await pendingQueue);
            }
            finally
            {
                try { await childTx.RollbackAsync(CancellationToken.None); } catch { }
                try
                {
                    if (pendingQueue is { IsCompleted: false }) await timeout.CancelAsync();
                }
                finally
                {
                    try
                    {
                        if (pendingQueue is not null) await pendingQueue;
                    }
                    catch { }
                    finally
                    {
                        try { await queueTx.RollbackAsync(CancellationToken.None); } catch { }
                    }
                }
            }
        }

        await using (var queue = Db())
        await using (var child = Db())
        await using (var queueTx = await queue.Database.BeginTransactionAsync(timeout.Token))
        await using (var childTx = await child.Database.BeginTransactionAsync(timeout.Token))
        {
            Task<int>? pendingChild = null;
            await queue.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE public.\"Plans\" SET \"State\"=5 WHERE \"EnvironmentId\"={seeded.Data.Environment.Id} AND \"Id\"={plan.Id}", timeout.Token);
            var childPid = await child.Database.SqlQueryRaw<int>("SELECT pg_catalog.pg_backend_pid() AS \"Value\"").SingleAsync(timeout.Token);
            try
            {
                pendingChild = child.Database.ExecuteSqlInterpolatedAsync($"""
                    INSERT INTO public."PlanItems"("EnvironmentId","PlanId","Id","TargetId","ExpectedVersion")
                    VALUES ({seeded.Data.Environment.Id},{plan.Id},{Guid.NewGuid()},'waiting',1)
                    """, timeout.Token);
                await WaitUntilBlocked(childPid, timeout.Token); Assert.False(pendingChild.IsCompleted);
                await queueTx.RollbackAsync(CancellationToken.None); Assert.Equal(1, await pendingChild);
            }
            finally
            {
                try { await queueTx.RollbackAsync(CancellationToken.None); } catch { }
                try
                {
                    if (pendingChild is { IsCompleted: false }) await timeout.CancelAsync();
                }
                finally
                {
                    try
                    {
                        if (pendingChild is not null) await pendingChild;
                    }
                    catch { }
                    finally
                    {
                        try { await childTx.RollbackAsync(CancellationToken.None); } catch { }
                    }
                }
            }
        }
    }

    private async Task<(Seeded Seeded, Guid PlanId, Guid OperationId)> QueueAnchoredPlan()
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var plan = await ApprovedExecutionPlan(seeded, factory); using var requester = Client(factory, seeded.Data.RequesterToken);
        var queued = await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(HttpStatusCode.Accepted, queued.Status);
        return (seeded, plan.Id, queued.Json.GetProperty("id").GetGuid());
    }

    private async Task<(Seeded Seeded, Guid PlanId, Guid OperationId, Guid ItemId)> QueueAnchoredPlanWithItem()
    {
        var (seeded, planId, operationId) = await QueueAnchoredPlan();
        await using var db = Db();
        var itemId = await db.PlanItems.Where(x => x.EnvironmentId == seeded.Data.Environment.Id && x.PlanId == planId)
            .Select(x => x.Id).SingleAsync();
        return (seeded, planId, operationId, itemId);
    }

    private static async Task AssertSqlState(string expected, Func<Task> action)
    {
        var error = await Assert.ThrowsAsync<PostgresException>(action);
        Assert.Equal(expected, error.SqlState);
    }

    private static byte[] Decode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4); return Convert.FromBase64String(padded);
    }

    private static async Task WaitUntilBlocked(int processId, CancellationToken cancellationToken)
    {
        await using var observer = Db();
        for (var attempt = 0; attempt < 200; attempt++)
        {
            if (await observer.Database.SqlQuery<bool>(
                $"SELECT pg_catalog.cardinality(pg_catalog.pg_blocking_pids({processId}))>0 AS \"Value\"").SingleAsync(cancellationToken))
                return;
            await Task.Delay(10, cancellationToken);
        }
        throw new TimeoutException("The expected parent-row lock wait was not observed.");
    }
}
