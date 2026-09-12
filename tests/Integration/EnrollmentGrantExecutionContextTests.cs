using System.Security.Cryptography;
using System.Text.Json;
using ItManagement.AgentEnrollment.Plans;
using ItManagement.Core;
using ItManagement.EnrollmentGrantExecution;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Fact]
    public async Task ExecutionContextLocksAndDecodesExactQueuedPlanHistory()
    {
        var stored = await QueuedJournalOperation();
        var expected = ToExecutionOperation(stored);
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();

        var result = await ReadExecutionContext(db, expected.EnvironmentId, expected.Id, expected);

        Assert.Equal(EnrollmentGrantContextReadOutcome.Found, result.Outcome);
        var context = Assert.IsType<ValidatedEnrollmentGrantExecutionContext>(result.Context);
        Assert.Same(expected, context.Operation);
        Assert.Equal(expected.PlanHash, context.VerifiedPlanHash);
    }

    [Fact]
    public async Task ExecutionContextReturnsNotFoundForWrongEnvironmentOrOperation()
    {
        var stored = await QueuedJournalOperation();
        var expected = ToExecutionOperation(stored);
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();

        foreach (var (environment, operation) in new[]
        {
            (Guid.NewGuid(), expected.Id),
            (expected.EnvironmentId, Guid.NewGuid())
        })
        {
            var result = await ReadExecutionContext(db, environment, operation, expected);
            Assert.Equal(EnrollmentGrantContextReadOutcome.NotFound, result.Outcome);
            Assert.Null(result.Context);
        }
    }

    [Fact]
    public async Task ApiRuntimeCannotExecuteOwnerContextHelper()
    {
        var stored = await QueuedJournalOperation();
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB"));
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT * FROM enrollment_execution.lock_plan_context(@environment,@operation)", connection);
        command.Parameters.AddWithValue("environment", stored.EnvironmentId);
        command.Parameters.AddWithValue("operation", stored.Id);

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteReaderAsync());
        Assert.Equal("42501", error.SqlState);
    }

    [Fact]
    public async Task ExecutionContextHelperIsInvokerOwnedWithExactExecutionDefinerAccess()
    {
        var seed = await _fixture.SeedAsync();
        await using var profile = await ProvisionExecutionRuntime(seed.Environment.Id);
        await using var db = Db();
        Assert.Equal(1, await db.Database.SqlQuery<int>($"""
            SELECT count(*)::int AS "Value"
            FROM pg_catalog.pg_proc p
            JOIN pg_catalog.pg_class plans ON plans.oid='public."Plans"'::regclass
            JOIN pg_catalog.pg_language language ON language.oid=p.prolang
            WHERE p.oid='enrollment_execution.lock_plan_context(uuid,uuid)'::regprocedure
              AND p.proowner=plans.relowner
              AND language.lanname='plpgsql'
              AND NOT p.prosecdef AND p.provolatile='v' AND p.proparallel='u' AND p.proretset
              AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
              AND pg_catalog.pg_get_function_identity_arguments(p.oid)='p_environment uuid, p_operation uuid'
              AND (SELECT count(*)=2 AND count(DISTINCT acl.grantee)=2
                   AND bool_and(acl.grantee IN(p.proowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname={profile.DefinerRole}))
                       AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
                   FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl)
            """).SingleAsync());
    }

    [Fact]
    public async Task ExpiredHistoricalPlanStillDecodesAsStoredContext()
    {
        var stored = await InsertExpiredQueuedOperation();
        var expected = ToExecutionOperation(stored);
        Assert.True(stored.AuthorizationNotAfter < DateTimeOffset.UtcNow);
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();

        var result = await ReadExecutionContext(db, expected.EnvironmentId, expected.Id, expected);

        Assert.Equal(EnrollmentGrantContextReadOutcome.Found, result.Outcome);
        Assert.Equal(expected.PlanHash, Assert.IsType<ValidatedEnrollmentGrantExecutionContext>(result.Context).VerifiedPlanHash);
    }

    [Fact]
    public async Task ExecutionContextLocksEnvironmentUntilCallerTransactionEnds()
    {
        var stored = await QueuedJournalOperation();
        var expected = ToExecutionOperation(stored);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var holder = Db();
        await using var contender = Db();
        await using var holderTx = await holder.Database.BeginTransactionAsync(timeout.Token);
        await using var contenderTx = await contender.Database.BeginTransactionAsync(timeout.Token);
        Task<int>? pending = null;
        try
        {
            Assert.Equal(EnrollmentGrantContextReadOutcome.Found,
                (await ReadExecutionContext(holder, expected.EnvironmentId, expected.Id, expected, timeout.Token)).Outcome);
            var contenderPid = await contender.Database.SqlQueryRaw<int>(
                "SELECT pg_catalog.pg_backend_pid() AS \"Value\"").SingleAsync(timeout.Token);
            pending = contender.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE public."Environments" SET "Version"="Version"
                WHERE "Id"={expected.EnvironmentId}
                """, timeout.Token);
            await WaitUntilBlocked(contenderPid, timeout.Token);
            Assert.False(pending.IsCompleted);
            await holderTx.RollbackAsync(CancellationToken.None);
            Assert.Equal(1, await pending);
        }
        finally
        {
            try { await holderTx.RollbackAsync(CancellationToken.None); } catch { }
            try
            {
                if (pending is { IsCompleted: false }) await timeout.CancelAsync();
            }
            finally
            {
                try { if (pending is not null) await pending; } catch { }
                finally { try { await contenderTx.RollbackAsync(CancellationToken.None); } catch { } }
            }
        }
    }

    private static async Task<EnrollmentGrantContextReadResult> ReadExecutionContext(ConsoleDbContext db,
        Guid environment, Guid operation, EnrollmentGrantExecutionOperation expected,
        CancellationToken cancellationToken = default)
    {
        await db.Database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT * FROM enrollment_execution.lock_plan_context(@environment,@operation)",
            (NpgsqlConnection)db.Database.GetDbConnection(),
            (NpgsqlTransaction?)db.Database.CurrentTransaction?.GetDbTransaction());
        command.Parameters.AddWithValue("environment", environment);
        command.Parameters.AddWithValue("operation", operation);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await PostgresExecutionContextCodec.ReadAsync(reader, expected, cancellationToken);
    }

    private async Task<EnrollmentGrantOperation> InsertExpiredQueuedOperation(bool extraItem = false)
    {
        var seeded = await Seed();
        var now = Canonical(DateTimeOffset.UtcNow);
        var mappingAt = now.AddMinutes(-13);
        var reservationAt = now.AddMinutes(-12);
        var approvedAt = now.AddMinutes(-11);
        var queuedAt = now.AddMinutes(-10);
        var expiresAt = now.AddMinutes(-2);
        var requestId = Guid.NewGuid();
        var planId = Guid.NewGuid();
        var operationId = Guid.NewGuid();
        var approvalId = Guid.NewGuid();
        var spki = DecodeBase64Url(seeded.SubjectPublicKeyInfo);
        var fingerprint = SHA256.HashData(spki);
        const string reason = "historical approved enrollment grant";
        var payload = new EnrollmentGrantPlanPayload(EnrollmentGrantPlanContract.SchemaVersion,
            EnrollmentGrantPlanContract.Action, seeded.Data.Environment.Id, seeded.DirectoryObjectId, seeded.DeviceId,
            mappingAt, seeded.Generation, seeded.Data.Environment.Version, seeded.SubjectPublicKeyInfo,
            EncodeBase64Url(fingerprint), requestId, reason, seeded.Data.Requester.Id, operationId,
            EnrollmentGrantPlanContract.GrantTtlSeconds);
        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var plan = new ChangePlanService().Create(seeded.Data.Environment.Id, planId, seeded.Data.Requester.Id,
            EnrollmentGrantPlanContract.Action, json, seeded.Data.Environment.Version, expiresAt,
            Enumerable.Range(0, extraItem ? 2 : 1).Select(_ => new ChangePlanItem
                { Id = Guid.NewGuid(), TargetId = seeded.Data.Environment.Id.ToString(),
                    ExpectedVersion = seeded.Data.Environment.Version }).ToArray(), reason);
        var approval = new ChangeApproval
        {
            EnvironmentId = plan.EnvironmentId, Id = approvalId, PlanId = plan.Id, PlanHash = plan.PlanHash,
            ApproverId = seeded.Data.Reviewer.Id, ApprovedAt = approvedAt, ExpiresAt = expiresAt
        };
        var operation = new EnrollmentGrantOperation
        {
            EnvironmentId = plan.EnvironmentId, Id = operationId, PlanId = plan.Id, RequestId = requestId,
            ApprovalId = approvalId, RequesterId = seeded.Data.Requester.Id, ApproverId = seeded.Data.Reviewer.Id,
            RequesterOperatorId = seeded.Data.Requester.OperatorId, ApproverOperatorId = seeded.Data.Reviewer.OperatorId,
            PlanHash = plan.PlanHash, DirectoryObjectId = seeded.DirectoryObjectId, ServerDeviceId = seeded.DeviceId,
            MappingCreatedAt = mappingAt, DirectoryGeneration = seeded.Generation,
            EnvironmentVersion = seeded.Data.Environment.Version, RecipientSpki = spki,
            RecipientKeyFingerprint = fingerprint, QueuedAt = queuedAt, AuthorizationNotAfter = expiresAt
        };
        var reservation = new EnrollmentGrantRecipientReservation
        {
            Fingerprint = fingerprint, EnvironmentId = plan.EnvironmentId, PlanId = plan.Id,
            RequesterId = plan.RequesterId, RequestId = requestId,
            RequestDigest = EnrollmentGrantPlanValidation.ComputeRequestDigest(plan.EnvironmentId, plan.RequesterId,
                requestId, seeded.DirectoryObjectId, seeded.DeviceId, mappingAt, seeded.Data.Environment.Version,
                seeded.Generation, seeded.SubjectPublicKeyInfo, reason), CreatedAt = reservationAt
        };

        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        db.Plans.Add(plan); db.EnrollmentGrantRecipientReservations.Add(reservation);
        await db.SaveChangesAsync();
        plan.State = ChangePlanState.Approved; db.Approvals.Add(approval);
        await db.SaveChangesAsync();
        plan.State = ChangePlanState.Queued;
        await db.SaveChangesAsync();
        db.EnrollmentGrantOperations.Add(operation);
        db.Outbox.Add(new OutboxMessage
        {
            EnvironmentId = operation.EnvironmentId, Id = operation.Id,
            EventType = EnrollmentGrantOperationContract.OutboxEvent, Version = EnrollmentGrantOperationContract.SchemaVersion,
            Payload = JsonSerializer.Serialize(new EnrollmentGrantExecutionNotification(1, operation.EnvironmentId, operation.Id),
                new JsonSerializerOptions(JsonSerializerDefaults.Web)),
            CreatedAt = operation.QueuedAt
        });
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return operation;
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight((padded.Length + 3) / 4 * 4, '=');
        return Convert.FromBase64String(padded);
    }

    private static string EncodeBase64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
