using System.Security.Cryptography;
using System.Text.Json;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static async Task VerifyPublicationCommitBoundaryAsync(NpgsqlConnection owner, NpgsqlConnection admin,
        NpgsqlConnection api, Guid environment, CancellationToken cancellationToken)
    {
        var now = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var requester = new Principal { Id = Guid.NewGuid(), OperatorId = Guid.NewGuid(), Issuer = "publication-test", Subject = Guid.NewGuid().ToString(), Enabled = true };
        var approver = new Principal { Id = Guid.NewGuid(), OperatorId = Guid.NewGuid(), Issuer = "publication-test", Subject = Guid.NewGuid().ToString(), Enabled = true };
        var plan = new ChangePlan { EnvironmentId = environment, Id = Guid.NewGuid(), RequesterId = requester.Id,
            Action = "agent-enrollment.initial-grant.v1", ImmutablePlanJson = "{}", PlanHash = new string('a', 64),
            PolicyVersion = 1, ExpiresAt = now.AddMinutes(10), State = ChangePlanState.Approved };
        var approval = new ChangeApproval { EnvironmentId = environment, Id = Guid.NewGuid(), PlanId = plan.Id,
            PlanHash = plan.PlanHash, ApproverId = approver.Id, ApprovedAt = now, ExpiresAt = now.AddMinutes(10) };
        using var recipient = RSA.Create(2048);
        var spki = recipient.ExportSubjectPublicKeyInfo();
        var reservation = new EnrollmentGrantRecipientReservation { EnvironmentId = environment, PlanId = plan.Id,
            RequesterId = requester.Id, RequestId = Guid.NewGuid(), Fingerprint = SHA256.HashData(spki),
            RequestDigest = RandomNumberGenerator.GetBytes(32), CreatedAt = now };
        // Seed only ordinary valid prerequisites in this disposable database. No trigger,
        // RLS or replication bypass is used for the actual API publication transactions.
        await using (var seed = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(admin).Options))
        {
            seed.Principals.AddRange(requester, approver);
            seed.Memberships.AddRange(new EnvironmentMembership { EnvironmentId = environment, PrincipalId = requester.Id, Active = true },
                new EnvironmentMembership { EnvironmentId = environment, PrincipalId = approver.Id, Active = true });
            seed.Plans.Add(plan);
            seed.Approvals.Add(approval);
            seed.EnrollmentGrantRecipientReservations.Add(reservation);
            await seed.SaveChangesAsync(cancellationToken);
        }
        var operationId = Guid.NewGuid();
        EnrollmentGrantOperation Operation() => new()
        {
            EnvironmentId = environment, Id = operationId, PlanId = plan.Id, RequestId = reservation.RequestId,
            ApprovalId = approval.Id, RequesterId = requester.Id, ApproverId = approver.Id,
            RequesterOperatorId = requester.OperatorId, ApproverOperatorId = approver.OperatorId, PlanHash = plan.PlanHash,
            DirectoryObjectId = Guid.NewGuid(), ServerDeviceId = Guid.NewGuid(), MappingCreatedAt = now.AddMinutes(-1),
            DirectoryGeneration = Guid.NewGuid(), EnvironmentVersion = 1, RecipientSpki = spki,
            RecipientKeyFingerprint = reservation.Fingerprint, QueuedAt = now, AuthorizationNotAfter = now.AddMinutes(5)
        };
        OutboxMessage Outbox() => new() { EnvironmentId = environment, Id = operationId,
            EventType = EnrollmentGrantOperationContract.OutboxEvent, Version = 1, CreatedAt = now,
            Payload = JsonSerializer.Serialize(new { version = 1, environmentId = environment, operationId }) };
        async Task Publish(bool changePlan, bool operation, bool outbox, Func<Task>? afterSnapshot = null)
        {
            await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(api).Options);
            await using var transaction = await db.BeginEnvironment(environment, requester.Id, cancellationToken);
            if (afterSnapshot is not null)
            {
                await using var snapshot = new NpgsqlCommand("SELECT count(*) FROM pg_catalog.pg_class", api);
                await snapshot.ExecuteScalarAsync(cancellationToken);
                await afterSnapshot();
            }
            // Intentionally direct API DML: the database barrier must hold independently
            // of the HTTP endpoint's in-memory availability and early shared lock.
            if (changePlan)
                Assert.Equal(1, await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE public.\"Plans\" SET \"State\"=5 WHERE \"Id\"={plan.Id}", cancellationToken));
            if (operation) db.EnrollmentGrantOperations.Add(Operation());
            if (outbox) db.Outbox.Add(Outbox());
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        async Task Unchanged()
        {
            await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(admin).Options);
            Assert.Equal(ChangePlanState.Approved, await db.Plans.Where(x => x.Id == plan.Id).Select(x => x.State).SingleAsync(cancellationToken));
            Assert.False(await db.EnrollmentGrantOperations.AnyAsync(x => x.Id == operationId, cancellationToken));
            Assert.False(await db.Outbox.AnyAsync(x => x.Id == operationId, cancellationToken));
        }
        // A syntactically and referentially valid Connector binding must not be
        // accepted until its complete capability attestation is composed.
        await using (var transaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await using var binding = new NpgsqlCommand("INSERT INTO public.\"DirectoryDatabaseBindings\"(\"LoginRole\",\"Purpose\",\"ContractVersion\",\"EnvironmentId\",\"PrincipalId\") VALUES('unattested_connector','Connector',1,@environment,@principal)", owner);
            binding.Parameters.AddWithValue("environment", environment);
            binding.Parameters.AddWithValue("principal", requester.Id);
            Assert.Equal(1, await binding.ExecuteNonQueryAsync(cancellationToken));
            foreach (var function in new[] { "audit_execution_profile_structure", "audit_execution_privileges" })
            {
                await using var audit = new NpgsqlCommand($"SELECT is_valid FROM enrollment_execution.{function}(@environment)", owner);
                audit.Parameters.AddWithValue("environment", environment);
                Assert.Equal(false, await audit.ExecuteScalarAsync(cancellationToken));
            }
            await transaction.RollbackAsync(cancellationToken);
        }
        // Exercise the original membership semantics through the real API LOGIN,
        // including negative identities, before relying on it for plan publication.
        await using (var membership = new NpgsqlCommand("SELECT public.has_environment_membership(@environment,@requester),public.has_environment_membership(@environment,@approver),public.has_environment_membership(@other,@requester),public.has_environment_membership(@environment,@missing)", api))
        {
            membership.Parameters.AddWithValue("environment", environment);
            membership.Parameters.AddWithValue("requester", requester.Id);
            membership.Parameters.AddWithValue("approver", approver.Id);
            membership.Parameters.AddWithValue("other", Guid.NewGuid());
            membership.Parameters.AddWithValue("missing", Guid.NewGuid());
            await using var reader = await membership.ExecuteReaderAsync(cancellationToken);
            Assert.True(await reader.ReadAsync(cancellationToken));
            Assert.True(reader.GetBoolean(0));
            Assert.True(reader.GetBoolean(1));
            Assert.False(reader.GetBoolean(2));
            Assert.False(reader.GetBoolean(3));
            Assert.False(await reader.ReadAsync(cancellationToken));
        }
        foreach (var mode in new[] { (Plan: true, Operation: false, Outbox: false),
            (Plan: false, Operation: false, Outbox: true), (Plan: true, Operation: true, Outbox: false) })
        {
            var failure = await Assert.ThrowsAnyAsync<Exception>(() => Publish(mode.Plan, mode.Operation, mode.Outbox));
            var postgres = failure as PostgresException ?? failure.InnerException as PostgresException;
            Assert.NotNull(postgres);
            Assert.True(postgres.SqlState == "23514", $"{mode}: {postgres.SqlState}: {postgres.MessageText}");
            await Unchanged();
        }
        async Task Close()
        {
            await using var close = new NpgsqlCommand("UPDATE enrollment_execution.profile4_readiness SET state='PendingHistoryAudit',generation=generation+1,installation_nonce=@nonce,pending_at=statement_timestamp(),ready_at=NULL,ready_by=NULL", owner) { CommandTimeout = 3 };
            close.Parameters.AddWithValue("nonce", Guid.NewGuid());
            await close.ExecuteNonQueryAsync(cancellationToken);
        }
        static PostgresException Postgres(Exception error)
        {
            Exception? cause = error;
            while (cause is not null && cause is not PostgresException) cause = cause.InnerException;
            return Assert.IsType<PostgresException>(cause);
        }
        async Task Ready()
        {
            await using var ready = new NpgsqlCommand("UPDATE enrollment_execution.profile4_readiness SET state='Ready',ready_at=statement_timestamp(),ready_by=session_user", owner);
            await ready.ExecuteNonQueryAsync(cancellationToken);
        }
        await Close();
        var unavailable = await Assert.ThrowsAnyAsync<Exception>(() => Publish(true, true, true));
        var denied = Postgres(unavailable);
        Assert.Equal("55000", denied.SqlState);
        Assert.Equal("Enrollment grant publication is unavailable.", denied.MessageText);
        await Unchanged();
        await Ready();
        var stale = await Assert.ThrowsAnyAsync<Exception>(() => Publish(true, true, true, Close));
        Assert.Equal("40001", Postgres(stale).SqlState);
        await Unchanged();
        await Ready();
        await Publish(true, true, true);
        await using (var verify = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(admin).Options))
        {
            Assert.Equal(ChangePlanState.Queued, await verify.Plans.Where(x => x.Id == plan.Id).Select(x => x.State).SingleAsync(cancellationToken));
            Assert.Equal(1, await verify.EnrollmentGrantOperations.CountAsync(x => x.Id == operationId, cancellationToken));
            Assert.Equal(1, await verify.Outbox.CountAsync(x => x.Id == operationId, cancellationToken));
        }
    }
}
