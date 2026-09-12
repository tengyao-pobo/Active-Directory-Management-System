using System.Data;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    private static async Task<string> SetDeliveryContext(ConsoleDbContext db, EnrollmentGrantOperation operation)
    {
        // Receipt seeding validates deferred constraints eagerly; restore the normal transaction mode for atomic ACK/delete.
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL DEFERRED");
        var session = await db.Sessions.AsNoTracking().Where(x => x.PrincipalId == operation.RequesterId)
            .OrderByDescending(x => x.CreatedAt).FirstAsync();
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT set_config('app.delivery_environment_id',{operation.EnvironmentId.ToString()},true),
                set_config('app.delivery_operation_id',{operation.Id.ToString()},true),
                set_config('app.delivery_requester_id',{operation.RequesterId.ToString()},true)
            """);
        return session.IdHash;
    }

    private static async Task<string> ReadSealedDelivery(ConsoleDbContext db, EnrollmentGrantOperation operation, string session)
    {
        await using var command = new NpgsqlCommand("""
            SELECT * FROM enrollment_execution.get_sealed_delivery(@environment,@operation,@requester,@session)
            """, (NpgsqlConnection)db.Database.GetDbConnection(), (NpgsqlTransaction)db.Database.CurrentTransaction!.GetDbTransaction());
        command.Parameters.AddWithValue("environment", operation.EnvironmentId);
        command.Parameters.AddWithValue("operation", operation.Id);
        command.Parameters.AddWithValue("requester", operation.RequesterId);
        command.Parameters.AddWithValue("session", session);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal((short)1, reader.GetInt16(0));
        var outcome = reader.GetString(1);
        if (outcome == "Available")
        {
            Assert.Equal(operation.EnvironmentId, reader.GetGuid(2));
            Assert.Equal(operation.Id, reader.GetGuid(3));
            Assert.Equal((short)1, reader.GetInt16(4));
            Assert.Equal(operation.RecipientKeyFingerprint, reader.GetFieldValue<byte[]>(5));
            var ciphertext = reader.GetFieldValue<byte[]>(6);
            Assert.Equal(384, ciphertext.Length);
            Assert.Equal(System.Security.Cryptography.SHA256.HashData(ciphertext), reader.GetFieldValue<byte[]>(7));
            var until = reader.GetFieldValue<DateTimeOffset>(8);
            var queried = reader.GetFieldValue<DateTimeOffset>(9);
            Assert.True(until > queried && until <= queried.AddSeconds(15));
        }
        else for (var i = 2; i < 10; i++) Assert.True(reader.IsDBNull(i));
        Assert.False(await reader.ReadAsync());
        return outcome;
    }

    private static async Task<string> AcknowledgeSealedDelivery(ConsoleDbContext db, EnrollmentGrantOperation operation,
        string session, bool wrongHash = false) => await db.Database.SqlQuery<string>($"""
            SELECT ack.outcome AS "Value" FROM enrollment_execution.mint_permits permit
            CROSS JOIN LATERAL enrollment_execution.ack_sealed_delivery(
                {operation.EnvironmentId},{operation.Id},{operation.RequesterId},{session},permit.recipient_fingerprint,
                CASE WHEN {wrongHash} THEN decode(repeat('ff',32),'hex') ELSE permit.ciphertext_sha256 END) ack
            WHERE permit.operation_id={operation.Id}
            """).SingleAsync();

    [Fact]
    public async Task DeliveryHelperRequiresFreshStatusAndAcknowledgesAtomically()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var session = await SetDeliveryContext(db, operation);
        Assert.Equal("Pending", await ReadSealedDelivery(db, operation, session));
        await RecordStatus(db, operation, Guid.NewGuid(), "Available", Canonical(DateTimeOffset.UtcNow));
        Assert.Equal("Available", await ReadSealedDelivery(db, operation, session));
        Assert.Equal("Acknowledged", await AcknowledgeSealedDelivery(db, operation, session));
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        Assert.Equal("Acknowledged", await ReadSealedDelivery(db, operation, session));
        Assert.Equal("AlreadyAcknowledged", await AcknowledgeSealedDelivery(db, operation, session));
        Assert.Equal("Conflict", await AcknowledgeSealedDelivery(db, operation, session, wrongHash: true));
        Assert.Equal(0, await db.Database.SqlQuery<int>($"""
            SELECT count(*)::int AS "Value" FROM enrollment_execution.sealed_envelopes WHERE operation_id={operation.Id}
            """).SingleAsync());
    }

    [Theory]
    [InlineData("Unknown", "OutcomeUnknown")]
    [InlineData("Consumed", "Unavailable")]
    [InlineData("Revoked", "Unavailable")]
    [InlineData("Expired", "Unavailable")]
    public async Task DeliveryHelperBlocksCiphertextButAllowsAcknowledgementAfterStateChange(string state, string expected)
    {
        var operation = state == "Expired" ? await InsertExpiredQueuedOperation() : await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var session = await SetDeliveryContext(db, operation);
        var at = Canonical(DateTimeOffset.UtcNow);
        await RecordStatus(db, operation, Guid.NewGuid(), state, state == "Unknown" ? null : at,
            state is "Consumed" or "Revoked" ? operation.QueuedAt : null,
            state == "Unknown" ? "ConnectionUnavailable" : "None");
        Assert.Equal(expected, await ReadSealedDelivery(db, operation, session));
        Assert.Equal("Acknowledged", await AcknowledgeSealedDelivery(db, operation, session));
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
    }

    [Theory]
    [InlineData("step-up-old")]
    [InlineData("step-up-future")]
    [InlineData("idle")]
    [InlineData("revoked")]
    [InlineData("expired")]
    [InlineData("disabled-principal")]
    [InlineData("inactive-membership")]
    [InlineData("missing-session")]
    [InlineData("forged-context")]
    public async Task DeliveryHelperRechecksSessionAndCurrentMembershipForGetAndAck(string fault)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var session = await SetDeliveryContext(db, operation);
        await RecordStatus(db, operation, Guid.NewGuid(), "Available", Canonical(DateTimeOffset.UtcNow));
        if (fault == "disabled-principal")
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE public.\"Principals\" SET \"Enabled\"=false WHERE \"Id\"={operation.RequesterId}");
        else if (fault == "inactive-membership")
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE public.\"Memberships\" SET \"Active\"=false WHERE \"PrincipalId\"={operation.RequesterId} AND \"EnvironmentId\"={operation.EnvironmentId}");
        else if (fault == "missing-session") session = new string('F', 64);
        else if (fault == "forged-context")
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT set_config('app.delivery_requester_id',{Guid.NewGuid().ToString()},true)");
        else
        {
            var stored = await db.Sessions.SingleAsync(x => x.IdHash == session);
            var now = Canonical(DateTimeOffset.UtcNow);
            if (fault == "step-up-old") stored.StepUpAt = now.AddMinutes(-2);
            if (fault == "step-up-future") stored.StepUpAt = now.AddMinutes(1);
            if (fault == "idle") stored.LastSeenAt = now.AddMinutes(-2);
            if (fault == "revoked") stored.RevokedAt = now;
            if (fault == "expired") stored.ExpiresAt = now.AddSeconds(-1);
            await db.SaveChangesAsync();
        }
        Assert.Equal("NotFound", await ReadSealedDelivery(db, operation, session));
        Assert.Equal("NotFound", await AcknowledgeSealedDelivery(db, operation, session));
        Assert.Equal(1, await db.Database.SqlQuery<int>($"""
            SELECT count(*)::int AS "Value" FROM enrollment_execution.sealed_envelopes WHERE operation_id={operation.Id}
            """).SingleAsync());
    }

    [Theory]
    [InlineData("view")]
    [InlineData("manage")]
    [InlineData("ordinary-manage")]
    [InlineData("sync-stale")]
    [InlineData("sync-future")]
    [InlineData("sync-failed")]
    [InlineData("target-missing")]
    public async Task DeliveryHelperRechecksCurrentComputerAuthority(string fault)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var session = await SetDeliveryContext(db, operation);
        await RecordStatus(db, operation, Guid.NewGuid(), "Available", Canonical(DateTimeOffset.UtcNow));
        if (fault == "view") await RemovePermission(db, operation.EnvironmentId, operation.RequesterId, PermissionCatalog.ComputerView);
        if (fault == "manage") await RemovePermission(db, operation.EnvironmentId, operation.RequesterId, PermissionCatalog.AgentEnrollmentGrantManage);
        if (fault == "ordinary-manage") await AddOrdinaryManageRole(db, operation);
        if (fault == "target-missing") await db.DirectoryObjects.Where(x => x.EnvironmentId == operation.EnvironmentId && x.Id == operation.DirectoryObjectId).ExecuteDeleteAsync();
        if (fault.StartsWith("sync-", StringComparison.Ordinal))
        {
            var sync = await db.DirectorySync.SingleAsync(x => x.EnvironmentId == operation.EnvironmentId);
            if (fault == "sync-stale") sync.CompletedAt = Canonical(DateTimeOffset.UtcNow.AddMinutes(-16));
            if (fault == "sync-future") sync.CompletedAt = Canonical(DateTimeOffset.UtcNow.AddMinutes(1));
            if (fault == "sync-failed") sync.Status = "Failed";
            await db.SaveChangesAsync();
        }
        Assert.Equal("NotFound", await ReadSealedDelivery(db, operation, session));
        Assert.Equal("NotFound", await AcknowledgeSealedDelivery(db, operation, session));
    }

    [Fact]
    public async Task DeliveryHelperReceiptReadBindsEveryIssuedFieldAndHidesWrongEnvironment()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        Assert.True(await db.Database.SqlQuery<bool>($"""
            SELECT read.contract_version=1 AND read.outcome='Found' AND
                (read.environment_id,read.operation_id,read.grant_id,read.directory_object_id,read.device_id,
                 read.mapping_created_at,read.grant_created_at,read.grant_expires_at,read.issue_contract_version,
                 read.mint_permit_not_after,read.token_sha256,read.authorization_digest)
                IS NOT DISTINCT FROM
                (stored.environment_id,stored.operation_id,stored.grant_id,stored.directory_object_id,stored.device_id,
                 stored.mapping_created_at,stored.grant_created_at,stored.grant_expires_at,stored.issue_contract_version,
                 stored.mint_permit_not_after,stored.token_sha256,stored.authorization_digest) AS "Value"
            FROM enrollment_execution.issue_results stored
            CROSS JOIN LATERAL enrollment_execution.read_status_refresh_receipt({operation.EnvironmentId},{operation.Id}) read
            WHERE stored.operation_id={operation.Id}
            """).SingleAsync());
        Assert.True(await db.Database.SqlQuery<bool>($"""
            SELECT contract_version=1 AND outcome='NotFound' AND
                (environment_id,operation_id,grant_id,directory_object_id,device_id,mapping_created_at,grant_created_at,
                 grant_expires_at,issue_contract_version,mint_permit_not_after,token_sha256,authorization_digest) IS NULL AS "Value"
            FROM enrollment_execution.read_status_refresh_receipt({Guid.NewGuid()},{operation.Id})
            """).SingleAsync());
    }

    [Fact]
    public async Task DeliveryHelperReceiptReadDoesNotBlockAcknowledgement()
    {
        var operation = await QueuedJournalOperation();
        await using (var setup = Db())
        await using (var tx = await setup.Database.BeginTransactionAsync(IsolationLevel.Serializable))
        {
            await SeedStatusReceipt(setup, operation);
            await tx.CommitAsync();
        }
        await using var statusDb = Db();
        await using var statusTx = await statusDb.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        Assert.Equal("Found", await statusDb.Database.SqlQuery<string>($"""
            SELECT outcome AS "Value" FROM enrollment_execution.read_status_refresh_receipt({operation.EnvironmentId},{operation.Id})
            """).SingleAsync());
        // Keep the reader transaction open while a different connection confirms delivery.
        await using var ackDb = Db();
        ackDb.Database.SetCommandTimeout(3);
        await using var ackTx = await ackDb.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        var session = await SetDeliveryContext(ackDb, operation);
        Assert.Equal("Acknowledged", await AcknowledgeSealedDelivery(ackDb, operation, session));
        await ackTx.CommitAsync();
        await statusTx.CommitAsync();
    }
}
