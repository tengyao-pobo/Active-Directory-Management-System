using System.Net;
using System.Security.Cryptography;
using ItManagement.AgentEnrollment.Crypto;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    private async Task<EnrollmentGrantOperation> QueuedJournalOperation()
    {
        var seeded = await Seed();
        using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var plan = await ApprovedExecutionPlan(seeded, factory);
        using var requester = Client(factory, seeded.Data.RequesterToken);
        var queued = await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(HttpStatusCode.Accepted, queued.Status);
        var operationId = queued.Json.GetProperty("id").GetGuid();
        await using var db = Db();
        return await db.EnrollmentGrantOperations.AsNoTracking().SingleAsync(x => x.Id == operationId);
    }

    private static async Task<SealedEnrollmentGrant> InsertJournalPermit(ConsoleDbContext db,
        EnrollmentGrantOperation operation, bool includeEnvelope = true, int deadlineSeconds = 60,
        bool wrongFingerprint = false, bool wrongCiphertextDigest = false, CancellationToken ct = default, int issuedSeconds = 0)
    {
        var envelope = SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id);
        var issued = operation.QueuedAt.AddSeconds(issuedSeconds);
        var deadline = issued.AddSeconds(deadlineSeconds);
        var tokenHash = envelope.GetTokenSha256();
        var fingerprint = wrongFingerprint ? new byte[32] : envelope.GetRecipientSubjectPublicKeyInfoSha256();
        var ciphertext = envelope.GetCiphertext();
        var ciphertextHash = wrongCiphertextDigest ? new byte[32] : SHA256.HashData(ciphertext);
        var digest = SHA256.HashData("synthetic-journal-contract"u8);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.mint_permits
                (operation_id,format_version,issued_at,not_after,token_sha256,recipient_fingerprint,ciphertext_sha256,authorization_digest)
            VALUES ({operation.Id},1,{issued},{deadline},{tokenHash},{fingerprint},{ciphertextHash},{digest})
            """, ct);
        if (includeEnvelope)
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO enrollment_execution.sealed_envelopes(operation_id,ciphertext) VALUES ({operation.Id},{ciphertext})
                """, ct);
        return envelope;
    }

    private static async Task InsertJournalReceipt(ConsoleDbContext db, EnrollmentGrantOperation operation,
        bool wrongDevice = false, bool wrongHash = false, CancellationToken ct = default)
    {
        var grant = Guid.NewGuid();
        var device = wrongDevice ? Guid.NewGuid() : operation.ServerDeviceId;
        var created = operation.QueuedAt.AddSeconds(1);
        var expires = created.AddSeconds(600);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.issue_results
                (operation_id,outcome,diagnostic,recorded_at,grant_id,environment_id,directory_object_id,device_id,
                mapping_created_at,grant_created_at,grant_expires_at,issue_contract_version,mint_permit_not_after,
                token_sha256,authorization_digest)
            SELECT operation_id,'Issued','None',{created},{grant},{operation.EnvironmentId},{operation.DirectoryObjectId},{device},
                {operation.MappingCreatedAt},{created},{expires},2,not_after,
                CASE WHEN {wrongHash} THEN decode(repeat('00',32),'hex') ELSE token_sha256 END,authorization_digest
            FROM enrollment_execution.mint_permits WHERE operation_id={operation.Id}
            """, ct);
    }

    [Fact]
    public async Task JournalPermitAndEnvelopeAreAtomicAndImmutable()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await InsertJournalPermit(db, operation);
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        Assert.Equal(1, await db.Database.SqlQuery<int>($"""
            SELECT count(*)::int AS "Value" FROM enrollment_execution.mint_permits WHERE operation_id={operation.Id}
            """).SingleAsync());
        var error = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE enrollment_execution.mint_permits SET not_after=not_after+interval '1 second' WHERE operation_id={operation.Id}
            """));
        Assert.Equal("55000", error.SqlState);
    }

    [Theory]
    [InlineData("missing-envelope")]
    [InlineData("fingerprint")]
    [InlineData("ciphertext-digest")]
    [InlineData("overlong-permit")]
    public async Task JournalRejectsInvalidAtomicBinding(string fault)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        var error = await Assert.ThrowsAsync<PostgresException>(async () =>
        {
            await InsertJournalPermit(db, operation, fault != "missing-envelope", fault == "overlong-permit" ? 61 : 60,
                fault == "fingerprint", fault == "ciphertext-digest");
            await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        });
        Assert.Equal("23514", error.SqlState);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task JournalReceiptMustMatchPersistedPermitAndOperation(bool wrongDevice, bool wrongHash)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await InsertJournalPermit(db, operation);
        await InsertJournalReceipt(db, operation, wrongDevice, wrongHash);
        if (wrongDevice || wrongHash)
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE"));
            Assert.Equal("23514", error.SqlState);
        }
        else await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("retained-envelope")]
    [InlineData("wrong-requester")]
    [InlineData("wrong-token")]
    [InlineData("wrong-ciphertext-hash")]
    [InlineData("no-receipt")]
    public async Task JournalAcknowledgementRequiresReceiptProofAndAtomicEnvelopeDeletion(string fault)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await InsertJournalPermit(db, operation);
        if (fault != "no-receipt") await InsertJournalReceipt(db, operation);
        var requester = fault == "wrong-requester" ? Guid.NewGuid() : operation.RequesterId;
        var at = operation.QueuedAt.AddSeconds(2);
        var wrongHash = fault == "wrong-token";
        async Task Ack()
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO enrollment_execution.delivery_acks
                    (operation_id,requester_id,ciphertext_sha256,token_sha256,acknowledged_at)
                SELECT operation_id,{requester},CASE WHEN {fault == "wrong-ciphertext-hash"} THEN decode(repeat('00',32),'hex') ELSE ciphertext_sha256 END,
                    CASE WHEN {wrongHash} THEN decode(repeat('00',32),'hex') ELSE token_sha256 END,{at}
                FROM enrollment_execution.mint_permits WHERE operation_id={operation.Id}
                """);
            if (fault != "retained-envelope") await db.Database.ExecuteSqlInterpolatedAsync($"""
                DELETE FROM enrollment_execution.sealed_envelopes WHERE operation_id={operation.Id}
                """);
            await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        }
        if (fault == "valid") await Ack();
        else
        {
            var error = await Assert.ThrowsAsync<PostgresException>(Ack);
            Assert.Equal(fault == "no-receipt" ? "23503" : "23514", error.SqlState);
        }
    }

    [Theory]
    [InlineData("MintPermitExpired", true, true)]
    [InlineData("MintPermitExpired", false, false)]
    [InlineData("OutcomeUnknown", true, false)]
    [InlineData("ConnectionUnavailable", true, false)]
    [InlineData("OperationConflict", true, false)]
    public async Task JournalOnlyClosedDefiniteRejectionCanEraseEnvelope(string diagnostic, bool erase, bool accepted)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await InsertJournalPermit(db, operation);
        async Task Reject()
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO enrollment_execution.issue_results(operation_id,outcome,diagnostic,recorded_at)
                VALUES ({operation.Id},'Rejected',{diagnostic},{operation.QueuedAt.AddSeconds(61)})
                """);
            if (erase) await db.Database.ExecuteSqlInterpolatedAsync($"""
                DELETE FROM enrollment_execution.sealed_envelopes WHERE operation_id={operation.Id}
                """);
            await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        }
        if (accepted) await Reject();
        else Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(Reject)).SqlState);
    }

    [Fact]
    public async Task JournalCannotBeReadByApiRuntimeEvenWithForgedContext()
    {
        var operation = await QueuedJournalOperation();
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB"));
        await connection.OpenAsync();
        await using var tx = await connection.BeginTransactionAsync();
        await using var command = new NpgsqlCommand("SELECT set_config('app.environment_id',@env,true),set_config('app.principal_id',@actor,true)", connection, tx);
        command.Parameters.AddWithValue("env", operation.EnvironmentId.ToString());
        command.Parameters.AddWithValue("actor", operation.RequesterId.ToString());
        await command.ExecuteNonQueryAsync();
        command.CommandText = "SELECT * FROM enrollment_execution.sealed_envelopes";
        Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync())).SqlState);
    }

    [Theory]
    [InlineData("MappingUnavailable", -1)]
    [InlineData("MintPermitExpired", 59)]
    public async Task JournalRejectsPredatedRejection(string diagnostic, int seconds)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await InsertJournalPermit(db, operation);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.issue_results(operation_id,outcome,diagnostic,recorded_at)
            VALUES ({operation.Id},'Rejected',{diagnostic},{operation.QueuedAt.AddSeconds(seconds)});
            DELETE FROM enrollment_execution.sealed_envelopes WHERE operation_id={operation.Id};
            """);
        Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() =>
            db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE"))).SqlState);
    }

    [Theory]
    [InlineData("environment_id")]
    [InlineData("directory_object_id")]
    [InlineData("mapping_created_at")]
    [InlineData("mint_permit_not_after")]
    [InlineData("authorization_digest")]
    public async Task JournalRejectsEveryMismatchedReceiptBinding(string field)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await InsertJournalPermit(db, operation);
        // Insert a malformed row directly, before immutable history exists.
        var replacement = field switch
        {
            "environment_id" or "directory_object_id" => "'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'::uuid",
            "mapping_created_at" => "o.\"MappingCreatedAt\"-interval '1 second'",
            "mint_permit_not_after" => "p.not_after-interval '1 second'",
            "authorization_digest" => "decode(repeat('ff',32),'hex')",
            _ => throw new ArgumentOutOfRangeException(nameof(field))
        };
        var environment = field == "environment_id" ? replacement : "o.\"EnvironmentId\"";
        var directory = field == "directory_object_id" ? replacement : "o.\"DirectoryObjectId\"";
        var mapping = field == "mapping_created_at" ? replacement : "o.\"MappingCreatedAt\"";
        var deadline = field == "mint_permit_not_after" ? replacement : "p.not_after";
        var digest = field == "authorization_digest" ? replacement : "p.authorization_digest";
        // All SQL fragments above are closed test constants. Operation ID remains a parameter.
        var sql = $"""
            INSERT INTO enrollment_execution.issue_results(operation_id,outcome,diagnostic,recorded_at,grant_id,
                environment_id,directory_object_id,device_id,mapping_created_at,grant_created_at,grant_expires_at,
                issue_contract_version,mint_permit_not_after,token_sha256,authorization_digest)
            SELECT p.operation_id,'Issued','None',p.issued_at+interval '1 second',gen_random_uuid(),
                {environment},{directory},o."ServerDeviceId",{mapping},p.issued_at+interval '1 second',
                p.issued_at+interval '601 seconds',2,{deadline},p.token_sha256,{digest}
            FROM enrollment_execution.mint_permits p JOIN public."EnrollmentGrantOperations" o ON o."Id"=p.operation_id
            WHERE p.operation_id=@operation
            """;
        await db.Database.ExecuteSqlRawAsync(sql, new NpgsqlParameter("operation", operation.Id));
        Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() =>
            db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE"))).SqlState);
    }

    [Fact]
    public async Task JournalRejectsTokenReuseAcrossOperations()
    {
        var first = await QueuedJournalOperation();
        var second = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await InsertJournalPermit(db, first);
        var error = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.mint_permits(operation_id,format_version,issued_at,not_after,
                token_sha256,recipient_fingerprint,ciphertext_sha256,authorization_digest)
            SELECT {second.Id},format_version,{second.QueuedAt},{second.QueuedAt.AddSeconds(60)},
                token_sha256,{second.RecipientKeyFingerprint},ciphertext_sha256,authorization_digest
            FROM enrollment_execution.mint_permits WHERE operation_id={first.Id}
            """));
        Assert.Equal("23505", error.SqlState);
    }

    [Fact]
    public async Task JournalTwoConnectionsCommitOnlyOneEnvelopeForAnOperation()
    {
        var operation = await QueuedJournalOperation();
        await using var first = Db();
        await using var second = Db();
        await using var firstTx = await first.Database.BeginTransactionAsync();
        await using var secondTx = await second.Database.BeginTransactionAsync();
        var secondPid = await second.Database.SqlQueryRaw<int>("SELECT pg_backend_pid() AS \"Value\"").SingleAsync();
        var winner = await InsertJournalPermit(first, operation);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var collision = InsertJournalPermit(second, operation, ct: timeout.Token);
        var released = false;
        try
        {
            var waiting = false;
            while (!collision.IsCompleted)
            {
                waiting = await first.Database.SqlQuery<bool>($"""
                    SELECT cardinality(pg_blocking_pids({secondPid}))>0 AS "Value"
                    """).SingleAsync(timeout.Token);
                if (waiting) break;
                await Task.Delay(25, timeout.Token);
            }
            Assert.True(waiting, "The competing insert did not reach the operation uniqueness lock.");
            await firstTx.CommitAsync(timeout.Token);
            released = true;
            Assert.Equal("23505", (await Assert.ThrowsAsync<PostgresException>(() => collision)).SqlState);
            var actual = await first.Database.SqlQuery<byte[]>($"""
                SELECT ciphertext AS "Value" FROM enrollment_execution.sealed_envelopes WHERE operation_id={operation.Id}
                """).SingleAsync(timeout.Token);
            Assert.Equal(winner.GetCiphertext(), actual);
        }
        finally
        {
            try
            {
                if (!released) await firstTx.RollbackAsync();
            }
            finally
            {
                try { await timeout.CancelAsync(); }
                finally
                {
                    try { await collision; }
                    catch (Exception error) when (error is OperationCanceledException or NpgsqlException) { }
                    finally { await secondTx.RollbackAsync(); }
                }
            }
        }
    }

    [Theory]
    [InlineData("AuthorizationChanged", false)]
    [InlineData("AuthorizationExpired", false)]
    [InlineData("StoredDataInvalid", false)]
    [InlineData("OperationConflict", true)]
    [InlineData("ReceiptMismatch", true)]
    public async Task JournalPersistsClosedAuthorizationAndQuarantineStops(string reason, bool withPermit)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        if (withPermit) await InsertJournalPermit(db, operation);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at)
            VALUES ({operation.Id},{reason},{operation.AuthorizationNotAfter})
            """);
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        Assert.Equal(reason, await db.Database.SqlQuery<string>($"""
            SELECT reason AS "Value" FROM enrollment_execution.execution_stops WHERE operation_id={operation.Id}
            """).SingleAsync());
        Assert.Equal(withPermit, await db.Database.SqlQuery<bool>($"""
            SELECT EXISTS(SELECT 1 FROM enrollment_execution.sealed_envelopes WHERE operation_id={operation.Id}) AS "Value"
            """).SingleAsync());
        var error = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync($"""
            DELETE FROM enrollment_execution.execution_stops WHERE operation_id={operation.Id}
            """));
        Assert.Equal("55000", error.SqlState);
    }

    [Theory]
    [InlineData("AuthorizationChanged")]
    [InlineData("AuthorizationExpired")]
    public async Task JournalAuthorizationStopCannotReplaceCommittedPermit(string reason)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await InsertJournalPermit(db, operation);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at)
            VALUES ({operation.Id},{reason},{operation.AuthorizationNotAfter})
            """);
        Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() =>
            db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE"))).SqlState);
    }

    [Theory]
    [InlineData("AuthorizationChanged")]
    [InlineData("StoredDataInvalid")]
    public async Task JournalNeverMintsAfterRecordedStop(string reason)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at)
            VALUES ({operation.Id},{reason},{operation.QueuedAt})
            """);
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() => InsertJournalPermit(db, operation))).SqlState);
    }

    [Fact]
    public async Task JournalQuarantineCannotReplaceIssuedResult()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await InsertJournalPermit(db, operation);
        await InsertJournalReceipt(db, operation);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at)
            VALUES ({operation.Id},'ReceiptMismatch',{operation.AuthorizationNotAfter})
            """);
        Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() =>
            db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE"))).SqlState);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task JournalRejectsQuarantineBeforePermitOrReceiptMismatchWithoutPermit(bool missingPermit)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        if (!missingPermit) await InsertJournalPermit(db, operation, issuedSeconds: 10);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at)
            VALUES ({operation.Id},'ReceiptMismatch',{operation.QueuedAt.AddSeconds(5)})
            """);
        Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() =>
            db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE"))).SqlState);
    }

    private static async Task InsertJournalStop(ConsoleDbContext db, EnrollmentGrantOperation operation,
        string reason, CancellationToken ct = default) =>
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at)
            VALUES ({operation.Id},{reason},{operation.AuthorizationNotAfter})
            """, ct);

    private static async Task RejectBlockedJournalContender(ConsoleDbContext first,
        Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction firstTx, ConsoleDbContext second,
        Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction secondTx, Func<CancellationToken, Task> contend)
    {
        var pid = await second.Database.SqlQueryRaw<int>("SELECT pg_backend_pid() AS \"Value\"").SingleAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var pending = contend(timeout.Token);
        var released = false;
        try
        {
            var blocked = false;
            while (!pending.IsCompleted)
            {
                blocked = await first.Database.SqlQuery<bool>($"""
                    SELECT cardinality(pg_blocking_pids({pid}))>0 AS "Value"
                    """).SingleAsync(timeout.Token);
                if (blocked) break;
                await Task.Delay(25, timeout.Token);
            }
            Assert.True(blocked, "The competing transition must wait on the operation row.");
            await firstTx.CommitAsync(timeout.Token);
            released = true;
            Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() => pending)).SqlState);
        }
        finally
        {
            try { if (!released) await firstTx.RollbackAsync(); }
            finally
            {
                try { await timeout.CancelAsync(); }
                finally
                {
                    try { await pending; }
                    catch (Exception error) when (error is OperationCanceledException or NpgsqlException) { }
                    finally { await secondTx.RollbackAsync(); }
                }
            }
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task JournalConcurrentAuthorizationStopAndPermitCannotBothCommit(bool stopFirst)
    {
        var operation = await QueuedJournalOperation();
        await using var first = Db(); await using var second = Db();
        await using var firstTx = await first.Database.BeginTransactionAsync();
        await using var secondTx = await second.Database.BeginTransactionAsync();
        if (stopFirst) await InsertJournalStop(first, operation, "AuthorizationChanged");
        else await InsertJournalPermit(first, operation);
        await first.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        await RejectBlockedJournalContender(first, firstTx, second, secondTx, async ct =>
        {
            if (stopFirst) await InsertJournalPermit(second, operation, ct: ct);
            else await InsertJournalStop(second, operation, "AuthorizationChanged", ct);
            await second.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE", ct);
        });
        Assert.Equal(stopFirst, await first.Database.SqlQuery<bool>($"""
            SELECT EXISTS(SELECT 1 FROM enrollment_execution.execution_stops WHERE operation_id={operation.Id}) AS "Value"
            """).SingleAsync());
        Assert.Equal(!stopFirst, await first.Database.SqlQuery<bool>($"""
            SELECT EXISTS(SELECT 1 FROM enrollment_execution.mint_permits WHERE operation_id={operation.Id}) AS "Value"
            """).SingleAsync());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task JournalConcurrentQuarantineAndIssueResultCannotBothCommit(bool stopFirst)
    {
        var operation = await QueuedJournalOperation();
        await using (var setup = Db())
        {
            await using var tx = await setup.Database.BeginTransactionAsync();
            await InsertJournalPermit(setup, operation);
            await tx.CommitAsync();
        }
        await using var first = Db(); await using var second = Db();
        await using var firstTx = await first.Database.BeginTransactionAsync();
        await using var secondTx = await second.Database.BeginTransactionAsync();
        if (stopFirst) await InsertJournalStop(first, operation, "OperationConflict");
        else await InsertJournalReceipt(first, operation);
        await first.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        await RejectBlockedJournalContender(first, firstTx, second, secondTx, async ct =>
        {
            if (stopFirst) await InsertJournalReceipt(second, operation, ct: ct);
            else await InsertJournalStop(second, operation, "OperationConflict", ct);
            await second.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE", ct);
        });
        Assert.Equal(stopFirst, await first.Database.SqlQuery<bool>($"""
            SELECT EXISTS(SELECT 1 FROM enrollment_execution.execution_stops WHERE operation_id={operation.Id}) AS "Value"
            """).SingleAsync());
        Assert.Equal(!stopFirst, await first.Database.SqlQuery<bool>($"""
            SELECT EXISTS(SELECT 1 FROM enrollment_execution.issue_results WHERE operation_id={operation.Id}) AS "Value"
            """).SingleAsync());
    }
}
