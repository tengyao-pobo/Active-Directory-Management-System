using System.Security.Cryptography;
using System.Text.Json;
using ItManagement.AgentEnrollment.Crypto;
using ItManagement.Core;
using ItManagement.EnrollmentGrantExecution;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData("queued", EnrollmentGrantExecutionState.Queued)]
    [InlineData("permit", EnrollmentGrantExecutionState.PermitStored)]
    [InlineData("issued", EnrollmentGrantExecutionState.Completed)]
    [InlineData("ack", EnrollmentGrantExecutionState.Acknowledged)]
    [InlineData("rejected", EnrollmentGrantExecutionState.PermanentRejected)]
    [InlineData("expired", EnrollmentGrantExecutionState.PermanentRejected)]
    [InlineData("stopped-before", EnrollmentGrantExecutionState.Quarantined)]
    [InlineData("stopped-after", EnrollmentGrantExecutionState.Quarantined)]
    public async Task ExecutionReadContractDecodesRealPostgresStates(string stage, EnrollmentGrantExecutionState expected)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        if (stage is "permit" or "issued" or "ack" or "rejected" or "stopped-after")
            await InsertCanonicalReadPermit(db, operation);
        if (stage is "issued" or "ack") await InsertJournalReceipt(db, operation);
        if (stage == "ack")
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO enrollment_execution.delivery_acks
                    (operation_id,requester_id,ciphertext_sha256,token_sha256,acknowledged_at)
                SELECT operation_id,{operation.RequesterId},ciphertext_sha256,token_sha256,{operation.QueuedAt.AddSeconds(2)}
                FROM enrollment_execution.mint_permits WHERE operation_id={operation.Id};
                DELETE FROM enrollment_execution.sealed_envelopes WHERE operation_id={operation.Id}
                """);
        }
        if (stage == "rejected")
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO enrollment_execution.issue_results(operation_id,outcome,diagnostic,recorded_at)
                VALUES ({operation.Id},'Rejected','MappingUnavailable',{operation.QueuedAt.AddSeconds(1)});
                DELETE FROM enrollment_execution.sealed_envelopes WHERE operation_id={operation.Id}
                """);
        if (stage is "expired" or "stopped-before" or "stopped-after")
        {
            var reason = stage == "expired" ? "AuthorizationExpired" : "StoredDataInvalid";
            var recordedAt = stage == "expired" ? operation.AuthorizationNotAfter : operation.QueuedAt.AddSeconds(1);
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at)
                VALUES ({operation.Id},{reason},{recordedAt})
                """);
        }
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        var read = await ReadSqlExecution(db, operation.EnvironmentId, operation.Id);
        Assert.Equal(EnrollmentGrantStoreReadOutcome.Found, read.Outcome);
        Assert.NotNull(read.Record);
        Assert.Equal(expected, read.Record.State);
        Assert.Equal(operation.PlanHash, read.Record.Operation.PlanHash);
        Assert.Equal(operation.RecipientSpki, read.Record.Operation.GetRecipientSpki());
        Assert.Equal(operation.QueuedAt, read.Record.Operation.QueuedAt);
        Assert.Equal(stage is "permit" or "issued" or "stopped-after", read.Record.Envelope is not null);
    }

    [Fact]
    public async Task ExecutionReadContractHidesOtherEnvironmentAndUnknownOperation()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await db.Database.OpenConnectionAsync();
        foreach (var (environment, id) in new[] { (Guid.NewGuid(), operation.Id), (operation.EnvironmentId, Guid.NewGuid()) })
        {
            var read = await ReadSqlExecution(db, environment, id);
            Assert.Equal(EnrollmentGrantStoreReadOutcome.NotFound, read.Outcome);
            Assert.Null(read.Record);
        }
    }

    [Fact]
    public async Task ExecutionReadContractRejectsJournalWithWrongAuthorizationDigest()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await InsertJournalPermit(db, operation); // Deliberately synthetic noncanonical digest.
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        var read = await ReadSqlExecution(db, operation.EnvironmentId, operation.Id);
        Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, read.Outcome);
        Assert.Null(read.Record);
    }

    [Fact]
    public async Task ExecutionReadHelpersRemainInvokerWithExactExecutionDefinerAccess()
    {
        var seed = await _fixture.SeedAsync();
        await using var profile = await ProvisionExecutionRuntime(seed.Environment.Id);
        await using var db = Db();
        Assert.Equal(2, await db.Database.SqlQuery<int>($"""
            SELECT count(*)::int AS "Value" FROM pg_catalog.pg_proc p
            WHERE p.pronamespace='enrollment_execution'::regnamespace
                AND p.proname IN ('read_record','authorization_digest') AND NOT p.prosecdef
                AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
                AND (SELECT count(*)=2 AND count(DISTINCT a.grantee)=2
                    AND bool_and(a.grantee IN(p.proowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname={profile.DefinerRole}))
                        AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)
                    FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a)
            """).SingleAsync());
        await using var runtime = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB"));
        await runtime.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT * FROM enrollment_execution.read_record(@environment,@operation)", runtime);
        command.Parameters.AddWithValue("environment", Guid.NewGuid());
        command.Parameters.AddWithValue("operation", Guid.NewGuid());
        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteReaderAsync());
        Assert.Equal("42501", error.SqlState);
    }

    private static async Task<EnrollmentGrantStoreReadResult> ReadSqlExecution(ConsoleDbContext db, Guid environment, Guid operation)
    {
        await using var command = new NpgsqlCommand("SELECT * FROM enrollment_execution.read_record(@environment,@operation)",
            (NpgsqlConnection)db.Database.GetDbConnection(), (NpgsqlTransaction?)db.Database.CurrentTransaction?.GetDbTransaction());
        command.Parameters.AddWithValue("environment", environment);
        command.Parameters.AddWithValue("operation", operation);
        await using var reader = await command.ExecuteReaderAsync();
        return await PostgresExecutionRecordCodec.ReadAsync(reader, environment, operation, CancellationToken.None);
    }

    private static async Task InsertCanonicalReadPermit(ConsoleDbContext db, EnrollmentGrantOperation operation)
    {
        var envelope = SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id);
        var token = envelope.GetTokenSha256();
        var fingerprint = envelope.GetRecipientSubjectPublicKeyInfoSha256();
        var ciphertext = envelope.GetCiphertext();
        var ciphertextHash = SHA256.HashData(ciphertext);
        var issued = operation.QueuedAt;
        var deadline = issued.AddSeconds(60);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.mint_permits
                (operation_id,format_version,issued_at,not_after,token_sha256,recipient_fingerprint,ciphertext_sha256,authorization_digest)
            SELECT o."Id",1,{issued},{deadline},{token},{fingerprint},{ciphertextHash},
                enrollment_execution.authorization_digest(o,1::smallint,{issued},{deadline},{token},{fingerprint},{ciphertextHash})
            FROM public."EnrollmentGrantOperations" o WHERE o."Id"={operation.Id};
            INSERT INTO enrollment_execution.sealed_envelopes(operation_id,ciphertext) VALUES ({operation.Id},{ciphertext})
            """);
    }

    [Fact]
    public async Task ExecutionSqlDigestMatchesCanonicalVectorEveryFieldAndTimeZone()
    {
        var baseline = DigestVectorOperation();
        var issued = baseline.QueuedAt.AddMinutes(1);
        var deadline = issued.AddMinutes(1);
        var token = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var cipher = Enumerable.Repeat((byte)0x22, 32).ToArray();
        await using var db = Db();
        await db.Database.OpenConnectionAsync();
        var expected = EnrollmentGrantAuthorizationDigest.Compute(ToExecutionOperation(baseline), 1, issued, deadline,
            token, baseline.RecipientKeyFingerprint, cipher);
        Assert.Equal("210FEA5449810D619EF3E5FED16435448AF5C7E48063A4A0651BC10FF14CE255", Convert.ToHexString(expected));
        foreach (var zone in new[] { "UTC", "Asia/Taipei", "America/New_York" })
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_catalog.set_config('TimeZone',{zone},false)");
            Assert.Equal(expected, await SqlDigest(db, baseline, issued, deadline, token, baseline.RecipientKeyFingerprint, cipher));
        }
        var changes = new Action<EnrollmentGrantOperation>[]
        {
            o => o.EnvironmentId=Guid.NewGuid(), o => o.Id=Guid.NewGuid(), o => o.PlanId=Guid.NewGuid(),
            o => o.RequestId=Guid.NewGuid(), o => o.ApprovalId=Guid.NewGuid(), o => o.RequesterId=Guid.NewGuid(),
            o => o.ApproverId=Guid.NewGuid(), o => o.RequesterOperatorId=Guid.NewGuid(), o => o.ApproverOperatorId=Guid.NewGuid(),
            o => o.PlanHash=new string('b',64), o => o.DirectoryObjectId=Guid.NewGuid(), o => o.ServerDeviceId=Guid.NewGuid(),
            o => o.MappingCreatedAt=o.MappingCreatedAt.AddTicks(10), o => o.DirectoryGeneration=Guid.NewGuid(),
            o => o.EnvironmentVersion++, o => { using var rsa=RSA.Create(3072); o.RecipientSpki=rsa.ExportSubjectPublicKeyInfo();
                o.RecipientKeyFingerprint=SHA256.HashData(o.RecipientSpki); },
            o => o.QueuedAt=o.QueuedAt.AddTicks(10), o => o.AuthorizationNotAfter=o.AuthorizationNotAfter.AddTicks(-10)
        };
        foreach (var change in changes)
        {
            var operation = DigestVectorOperation();
            change(operation);
            var csharp = EnrollmentGrantAuthorizationDigest.Compute(ToExecutionOperation(operation),1,issued,deadline,
                token,operation.RecipientKeyFingerprint,cipher);
            Assert.NotEqual(expected,csharp);
            Assert.Equal(csharp,await SqlDigest(db,operation,issued,deadline,token,operation.RecipientKeyFingerprint,cipher));
        }
        foreach (var field in Enumerable.Range(0,5))
        {
            var changedToken=(byte[])token.Clone(); var changedFingerprint=(byte[])baseline.RecipientKeyFingerprint.Clone();
            var changedCipher=(byte[])cipher.Clone();
            var changedIssued=field==0 ? issued.AddTicks(10) : issued;
            var changedDeadline=field==1 ? deadline.AddTicks(-10) : deadline;
            if(field==2) changedToken[0]^=0xff;
            if(field==3) changedFingerprint[0]^=0xff;
            if(field==4) changedCipher[0]^=0xff;
            if (field == 3)
            {
                var error = await Assert.ThrowsAsync<PostgresException>(() => SqlDigest(db,baseline,changedIssued,
                    changedDeadline,changedToken,changedFingerprint,changedCipher));
                Assert.Equal("22023",error.SqlState);
                continue;
            }
            var csharp=EnrollmentGrantAuthorizationDigest.Compute(ToExecutionOperation(baseline),1,changedIssued,changedDeadline,
                changedToken,changedFingerprint,changedCipher);
            Assert.NotEqual(expected,csharp);
            Assert.Equal(csharp,await SqlDigest(db,baseline,changedIssued,changedDeadline,changedToken,changedFingerprint,changedCipher));
        }
    }

    private static async Task<byte[]> SqlDigest(ConsoleDbContext db,EnrollmentGrantOperation operation,
        DateTimeOffset issued,DateTimeOffset deadline,byte[] token,byte[] fingerprint,byte[] cipher)
    {
        var json=JsonSerializer.Serialize(operation);
        return await db.Database.SqlQuery<byte[]>($"""
            SELECT enrollment_execution.authorization_digest(
                pg_catalog.jsonb_populate_record(NULL::public."EnrollmentGrantOperations",{json}::jsonb ||
                    jsonb_build_object('RecipientSpki',chr(92)||'x'||encode({operation.RecipientSpki},'hex'),
                        'RecipientKeyFingerprint',chr(92)||'x'||encode({operation.RecipientKeyFingerprint},'hex'))),
                1::smallint,{issued},{deadline},{token},{fingerprint},{cipher}) AS "Value"
            """).SingleAsync();
    }

    private static EnrollmentGrantExecutionOperation ToExecutionOperation(EnrollmentGrantOperation o) =>
        new(o.EnvironmentId,o.Id,o.PlanId,o.RequestId,o.ApprovalId,o.RequesterId,o.ApproverId,
            o.RequesterOperatorId,o.ApproverOperatorId,o.PlanHash,o.DirectoryObjectId,o.ServerDeviceId,o.MappingCreatedAt,
            o.DirectoryGeneration,o.EnvironmentVersion,o.RecipientSpki,o.RecipientKeyFingerprint,o.QueuedAt,o.AuthorizationNotAfter);

    private static EnrollmentGrantOperation DigestVectorOperation()
    {
        var spki=Convert.FromBase64String(DigestVectorSpki);
        return new()
        {
            EnvironmentId=Guid.Parse("11111111-1111-1111-1111-111111111111"),
            Id=Guid.Parse("22222222-2222-2222-2222-222222222222"),
            PlanId=Guid.Parse("33333333-3333-3333-3333-333333333333"),
            RequestId=Guid.Parse("44444444-4444-4444-4444-444444444444"),
            ApprovalId=Guid.Parse("55555555-5555-5555-5555-555555555555"),
            RequesterId=Guid.Parse("66666666-6666-6666-6666-666666666666"),
            ApproverId=Guid.Parse("77777777-7777-7777-7777-777777777777"),
            RequesterOperatorId=Guid.Parse("88888888-8888-8888-8888-888888888888"),
            ApproverOperatorId=Guid.Parse("99999999-9999-9999-9999-999999999999"),
            PlanHash=new string('a',64),
            DirectoryObjectId=Guid.Parse("aaaaaaaa-1111-1111-1111-111111111111"),
            ServerDeviceId=Guid.Parse("bbbbbbbb-1111-1111-1111-111111111111"),
            MappingCreatedAt=new(2026,9,12,0,0,0,TimeSpan.Zero),
            DirectoryGeneration=Guid.Parse("cccccccc-1111-1111-1111-111111111111"),EnvironmentVersion=7,
            RecipientSpki=spki,RecipientKeyFingerprint=SHA256.HashData(spki),
            QueuedAt=new(2026,9,12,0,1,0,TimeSpan.Zero),AuthorizationNotAfter=new(2026,9,12,0,11,0,TimeSpan.Zero)
        };
    }

    private const string DigestVectorSpki = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAl+iMe5xLwL/5QZI0X6381UpQF/3h3t4CN1WHtSKmmRUInVy6i8ilX1cAXVfd1eQqTCvEsBbee1q/4rnRW7AE0kKZDntIYDZKXDSVVrUYiixLgJpDqH777c0ICzDPVdHvFHbTOInviCD8j25sCUKlKoJYDTRjx+BtfiAEfZ3Ktuqtby59Z6Piai3gc6mw25Ov2qbJ3P9PHcJ3VqeaD04cP2fRqTyOBSbf4tLK2DsSCtodCd7Oew1r5tRYahA1trI8aKsJXPQZ2vvpvAY+IyFngtwEXXIpnsAnfzDVqhhW2mUcpMrVDK2Hg6+EdGqY5v9dWqoITqY7aJh1/dWjeDaWQI8uWeZ/VrFd/Ab8ZjO9h8reKRp2470jCY5j1X8jcVMJ5AUlngV1a5bz/nJffjUVmIUGoreXsdvjHA/KiVXOf7f/JkHxmyZJi82R5rPFAb6Q3mOVozQJZJl+SBWpjsn9p5DdajI9apFk7IA1e/GVt1MZbsjz6qhqoe6JRBkJPZbhAgMBAAE=";
}
