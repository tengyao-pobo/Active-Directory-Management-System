using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using System.Security.Cryptography;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task DeliveryHistoryRowsRejectInvalidCrossTableAndStatusHistory()
    {
        // Row-rule layer only. This privileged synthetic fixture does not prove owner
        // RLS visibility, installation readiness, or production authentication.
        var owner = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        Assert.Contains(owner.Host, new[] { "localhost", "127.0.0.1", "::1" });
        Assert.StartsWith("console_", owner.Database);
        var database = "console_delivery_history_" + Guid.NewGuid().ToString("N")[..12];
        var admin = new NpgsqlConnectionStringBuilder(owner.ConnectionString) { Database = "postgres", Pooling = false };
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var cleanup = new QueueUpgradeCleanup(admin.ConnectionString, database);
        await using (var connection = new NpgsqlConnection(admin.ConnectionString))
        {
            await connection.OpenAsync(deadline.Token);
            await using var create = new NpgsqlCommand("CREATE DATABASE " + database, connection);
            await create.ExecuteNonQueryAsync(deadline.Token);
            cleanup.DatabaseCreated = true;
        }
        owner.Database = database;
        owner.Pooling = false;
        await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(owner.ConnectionString).Options);
        await db.Database.MigrateAsync(deadline.Token);
        await db.Database.OpenConnectionAsync(deadline.Token);
        var now = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var operation = new EnrollmentGrantOperation
        {
            Id = Guid.NewGuid(), EnvironmentId = Guid.NewGuid(), PlanId = Guid.NewGuid(), RequestId = Guid.NewGuid(), ApprovalId = Guid.NewGuid(),
            RequesterId = Guid.NewGuid(), ApproverId = Guid.NewGuid(), RequesterOperatorId = Guid.NewGuid(), ApproverOperatorId = Guid.NewGuid(),
            PlanHash = new string('a', 64), DirectoryObjectId = Guid.NewGuid(), ServerDeviceId = Guid.NewGuid(), DirectoryGeneration = Guid.NewGuid(),
            MappingCreatedAt = now.AddMinutes(-1), EnvironmentVersion = 1, RecipientSpki = [1], RecipientKeyFingerprint = RandomNumberGenerator.GetBytes(32),
            QueuedAt = now, AuthorizationNotAfter = now.AddMinutes(5)
        };
        var ciphertext = RandomNumberGenerator.GetBytes(384);
        var token = RandomNumberGenerator.GetBytes(32);
        var digest = RandomNumberGenerator.GetBytes(32);
        await using (var seed = await db.Database.BeginTransactionAsync(deadline.Token))
        {
            await db.Database.ExecuteSqlRawAsync("SET LOCAL session_replication_role=replica", deadline.Token);
            db.EnrollmentGrantOperations.Add(operation);
            await db.SaveChangesAsync(deadline.Token);
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO enrollment_execution.mint_permits(operation_id,format_version,issued_at,not_after,token_sha256,recipient_fingerprint,ciphertext_sha256,authorization_digest)
                VALUES({operation.Id},1,{now},{now.AddSeconds(60)},{token},{operation.RecipientKeyFingerprint},{SHA256.HashData(ciphertext)},{digest});
                INSERT INTO enrollment_execution.sealed_envelopes(operation_id,ciphertext) VALUES({operation.Id},{ciphertext});
                INSERT INTO enrollment_execution.issue_results(operation_id,outcome,diagnostic,recorded_at,grant_id,environment_id,directory_object_id,device_id,
                    mapping_created_at,grant_created_at,grant_expires_at,issue_contract_version,mint_permit_not_after,token_sha256,authorization_digest)
                VALUES({operation.Id},'Issued','None',{now.AddSeconds(1)},{Guid.NewGuid()},{operation.EnvironmentId},{operation.DirectoryObjectId},{operation.ServerDeviceId},
                    {operation.MappingCreatedAt},{now.AddSeconds(1)},{now.AddSeconds(601)},2,{now.AddSeconds(60)},{token},{digest});
                INSERT INTO enrollment_execution.status_observations(observation_id,environment_id,operation_id,sequence,state,diagnostic,private_observed_at,recorded_at,available_until)
                VALUES({Guid.NewGuid()},{operation.EnvironmentId},{operation.Id},1,'Available','None',{now.AddSeconds(2)},{now.AddSeconds(3)},{now.AddSeconds(17)});
                """, deadline.Token);
            await seed.CommitAsync(deadline.Token);
        }
        var query = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-history-rows.sql"), deadline.Token);
        async Task<bool> Valid()
        {
            await using var command = new NpgsqlCommand(query, (NpgsqlConnection)db.Database.GetDbConnection());
            await using var reader = await command.ExecuteReaderAsync(deadline.Token);
            Assert.True(await reader.ReadAsync(deadline.Token));
            var result = reader.GetBoolean(0);
            Assert.False(await reader.ReadAsync(deadline.Token));
            return result;
        }
        Assert.True(await Valid());
        foreach (var (name, mutation, expected) in Cases())
        {
            await using var transaction = await db.Database.BeginTransactionAsync(deadline.Token);
            await using (var command = new NpgsqlCommand("SET LOCAL session_replication_role=replica; SET LOCAL search_path=pg_catalog,pg_temp; " + mutation + "; SET LOCAL session_replication_role=origin", (NpgsqlConnection)db.Database.GetDbConnection()))
                await command.ExecuteNonQueryAsync(deadline.Token);
            Assert.True(await Valid() == expected, "History row case: " + name);
            await transaction.RollbackAsync(deadline.Token);
        }
        Assert.True(await Valid());

        static IEnumerable<(string Name, string Sql, bool Expected)> Cases()
        {
            const string permit = "enrollment_execution.mint_permits";
            const string result = "enrollment_execution.issue_results";
            const string envelope = "enrollment_execution.sealed_envelopes";
            const string status = "enrollment_execution.status_observations";
            const string operations = "public.\"EnrollmentGrantOperations\"";
            const string removeStatusResult = "DELETE FROM enrollment_execution.status_observations; DELETE FROM enrollment_execution.issue_results;";
            const string randomHash = "decode(repeat('ff',32),'hex')";
            const string ack = "INSERT INTO enrollment_execution.delivery_acks(operation_id,requester_id,ciphertext_sha256,token_sha256,acknowledged_at) SELECT p.operation_id,o.\"RequesterId\",p.ciphertext_sha256,p.token_sha256,r.recorded_at+interval '1 second' FROM enrollment_execution.mint_permits p JOIN public.\"EnrollmentGrantOperations\" o ON o.\"Id\"=p.operation_id JOIN enrollment_execution.issue_results r ON r.operation_id=p.operation_id;";
            const string unknown = "UPDATE enrollment_execution.status_observations SET state='Unknown',diagnostic='ResponseUnavailable',private_observed_at=NULL,private_state_changed_at=NULL,available_until=NULL;";
            foreach (var item in new (string, string)[]
            {
                ("pending", removeStatusResult),
                ("acknowledged", ack + $"DELETE FROM {envelope}"),
                ("rejected", Reject("MappingUnavailable", "2030-01-01 00:00:01+00")),
                ("unknown", unknown),
                ("consumed", $"UPDATE {status} SET state='Consumed',private_state_changed_at=private_observed_at,available_until=NULL"),
                ("revoked-after-expiry", $"UPDATE {status} SET state='Revoked',private_state_changed_at='2030-01-01 00:11:00+00',private_observed_at='2030-01-01 00:12:00+00',recorded_at='2030-01-01 00:12:00+00',available_until=NULL"),
                ("expired", $"UPDATE {status} SET state='Expired',private_observed_at='2030-01-01 00:10:01+00',recorded_at='2030-01-01 00:10:02+00',available_until=NULL"),
                ("stopped-after-permit", removeStatusResult + Stop("StoredDataInvalid", "2030-01-01 00:00:04+00")),
                ("authorization-stop", removeStatusResult + $"DELETE FROM {envelope}; DELETE FROM {permit};" + Stop("AuthorizationChanged", "2030-01-01 00:00:04+00")),
                ("clock-reversal", unknown + $"UPDATE {status} SET recorded_at='2030-01-01 00:00:20+00';" + Observation(2,"Unknown",null,"2030-01-01 00:00:10+00",null) + Observation(3,"Available","2030-01-01 00:00:21+00","2030-01-01 00:00:22+00","2030-01-01 00:00:36+00"))
            }) yield return (item.Item1, item.Item2, true);
            foreach (var item in new (string, string)[]
            {
                ("orphan-operation", $"DELETE FROM {operations}"),
                ("permit-before-queue", $"UPDATE {permit} SET issued_at=issued_at-interval '1 second',not_after=not_after-interval '1 second'"),
                ("permit-after-authorization", $"UPDATE {operations} SET \"AuthorizationNotAfter\"=\"QueuedAt\"+interval '30 seconds'"),
                ("recipient", $"UPDATE {permit} SET recipient_fingerprint={randomHash}"),
                ("ciphertext", $"UPDATE {envelope} SET ciphertext=decode(repeat('ff',384),'hex')"),
                ("missing-envelope", $"DELETE FROM {envelope}"),
                ("orphan-permit-children", $"DELETE FROM {permit}"),
                ("orphan-receipt", $"DELETE FROM {result}"),
                ("result-before-permit", Reject("MappingUnavailable", "2029-12-31 23:59:59+00")),
                ("expired-result-too-early", Reject("MintPermitExpired", "2030-01-01 00:00:01+00")),
                ("result-environment", $"UPDATE {result} SET environment_id=gen_random_uuid()"),
                ("result-directory", $"UPDATE {result} SET directory_object_id=gen_random_uuid()"),
                ("result-device", $"UPDATE {result} SET device_id=gen_random_uuid()"),
                ("result-mapping", $"UPDATE {result} SET mapping_created_at=mapping_created_at-interval '1 second'"),
                ("result-not-after", $"UPDATE {result} SET mint_permit_not_after=mint_permit_not_after-interval '1 second'"),
                ("grant-before-permit", $"UPDATE {result} SET grant_created_at=grant_created_at-interval '2 seconds',grant_expires_at=grant_expires_at-interval '2 seconds'"),
                ("result-token", $"UPDATE {result} SET token_sha256={randomHash}"),
                ("result-digest", $"UPDATE {result} SET authorization_digest={randomHash}"),
                ("ack-retains-envelope", ack),
                ("ack-requester", ack + $"DELETE FROM {envelope}; UPDATE enrollment_execution.delivery_acks SET requester_id=gen_random_uuid()"),
                ("ack-cipher", ack + $"DELETE FROM {envelope}; UPDATE enrollment_execution.delivery_acks SET ciphertext_sha256={randomHash}"),
                ("ack-token", ack + $"DELETE FROM {envelope}; UPDATE enrollment_execution.delivery_acks SET token_sha256={randomHash}"),
                ("ack-time", ack + $"DELETE FROM {envelope}; UPDATE enrollment_execution.delivery_acks SET acknowledged_at='2030-01-01 00:00:00+00'"),
                ("stop-with-result", Stop("StoredDataInvalid", "2030-01-01 00:00:04+00")),
                ("stop-before-queue", removeStatusResult + Stop("StoredDataInvalid", "2029-12-31 23:59:59+00")),
                ("stop-before-later-permit", removeStatusResult + $"UPDATE {permit} SET issued_at=issued_at+interval '2 seconds',not_after=not_after+interval '2 seconds';" + Stop("StoredDataInvalid", "2030-01-01 00:00:01+00")),
                ("stop-requires-permit", removeStatusResult + $"DELETE FROM {envelope}; DELETE FROM {permit};" + Stop("ReceiptMismatch", "2030-01-01 00:00:04+00")),
                ("authorization-stop-with-permit", removeStatusResult + Stop("AuthorizationChanged", "2030-01-01 00:00:04+00")),
                ("expired-stop-too-early", removeStatusResult + $"DELETE FROM {envelope}; DELETE FROM {permit};" + Stop("AuthorizationExpired", "2030-01-01 00:00:04+00")),
                ("status-environment", $"UPDATE {status} SET environment_id=gen_random_uuid()"),
                ("sequence-start", $"UPDATE {status} SET sequence=2"),
                ("sequence-gap", Observation(3,"Unknown",null,"2030-01-01 00:00:04+00",null)),
                ("terminal-not-last", $"UPDATE {status} SET state='Consumed',private_state_changed_at=private_observed_at,available_until=NULL;" + Observation(2,"Unknown",null,"2030-01-01 00:00:04+00",null)),
                ("two-terminals", $"UPDATE {status} SET state='Consumed',private_state_changed_at=private_observed_at,available_until=NULL;" + Observation(2,"Expired","2030-01-01 00:10:01+00","2030-01-01 00:10:02+00",null)),
                ("private-before-grant", $"UPDATE {status} SET private_observed_at='2030-01-01 00:00:00+00',available_until='2030-01-01 00:00:15+00'"),
                ("available-deadline", $"UPDATE {status} SET available_until=available_until-interval '1 second'"),
                ("expired-too-early", $"UPDATE {status} SET state='Expired',available_until=NULL"),
                ("consumed-before-grant", $"UPDATE {status} SET state='Consumed',private_state_changed_at='2030-01-01 00:00:00+00',available_until=NULL"),
                ("consumed-after-expiry", $"UPDATE {status} SET state='Consumed',private_state_changed_at='2030-01-01 00:11:00+00',private_observed_at='2030-01-01 00:12:00+00',recorded_at='2030-01-01 00:12:00+00',available_until=NULL"),
                ("unknown-barrier", unknown + $"UPDATE {status} SET recorded_at='2030-01-01 00:00:20+00';" + Observation(2,"Available","2030-01-01 00:00:10+00","2030-01-01 00:00:11+00","2030-01-01 00:00:25+00"))
            }) yield return (item.Item1, item.Item2, false);
            static string Reject(string diagnostic, string time) => $"DELETE FROM enrollment_execution.status_observations; DELETE FROM enrollment_execution.sealed_envelopes; UPDATE enrollment_execution.issue_results SET outcome='Rejected',diagnostic='{diagnostic}',recorded_at='{time}',grant_id=NULL,environment_id=NULL,directory_object_id=NULL,device_id=NULL,mapping_created_at=NULL,grant_created_at=NULL,grant_expires_at=NULL,issue_contract_version=NULL,mint_permit_not_after=NULL,token_sha256=NULL,authorization_digest=NULL;";
            static string Stop(string reason, string time) => $"INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at) SELECT \"Id\",'{reason}','{time}' FROM public.\"EnrollmentGrantOperations\";";
            static string Observation(int sequence, string state, string? observed, string recorded, string? available) => $"INSERT INTO enrollment_execution.status_observations(observation_id,environment_id,operation_id,sequence,state,diagnostic,private_observed_at,recorded_at,available_until) SELECT gen_random_uuid(),\"EnvironmentId\",\"Id\",{sequence},'{state}','{(state == "Unknown" ? "ResponseUnavailable" : "None")}',{Time(observed)},'{recorded}',{Time(available)} FROM public.\"EnrollmentGrantOperations\";";
            static string Time(string? value) => value is null ? "NULL" : "'" + value + "'::timestamptz";
        }
    }
}
