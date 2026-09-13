using System.Data;
using ItManagement.EnrollmentGrantDelivery;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Fact]
    public async Task DeliveryCodecsDecodeRealOwnerHelperSchemasAndAtomicAcknowledgement()
    {
        // Owner-only synthetic evidence: this does not attest runtime profile4 or activate delivery.
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var session = await SetDeliveryContext(db, operation);
        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        var transaction = (NpgsqlTransaction)tx.GetDbTransaction();

        await using (var command = new NpgsqlCommand(
            "SELECT * FROM enrollment_execution.read_status_refresh_receipt(@environment,@operation)", connection, transaction))
        {
            command.Parameters.AddWithValue("environment", operation.EnvironmentId);
            command.Parameters.AddWithValue("operation", operation.Id);
            await using var reader = await command.ExecuteReaderAsync();
            var receipt = await PostgresEnrollmentDeliveryCodec.ReadReceiptAsync(
                reader, operation.EnvironmentId, operation.Id, CancellationToken.None);
            Assert.Equal(EnrollmentGrantStatusReceiptOutcome.Found, receipt.Outcome);
            Assert.NotNull(receipt.Receipt);
            Assert.Equal(operation.ServerDeviceId, receipt.Receipt.DeviceId);
        }

        var observedAt = Canonical(DateTimeOffset.UtcNow);
        var observationId = Guid.NewGuid();
        Assert.True(EnrollmentGrantStatusObservationCandidate.TryCreate(
            observationId, operation.EnvironmentId, operation.Id, EnrollmentGrantStatus.Available,
            EnrollmentGrantStatusDiagnostic.None, observedAt, null, operation.QueuedAt,
            operation.QueuedAt.AddSeconds(600), out var candidate));
        await using (var command = new NpgsqlCommand("""
            SELECT status.* FROM enrollment_execution.issue_results receipt
            CROSS JOIN LATERAL enrollment_execution.record_status_observation(
                @environment,@operation,@observation,'Available','None',@observed,NULL::timestamptz,
                receipt.grant_id,receipt.directory_object_id,receipt.device_id,receipt.mapping_created_at,
                receipt.grant_created_at,receipt.grant_expires_at,receipt.issue_contract_version,
                receipt.mint_permit_not_after,receipt.token_sha256,receipt.authorization_digest) status
            WHERE receipt.operation_id=@operation
            """, connection, transaction))
        {
            command.Parameters.AddWithValue("environment", operation.EnvironmentId);
            command.Parameters.AddWithValue("operation", operation.Id);
            command.Parameters.AddWithValue("observation", observationId);
            command.Parameters.AddWithValue("observed", observedAt);
            await using var reader = await command.ExecuteReaderAsync();
            var observation = await PostgresEnrollmentDeliveryCodec.ReadObservationAsync(
                reader, candidate!, CancellationToken.None);
            Assert.Equal(EnrollmentGrantStatusObservationWriteOutcome.Recorded, observation.Outcome);
            Assert.NotNull(observation.Evidence);
        }
        var delivery = await ReadDelivery();
        Assert.Equal(EnrollmentGrantDeliveryOutcome.Available, delivery.Outcome);
        Assert.NotNull(delivery.Payload);

        await using (var command = new NpgsqlCommand("""
            SELECT ack.* FROM enrollment_execution.mint_permits permit
            CROSS JOIN LATERAL enrollment_execution.ack_sealed_delivery(
                @environment,@operation,@requester,@session,permit.recipient_fingerprint,permit.ciphertext_sha256) ack
            WHERE permit.operation_id=@operation
            """, connection, transaction))
        {
            AddContext(command);
            await using var reader = await command.ExecuteReaderAsync();
            Assert.Equal(EnrollmentGrantAcknowledgementOutcome.Acknowledged,
                await PostgresEnrollmentDeliveryCodec.ReadAcknowledgementAsync(reader, CancellationToken.None));
        }
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        Assert.Equal(EnrollmentGrantDeliveryOutcome.Acknowledged, (await ReadDelivery()).Outcome);

        async Task<EnrollmentGrantDeliveryResponse> ReadDelivery()
        {
            await using var command = new NpgsqlCommand(
                "SELECT * FROM enrollment_execution.get_sealed_delivery(@environment,@operation,@requester,@session)",
                connection, transaction);
            AddContext(command);
            await using var reader = await command.ExecuteReaderAsync();
            return await PostgresEnrollmentDeliveryCodec.ReadDeliveryAsync(
                reader, operation.EnvironmentId, operation.Id, CancellationToken.None);
        }

        void AddContext(NpgsqlCommand command)
        {
            command.Parameters.AddWithValue("environment", operation.EnvironmentId);
            command.Parameters.AddWithValue("operation", operation.Id);
            command.Parameters.AddWithValue("requester", operation.RequesterId);
            command.Parameters.AddWithValue("session", session);
        }
    }
}
