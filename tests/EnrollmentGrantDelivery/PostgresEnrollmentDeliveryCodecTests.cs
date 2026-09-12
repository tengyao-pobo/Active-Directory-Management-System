using System.Data;
using System.Security.Cryptography;
using ItManagement.EnrollmentGrantDelivery;
using Xunit;

namespace EnrollmentGrantDelivery.Tests;

public sealed class PostgresEnrollmentDeliveryCodecTests
{
    private static readonly Guid EnvironmentId = Guid.Parse("10000000-0000-0000-0000-000000000001");
    private static readonly Guid OperationId = Guid.Parse("20000000-0000-0000-0000-000000000002");
    private static readonly Guid ObservationId = Guid.Parse("30000000-0000-0000-0000-000000000003");
    private static readonly DateTimeOffset Epoch = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task FoundReceiptReturnsTheBoundValidatedReceipt()
    {
        using var table = ReceiptTable("Found");
        using var reader = table.CreateDataReader();

        var result = await PostgresEnrollmentDeliveryCodec.ReadReceiptAsync(
            reader, EnvironmentId, OperationId, CancellationToken.None);

        Assert.Equal(EnrollmentGrantStatusReceiptOutcome.Found, result.Outcome);
        var receipt = Assert.IsType<ItManagement.AgentPlatformGrants.PlatformGrantReceipt>(result.Receipt);
        Assert.Equal(EnvironmentId, receipt.EnvironmentId);
        Assert.Equal(OperationId, receipt.OperationId);
        Assert.Equal(Epoch, receipt.MappingCreatedAt);
        Assert.Equal(Epoch.AddSeconds(10), receipt.CreatedAt);
        Assert.Equal(Epoch.AddSeconds(610), receipt.ExpiresAt);
        Assert.Equal(2, receipt.IssueContractVersion);
        Assert.Equal(Epoch.AddSeconds(60), receipt.MintPermitNotAfter);
        Assert.Equal(Bytes(32, 7), receipt.GetTokenSha256());
        Assert.Equal(Bytes(32, 17), receipt.GetAuthorizationDigest());
    }

    [Fact]
    public async Task NotFoundReceiptRequiresAnExactNullSentinel()
    {
        using var table = ReceiptTable("NotFound");
        using (var reader = table.CreateDataReader())
        {
            var result = await PostgresEnrollmentDeliveryCodec.ReadReceiptAsync(
                reader, EnvironmentId, OperationId, CancellationToken.None);
            Assert.Equal(EnrollmentGrantStatusReceiptOutcome.NotFound, result.Outcome);
            Assert.Null(result.Receipt);
        }

        table.Rows[0][13] = Bytes(32, 17);
        AssertReceiptUnknown(await ReadReceipt(table));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public async Task FoundReceiptRejectsMismatchedRequestBinding(int column)
    {
        using var table = ReceiptTable("Found");
        table.Rows[0][column] = Guid.NewGuid();

        AssertReceiptUnknown(await ReadReceipt(table));
    }

    [Theory]
    [InlineData("null-version")]
    [InlineData("zero-version")]
    [InlineData("null-outcome")]
    [InlineData("partial-found")]
    [InlineData("duplicate-row")]
    [InlineData("missing-row")]
    public async Task MalformedReceiptSentinelsFailClosed(string defect)
    {
        using var table = ReceiptTable("Found");
        switch (defect)
        {
            case "null-version": table.Rows[0][0] = DBNull.Value; break;
            case "zero-version": table.Rows[0][0] = (short)0; break;
            case "null-outcome": table.Rows[0][1] = DBNull.Value; break;
            case "partial-found": table.Rows[0][13] = DBNull.Value; break;
            case "duplicate-row": table.ImportRow(table.Rows[0]); break;
            case "missing-row": table.Rows.Clear(); break;
        }

        AssertReceiptUnknown(await ReadReceipt(table));
    }

    [Fact]
    public async Task AvailableDeliveryReturnsTheVerifiedEnvelope()
    {
        using var table = DeliveryTable("Available");
        using var reader = table.CreateDataReader();

        var result = await PostgresEnrollmentDeliveryCodec.ReadDeliveryAsync(
            reader, EnvironmentId, OperationId, CancellationToken.None);

        Assert.Equal(EnrollmentGrantDeliveryOutcome.Available, result.Outcome);
        var payload = Assert.IsType<EnrollmentGrantDeliveryDto>(result.Payload);
        Assert.Equal(OperationId, payload.OperationId);
        Assert.Equal(1, payload.FormatVersion);
        Assert.Equal(Epoch, payload.QueriedAt);
        Assert.Equal(Epoch.AddSeconds(10), payload.DeliveryNotAfter);
    }

    [Theory]
    [InlineData("Pending", EnrollmentGrantDeliveryOutcome.Pending)]
    [InlineData("Acknowledged", EnrollmentGrantDeliveryOutcome.Acknowledged)]
    [InlineData("Unavailable", EnrollmentGrantDeliveryOutcome.Unavailable)]
    [InlineData("NotFound", EnrollmentGrantDeliveryOutcome.NotFound)]
    [InlineData("OutcomeUnknown", EnrollmentGrantDeliveryOutcome.OutcomeUnknown)]
    [InlineData("FutureOutcome", EnrollmentGrantDeliveryOutcome.OutcomeUnknown)]
    public async Task NonAvailableDeliveryOutcomesNeverCarryPayload(
        string databaseOutcome,
        EnrollmentGrantDeliveryOutcome expectedOutcome)
    {
        using var table = DeliveryTable(databaseOutcome);
        using var reader = table.CreateDataReader();

        var result = await PostgresEnrollmentDeliveryCodec.ReadDeliveryAsync(
            reader, EnvironmentId, OperationId, CancellationToken.None);

        Assert.Equal(expectedOutcome, result.Outcome);
        Assert.Null(result.Payload);
    }

    [Theory]
    [InlineData("Pending")]
    [InlineData("Acknowledged")]
    [InlineData("Unavailable")]
    [InlineData("NotFound")]
    [InlineData("OutcomeUnknown")]
    public async Task NonAvailableDeliveryRejectsForbiddenPayload(string databaseOutcome)
    {
        using var table = DeliveryTable(databaseOutcome);
        table.Rows[0][2] = EnvironmentId;

        AssertDeliveryUnknown(await ReadDelivery(table));
    }

    [Theory]
    [InlineData("Acknowledged", EnrollmentGrantAcknowledgementOutcome.Acknowledged)]
    [InlineData("AlreadyAcknowledged", EnrollmentGrantAcknowledgementOutcome.AlreadyAcknowledged)]
    [InlineData("NotFound", EnrollmentGrantAcknowledgementOutcome.NotFound)]
    [InlineData("Conflict", EnrollmentGrantAcknowledgementOutcome.Conflict)]
    [InlineData("OutcomeUnknown", EnrollmentGrantAcknowledgementOutcome.OutcomeUnknown)]
    public async Task AcknowledgementOutcomesAreExact(
        string databaseOutcome,
        EnrollmentGrantAcknowledgementOutcome expectedOutcome)
    {
        using var table = AcknowledgementTable(databaseOutcome);
        using var reader = table.CreateDataReader();

        Assert.Equal(expectedOutcome,
            await PostgresEnrollmentDeliveryCodec.ReadAcknowledgementAsync(reader, CancellationToken.None));
    }

    [Fact]
    public async Task MultipleAcknowledgementRowsFailClosed()
    {
        using var table = AcknowledgementTable("Acknowledged");
        table.ImportRow(table.Rows[0]);
        using var reader = table.CreateDataReader();

        Assert.Equal(EnrollmentGrantAcknowledgementOutcome.OutcomeUnknown,
            await PostgresEnrollmentDeliveryCodec.ReadAcknowledgementAsync(reader, CancellationToken.None));
    }

    [Fact]
    public async Task RecordedObservationReturnsNormalizedEvidence()
    {
        var candidate = ObservationCandidate();
        using var table = ObservationTable(candidate);
        using var reader = table.CreateDataReader();

        var result = await PostgresEnrollmentDeliveryCodec.ReadObservationAsync(
            reader, candidate, CancellationToken.None);

        Assert.Equal(EnrollmentGrantStatusObservationWriteOutcome.Recorded, result.Outcome);
        Assert.Equal(candidate.ObservationId, result.Evidence!.ObservationId);
        Assert.Equal(EnvironmentId, result.Evidence.EnvironmentId);
        Assert.Equal(OperationId, result.Evidence.OperationId);
        Assert.Equal(7, result.Evidence.Sequence);
    }

    [Fact]
    public async Task UnknownContractVersionsFailClosedForAllFourReaders()
    {
        using var receipt = ReceiptTable("Found"); receipt.Rows[0][0] = (short)2;
        using var delivery = DeliveryTable("Available"); delivery.Rows[0][0] = (short)2;
        using var acknowledgement = AcknowledgementTable("Acknowledged"); acknowledgement.Rows[0][0] = (short)2;
        var candidate = ObservationCandidate();
        using var observation = ObservationTable(candidate); observation.Rows[0][0] = (short)2;

        AssertReceiptUnknown(await ReadReceipt(receipt));
        AssertDeliveryUnknown(await ReadDelivery(delivery));
        AssertObservationUnknown(await ReadObservation(observation, candidate));
        using var acknowledgementReader = acknowledgement.CreateDataReader();
        Assert.Equal(EnrollmentGrantAcknowledgementOutcome.OutcomeUnknown,
            await PostgresEnrollmentDeliveryCodec.ReadAcknowledgementAsync(acknowledgementReader, CancellationToken.None));
    }

    [Fact]
    public async Task ReadersRejectWrongColumnNamesAndTypes()
    {
        using var receipt = ReceiptTable("Found"); receipt.Columns[4].ColumnName = "untrusted_grant_id";
        AssertReceiptUnknown(await ReadReceipt(receipt));

        using var delivery = DeliveryTable("Pending");
        delivery.Columns.RemoveAt(4);
        delivery.Columns.Add("format_version", typeof(int)).SetOrdinal(4);
        AssertDeliveryUnknown(await ReadDelivery(delivery));

        using var acknowledgement = AcknowledgementTable("Acknowledged");
        acknowledgement.Columns[1].ColumnName = "untrusted_outcome";
        using var acknowledgementReader = acknowledgement.CreateDataReader();
        Assert.Equal(EnrollmentGrantAcknowledgementOutcome.OutcomeUnknown,
            await PostgresEnrollmentDeliveryCodec.ReadAcknowledgementAsync(acknowledgementReader, CancellationToken.None));

        var candidate = ObservationCandidate();
        using var observation = ObservationTable(candidate);
        observation.Columns[5].ColumnName = "untrusted_sequence";
        AssertObservationUnknown(await ReadObservation(observation, candidate));
    }

    [Fact]
    public async Task ReadersRejectAdditionalResultSets()
    {
        using var receipt = ReceiptTable("Found");
        using var receiptReader = new DataTableReader([receipt, ExtraResultSet()]);
        AssertReceiptUnknown(await PostgresEnrollmentDeliveryCodec.ReadReceiptAsync(
            receiptReader, EnvironmentId, OperationId, CancellationToken.None));

        using var delivery = DeliveryTable("Pending");
        using var deliveryReader = new DataTableReader([delivery, ExtraResultSet()]);
        AssertDeliveryUnknown(await PostgresEnrollmentDeliveryCodec.ReadDeliveryAsync(
            deliveryReader, EnvironmentId, OperationId, CancellationToken.None));

        using var acknowledgement = AcknowledgementTable("Acknowledged");
        using var acknowledgementReader = new DataTableReader([acknowledgement, ExtraResultSet()]);
        Assert.Equal(EnrollmentGrantAcknowledgementOutcome.OutcomeUnknown,
            await PostgresEnrollmentDeliveryCodec.ReadAcknowledgementAsync(acknowledgementReader, CancellationToken.None));

        var candidate = ObservationCandidate();
        using var observation = ObservationTable(candidate);
        using var observationReader = new DataTableReader([observation, ExtraResultSet()]);
        AssertObservationUnknown(await PostgresEnrollmentDeliveryCodec.ReadObservationAsync(
            observationReader, candidate, CancellationToken.None));
    }

    private static async Task<EnrollmentGrantStatusReceiptResult> ReadReceipt(DataTable table)
    {
        using var reader = table.CreateDataReader();
        return await PostgresEnrollmentDeliveryCodec.ReadReceiptAsync(
            reader, EnvironmentId, OperationId, CancellationToken.None);
    }

    private static async Task<EnrollmentGrantDeliveryResponse> ReadDelivery(DataTable table)
    {
        using var reader = table.CreateDataReader();
        return await PostgresEnrollmentDeliveryCodec.ReadDeliveryAsync(
            reader, EnvironmentId, OperationId, CancellationToken.None);
    }

    private static async Task<EnrollmentGrantStatusObservationWriteResult> ReadObservation(
        DataTable table,
        EnrollmentGrantStatusObservationCandidate candidate)
    {
        using var reader = table.CreateDataReader();
        return await PostgresEnrollmentDeliveryCodec.ReadObservationAsync(
            reader, candidate, CancellationToken.None);
    }

    private static DataTable ReceiptTable(string outcome)
    {
        var table = Table(
            ("contract_version", typeof(short)), ("outcome", typeof(string)),
            ("environment_id", typeof(Guid)), ("operation_id", typeof(Guid)), ("grant_id", typeof(Guid)),
            ("directory_object_id", typeof(Guid)), ("device_id", typeof(Guid)),
            ("mapping_created_at", typeof(DateTimeOffset)), ("grant_created_at", typeof(DateTimeOffset)),
            ("grant_expires_at", typeof(DateTimeOffset)), ("issue_contract_version", typeof(short)),
            ("mint_permit_not_after", typeof(DateTimeOffset)), ("token_sha256", typeof(byte[])),
            ("authorization_digest", typeof(byte[])));
        if (outcome == "Found")
        {
            table.Rows.Add((short)1, outcome, EnvironmentId, OperationId, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
                Epoch, Epoch.AddSeconds(10), Epoch.AddSeconds(610), (short)2, Epoch.AddSeconds(60),
                Bytes(32, 7), Bytes(32, 17));
        }
        else
        {
            var row = table.NewRow(); row[0] = (short)1; row[1] = outcome; table.Rows.Add(row);
        }
        return table;
    }

    private static DataTable DeliveryTable(string outcome)
    {
        var table = Table(
            ("contract_version", typeof(short)), ("outcome", typeof(string)),
            ("environment_id", typeof(Guid)), ("operation_id", typeof(Guid)), ("format_version", typeof(short)),
            ("recipient_fingerprint", typeof(byte[])), ("ciphertext", typeof(byte[])),
            ("ciphertext_sha256", typeof(byte[])), ("delivery_not_after", typeof(DateTimeOffset)),
            ("queried_at", typeof(DateTimeOffset)));
        if (outcome == "Available")
        {
            var ciphertext = Bytes(384, 31);
            table.Rows.Add((short)1, outcome, EnvironmentId, OperationId, (short)1, Bytes(32, 23), ciphertext,
                SHA256.HashData(ciphertext), Epoch.AddSeconds(10), Epoch);
        }
        else
        {
            var row = table.NewRow(); row[0] = (short)1; row[1] = outcome; table.Rows.Add(row);
        }
        return table;
    }

    private static DataTable AcknowledgementTable(string outcome)
    {
        var table = Table(("contract_version", typeof(short)), ("outcome", typeof(string)));
        table.Rows.Add((short)1, outcome);
        return table;
    }

    private static EnrollmentGrantStatusObservationCandidate ObservationCandidate()
    {
        Assert.True(EnrollmentGrantStatusObservationCandidate.TryCreate(
            ObservationId, EnvironmentId, OperationId, EnrollmentGrantStatus.Available,
            EnrollmentGrantStatusDiagnostic.None, Epoch.AddSeconds(100), null,
            Epoch, Epoch.AddSeconds(600), out var candidate));
        return candidate!;
    }

    private static DataTable ObservationTable(EnrollmentGrantStatusObservationCandidate candidate)
    {
        var table = Table(
            ("contract_version", typeof(short)), ("outcome", typeof(string)),
            ("observation_id", typeof(Guid)), ("environment_id", typeof(Guid)), ("operation_id", typeof(Guid)),
            ("sequence", typeof(long)), ("state", typeof(string)), ("diagnostic", typeof(string)),
            ("private_observed_at", typeof(DateTimeOffset)), ("private_state_changed_at", typeof(DateTimeOffset)),
            ("recorded_at", typeof(DateTimeOffset)), ("available_until", typeof(DateTimeOffset)));
        table.Rows.Add((short)1, "Recorded", candidate.ObservationId, EnvironmentId, OperationId, 7L,
            "Available", "None", Epoch.AddSeconds(100), DBNull.Value,
            Epoch.AddSeconds(110), Epoch.AddSeconds(115));
        return table;
    }

    private static DataTable ExtraResultSet()
    {
        var table = Table(("unexpected", typeof(int)));
        table.Rows.Add(1);
        return table;
    }

    private static DataTable Table(params (string Name, Type Type)[] columns)
    {
        var table = new DataTable();
        foreach (var (name, type) in columns) table.Columns.Add(name, type);
        return table;
    }

    private static byte[] Bytes(int length, byte seed) =>
        Enumerable.Range(0, length).Select(index => (byte)(seed + index)).ToArray();

    private static void AssertReceiptUnknown(EnrollmentGrantStatusReceiptResult result)
    {
        Assert.Equal(EnrollmentGrantStatusReceiptOutcome.OutcomeUnknown, result.Outcome);
        Assert.Null(result.Receipt);
    }

    private static void AssertDeliveryUnknown(EnrollmentGrantDeliveryResponse result)
    {
        Assert.Equal(EnrollmentGrantDeliveryOutcome.OutcomeUnknown, result.Outcome);
        Assert.Null(result.Payload);
    }

    private static void AssertObservationUnknown(EnrollmentGrantStatusObservationWriteResult result)
    {
        Assert.Equal(EnrollmentGrantStatusObservationWriteOutcome.OutcomeUnknown, result.Outcome);
        Assert.Null(result.Evidence);
    }
}
