using System.Data;
using System.Security.Cryptography;
using ItManagement.AgentPlatformGrants;
using Xunit;

namespace ItManagement.EnrollmentGrantExecution.Tests;

public sealed class PostgresExecutionRecordCodecTests
{
    [Fact]
    public async Task NotFoundRequiresOnlyVersionAndOutcome()
    {
        var table = Table(); var row = table.NewRow(); row[0] = (short)1; row[1] = "NotFound"; table.Rows.Add(row);
        var result = await Read(table);
        Assert.Equal(EnrollmentGrantStoreReadOutcome.NotFound, result.Outcome); Assert.Null(result.Record);

        row[49] = Utc(1);
        Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(table)).Outcome);

        Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(Table())).Outcome);
    }

    [Fact]
    public async Task QueuedRecordRoundTripsAndDefensivelyCopiesBytes()
    {
        var fixture = Fixture.Create(); var table = fixture.Queued();
        var result = await Read(table, fixture);
        var record = Assert.IsType<EnrollmentGrantExecutionRecord>(result.Record);
        Assert.Equal(EnrollmentGrantStoreReadOutcome.Found, result.Outcome);
        var source = (byte[])table.Rows[0][18]; source[0] ^= 0xff;
        Assert.NotEqual(source, record.Operation.GetRecipientSpki());
    }

    [Fact]
    public async Task MetadataCardinalityAndSingleRowAreExact()
    {
        var fixture = Fixture.Create();
        var extra = fixture.Queued(); extra.Columns.Add("extra", typeof(string));
        Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(extra, fixture)).Outcome);

        var wrongName = fixture.Queued(); wrongName.Columns[3].ColumnName = "environment_id";
        Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(wrongName, fixture)).Outcome);

        var wrongType = fixture.Queued(); wrongType.Columns.RemoveAt(17); wrongType.Columns.Add("op_environment_version", typeof(int));
        wrongType.Columns[49].SetOrdinal(17);
        Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(wrongType, fixture)).Outcome);

        var duplicate = fixture.Queued(); duplicate.ImportRow(duplicate.Rows[0]);
        Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(duplicate, fixture)).Outcome);
    }

    [Fact]
    public async Task UnknownVersionOutcomeStateAndCrossContextFailClosed()
    {
        var fixture = Fixture.Create();
        foreach (var mutate in new Action<DataRow>[]
        {
            row => row[0] = (short)2,
            row => row[1] = "found",
            row => row[2] = "completed",
            row => row[3] = Guid.NewGuid(),
            row => row[4] = Guid.NewGuid()
        })
        {
            var table = fixture.Queued(); mutate(table.Rows[0]);
            Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(table, fixture)).Outcome);
        }
    }

    [Fact]
    public async Task PermitAndCompletedReceiptRequireExactTupleHashesAndTimes()
    {
        var fixture = Fixture.Create();
        Assert.Equal(EnrollmentGrantExecutionState.PermitStored,
            Assert.IsType<EnrollmentGrantExecutionRecord>((await Read(fixture.PermitStored(), fixture)).Record).State);
        Assert.Equal(EnrollmentGrantExecutionState.Completed,
            Assert.IsType<EnrollmentGrantExecutionRecord>((await Read(fixture.Completed(), fixture)).Record).State);

        foreach (var mutate in new Action<DataRow>[]
        {
            row => ((byte[])row[43])[0] ^= 0xff,
            row => row[34] = Guid.NewGuid(),
            row => row[38] = Utc(3),
            row => row[39] = Utc(12, 30).AddTicks(10),
            row => row[40] = (short)1,
            row => row[29] = DBNull.Value
        })
        {
            var table = fixture.Completed(); mutate(table.Rows[0]);
            Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(table, fixture)).Outcome);
        }
    }

    [Fact]
    public async Task AcknowledgedRequiresNoEnvelopeAndExactAcknowledgement()
    {
        var fixture = Fixture.Create(); var table = fixture.Acknowledged();
        var record = Assert.IsType<EnrollmentGrantExecutionRecord>((await Read(table, fixture)).Record);
        Assert.Equal(EnrollmentGrantExecutionState.Acknowledged, record.State); Assert.Null(record.Envelope);

        foreach (var mutate in new Action<DataRow>[]
        {
            row => row[29] = new byte[384],
            row => row[44] = Guid.NewGuid(),
            row => ((byte[])row[45])[0] ^= 0xff,
            row => row[47] = Utc(2, 30)
        })
        {
            table = fixture.Acknowledged(); mutate(table.Rows[0]);
            Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(table, fixture)).Outcome);
        }
    }

    [Fact]
    public async Task StopStateMatrixRequiresCanonicalBoundTimeAndPostPermitEnvelope()
    {
        var fixture = Fixture.Create();
        var pre = fixture.Stopped(EnrollmentGrantExecutionState.PermanentRejected,
            EnrollmentGrantExecutionStopReason.AuthorizationExpired, withPermit: false, Utc(11));
        Assert.Equal(EnrollmentGrantExecutionState.PermanentRejected,
            Assert.IsType<EnrollmentGrantExecutionRecord>((await Read(pre, fixture)).Record).State);

        var post = fixture.Stopped(EnrollmentGrantExecutionState.Quarantined,
            EnrollmentGrantExecutionStopReason.ReceiptMismatch, withPermit: true, Utc(4));
        var postRecord = Assert.IsType<EnrollmentGrantExecutionRecord>((await Read(post, fixture)).Record);
        Assert.NotNull(postRecord.Permit); Assert.NotNull(postRecord.Envelope);

        foreach (var invalid in new[]
        {
            fixture.Stopped(EnrollmentGrantExecutionState.PermanentRejected,
                EnrollmentGrantExecutionStopReason.AuthorizationExpired, false, Utc(10, 59)),
            fixture.Stopped(EnrollmentGrantExecutionState.Quarantined,
                EnrollmentGrantExecutionStopReason.ReceiptMismatch, false, Utc(4)),
            fixture.Stopped(EnrollmentGrantExecutionState.Quarantined,
                EnrollmentGrantExecutionStopReason.OperationConflict, true, Utc(1, 59))
        })
            Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(invalid, fixture)).Outcome);
    }

    [Fact]
    public async Task RejectedResultRequiresClosedDiagnosticAndDeadlineBoundRecordTime()
    {
        var fixture = Fixture.Create(); var valid = fixture.Rejected(PlatformGrantDiagnostic.MintPermitExpired, Utc(3));
        var record = Assert.IsType<EnrollmentGrantExecutionRecord>((await Read(valid, fixture)).Record);
        Assert.Equal(EnrollmentGrantExecutionState.PermanentRejected, record.State);

        foreach (var invalid in new[]
        {
            fixture.Rejected(PlatformGrantDiagnostic.MintPermitExpired, Utc(2, 59)),
            fixture.Rejected(PlatformGrantDiagnostic.InvalidMintPermit, Utc(3)),
            fixture.Rejected(PlatformGrantDiagnostic.None, Utc(3))
        })
            Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(invalid, fixture)).Outcome);
    }

    [Fact]
    public async Task NonUtcAndSubMicrosecondDatesFailClosed()
    {
        var fixture = Fixture.Create(); var nonUtc = fixture.Queued();
        var values = nonUtc.Rows[0].ItemArray; nonUtc = Table(utcDates: false); nonUtc.Rows.Add(values);
        Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(nonUtc, fixture)).Outcome);

        var subMicrosecond = fixture.Queued(); subMicrosecond.Rows[0][20] = Utc(1).AddTicks(1);
        Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(subMicrosecond, fixture)).Outcome);
    }

    [Fact]
    public async Task NullMasksAndUnknownStoredEnumsFailClosed()
    {
        var fixture = Fixture.Create();
        foreach (var mutate in new Action<DataRow>[]
        {
            row => row[25] = DBNull.Value,
            row => row[30] = "AlreadyCreated",
            row => row[31] = "InvalidMintPermit",
            row => row[48] = "receiptMismatch"
        })
        {
            var table = fixture.Completed(); mutate(table.Rows[0]);
            Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, (await Read(table, fixture)).Outcome);
        }
    }

    [Fact]
    public async Task CancellationIsPropagatedWithoutPartialFound()
    {
        var fixture = Fixture.Create(); using var reader = fixture.Queued().CreateDataReader();
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => PostgresExecutionRecordCodec.ReadAsync(
            reader, fixture.EnvironmentId, fixture.OperationId, cancellation.Token));
    }

    private static async Task<EnrollmentGrantStoreReadResult> Read(DataTable table, Fixture? fixture = null)
    {
        fixture ??= Fixture.Create(); using var reader = table.CreateDataReader();
        return await PostgresExecutionRecordCodec.ReadAsync(reader, fixture.EnvironmentId, fixture.OperationId, default);
    }

    private static DataTable Table(bool utcDates = true)
    {
        var table = new DataTable(); var types = Types();
        for (var i = 0; i < PostgresExecutionRecordCodec.CanonicalColumnNames.Count; i++)
        {
            var column = table.Columns.Add(PostgresExecutionRecordCodec.CanonicalColumnNames[i], types[i]);
            if (types[i] == typeof(DateTime))
                column.DateTimeMode = utcDates ? DataSetDateTime.Utc : DataSetDateTime.Unspecified;
        }
        return table;
    }

    private static Type[] Types() =>
    [
        typeof(short), typeof(string), typeof(string), typeof(Guid), typeof(Guid), typeof(Guid), typeof(Guid), typeof(Guid),
        typeof(Guid), typeof(Guid), typeof(Guid), typeof(Guid), typeof(string), typeof(Guid), typeof(Guid), typeof(DateTime),
        typeof(Guid), typeof(long), typeof(byte[]), typeof(byte[]), typeof(DateTime), typeof(DateTime), typeof(short),
        typeof(DateTime), typeof(DateTime), typeof(byte[]), typeof(byte[]), typeof(byte[]), typeof(byte[]), typeof(byte[]),
        typeof(string), typeof(string), typeof(DateTime), typeof(Guid), typeof(Guid), typeof(Guid), typeof(Guid), typeof(DateTime),
        typeof(DateTime), typeof(DateTime), typeof(short), typeof(DateTime), typeof(byte[]), typeof(byte[]), typeof(Guid),
        typeof(byte[]), typeof(byte[]), typeof(DateTime), typeof(string), typeof(DateTime)
    ];

    private static DateTime Utc(int minute, int second = 0) =>
        new(2026, 9, 12, 0, minute, second, DateTimeKind.Utc);

    private sealed class Fixture
    {
        private readonly byte[] _spki, _fingerprint, _token, _ciphertext, _ciphertextHash, _digest;
        private Fixture(byte[] spki, byte[] fingerprint)
        {
            _spki = spki; _fingerprint = fingerprint; _token = Enumerable.Repeat((byte)0x11, 32).ToArray();
            _ciphertext = Enumerable.Repeat((byte)0x22, 384).ToArray(); _ciphertextHash = SHA256.HashData(_ciphertext);
            var operation = Operation();
            _digest = EnrollmentGrantAuthorizationDigest.Compute(operation, 1, new(Utc(2)), new(Utc(3)),
                _token, _fingerprint, _ciphertextHash);
        }

        internal Guid EnvironmentId { get; } = Guid.Parse("11111111-1111-1111-1111-111111111111");
        internal Guid OperationId { get; } = Guid.Parse("22222222-2222-2222-2222-222222222222");
        internal static Fixture Create()
        {
            using var key = RSA.Create(3072); var spki = key.ExportSubjectPublicKeyInfo();
            return new(spki, SHA256.HashData(spki));
        }

        internal DataTable Queued() => Base("Queued");
        internal DataTable PermitStored() { var table = Base("PermitStored"); AddPermit(table.Rows[0], true); return table; }
        internal DataTable Completed()
        {
            var table = Base("Completed"); var row = table.Rows[0]; AddPermit(row, true);
            row[30] = "Issued"; row[31] = "None"; row[32] = Utc(2, 31); AddReceipt(row); return table;
        }
        internal DataTable Acknowledged()
        {
            var table = Completed(); var row = table.Rows[0]; row[2] = "Acknowledged"; row[29] = DBNull.Value;
            row[44] = Guid.Parse("66666666-6666-6666-6666-666666666666"); row[45] = _token.ToArray();
            row[46] = _ciphertextHash.ToArray(); row[47] = Utc(2, 32); return table;
        }
        internal DataTable Rejected(PlatformGrantDiagnostic diagnostic, DateTime recordedAt)
        {
            var table = Base("PermanentRejected"); var row = table.Rows[0]; AddPermit(row, false);
            row[30] = "Rejected"; row[31] = diagnostic.ToString(); row[32] = recordedAt; return table;
        }
        internal DataTable Stopped(EnrollmentGrantExecutionState state, EnrollmentGrantExecutionStopReason reason,
            bool withPermit, DateTime stoppedAt)
        {
            var table = Base(state.ToString()); var row = table.Rows[0]; if (withPermit) AddPermit(row, true);
            row[48] = reason.ToString(); row[49] = stoppedAt; return table;
        }

        private DataTable Base(string state)
        {
            var table = Table(); var row = table.NewRow(); row[0] = (short)1; row[1] = "Found"; row[2] = state;
            row[3] = EnvironmentId; row[4] = OperationId; row[5] = Guid.Parse("33333333-3333-3333-3333-333333333333");
            row[6] = Guid.Parse("44444444-4444-4444-4444-444444444444");
            row[7] = Guid.Parse("55555555-5555-5555-5555-555555555555");
            row[8] = Guid.Parse("66666666-6666-6666-6666-666666666666");
            row[9] = Guid.Parse("77777777-7777-7777-7777-777777777777");
            row[10] = Guid.Parse("88888888-8888-8888-8888-888888888888");
            row[11] = Guid.Parse("99999999-9999-9999-9999-999999999999"); row[12] = new string('a', 64);
            row[13] = Guid.Parse("aaaaaaaa-1111-1111-1111-111111111111");
            row[14] = Guid.Parse("bbbbbbbb-1111-1111-1111-111111111111"); row[15] = Utc(0);
            row[16] = Guid.Parse("cccccccc-1111-1111-1111-111111111111"); row[17] = 7L;
            row[18] = _spki.ToArray(); row[19] = _fingerprint.ToArray(); row[20] = Utc(1); row[21] = Utc(11);
            table.Rows.Add(row); return table;
        }
        private EnrollmentGrantExecutionOperation Operation() => new(EnvironmentId, OperationId,
            Guid.Parse("33333333-3333-3333-3333-333333333333"), Guid.Parse("44444444-4444-4444-4444-444444444444"),
            Guid.Parse("55555555-5555-5555-5555-555555555555"), Guid.Parse("66666666-6666-6666-6666-666666666666"),
            Guid.Parse("77777777-7777-7777-7777-777777777777"), Guid.Parse("88888888-8888-8888-8888-888888888888"),
            Guid.Parse("99999999-9999-9999-9999-999999999999"), new string('a', 64),
            Guid.Parse("aaaaaaaa-1111-1111-1111-111111111111"), Guid.Parse("bbbbbbbb-1111-1111-1111-111111111111"),
            new(Utc(0)), Guid.Parse("cccccccc-1111-1111-1111-111111111111"), 7, _spki, _fingerprint,
            new(Utc(1)), new(Utc(11)));
        private void AddPermit(DataRow row, bool envelope)
        {
            row[22] = (short)1; row[23] = Utc(2); row[24] = Utc(3); row[25] = _token.ToArray();
            row[26] = _fingerprint.ToArray(); row[27] = _ciphertextHash.ToArray(); row[28] = _digest.ToArray();
            if (envelope) row[29] = _ciphertext.ToArray();
        }
        private void AddReceipt(DataRow row)
        {
            row[33] = Guid.Parse("dddddddd-1111-1111-1111-111111111111"); row[34] = EnvironmentId;
            row[35] = Guid.Parse("aaaaaaaa-1111-1111-1111-111111111111");
            row[36] = Guid.Parse("bbbbbbbb-1111-1111-1111-111111111111"); row[37] = Utc(0);
            row[38] = Utc(2, 30); row[39] = Utc(12, 30); row[40] = (short)2; row[41] = Utc(3);
            row[42] = _token.ToArray(); row[43] = _digest.ToArray();
        }
    }
}
