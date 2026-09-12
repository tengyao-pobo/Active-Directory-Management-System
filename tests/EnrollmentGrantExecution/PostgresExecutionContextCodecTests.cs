using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using ItManagement.AgentEnrollment.Plans;
using ItManagement.Core;
using Xunit;

namespace ItManagement.EnrollmentGrantExecution.Tests;

public sealed class PostgresExecutionContextCodecTests
{
    [Fact]
    public async Task FoundReturnsOnlyExpectedOperationAndVerifiedHashEvenAfterDeadline()
    {
        var fixture = Fixture.Create();
        var result = await Read(fixture.Found(), fixture.Operation);

        Assert.Equal(EnrollmentGrantContextReadOutcome.Found, result.Outcome);
        var context = Assert.IsType<ValidatedEnrollmentGrantExecutionContext>(result.Context);
        Assert.Same(fixture.Operation, context.Operation);
        Assert.Equal(fixture.Operation.PlanHash, context.VerifiedPlanHash);
    }

    [Fact]
    public async Task NotFoundRequiresEveryContextColumnToBeNull()
    {
        var fixture = Fixture.Create();
        var table = Table(); var row = table.NewRow();
        row[0] = (short)1; row[1] = "NotFound"; table.Rows.Add(row);
        Assert.Equal(EnrollmentGrantContextReadOutcome.NotFound, (await Read(table, fixture.Operation)).Outcome);

        row[31] = fixture.DatabaseCheckedAt.UtcDateTime;
        Assert.Equal(EnrollmentGrantContextReadOutcome.OutcomeUnknown, (await Read(table, fixture.Operation)).Outcome);
        Assert.Equal(EnrollmentGrantContextReadOutcome.OutcomeUnknown, (await Read(Table(), fixture.Operation)).Outcome);
    }

    [Fact]
    public async Task MetadataAndSingleRowShapeAreExact()
    {
        var fixture = Fixture.Create();
        var extraColumn = fixture.Found(); extraColumn.Columns.Add("extra", typeof(string));
        AssertUnknown(await Read(extraColumn, fixture.Operation));

        var wrongName = fixture.Found(); wrongName.Columns[2].ColumnName = "environment_id";
        AssertUnknown(await Read(wrongName, fixture.Operation));

        var wrongType = fixture.Found(); wrongType.Columns.RemoveAt(8);
        wrongType.Columns.Add("plan_policy_version", typeof(int)).SetOrdinal(8);
        AssertUnknown(await Read(wrongType, fixture.Operation));

        var duplicate = fixture.Found(); duplicate.ImportRow(duplicate.Rows[0]);
        AssertUnknown(await Read(duplicate, fixture.Operation));
    }

    [Fact]
    public async Task ContractOutcomeNullMaskAndQueuedStateAreClosed()
    {
        var fixture = Fixture.Create();
        foreach (var mutate in new Action<DataRow>[]
        {
            row => row[0] = (short)2,
            row => row[1] = "found",
            row => row[10] = 1,
            row => row[11] = DBNull.Value,
            row => row[14] = Guid.Empty,
            row => row[24] = DBNull.Value,
            row => row[32] = DBNull.Value,
            row => row[32] = new byte[31],
            row => ((byte[])row[32])[0] ^= 0xff
        })
        {
            var table = fixture.Found(); mutate(table.Rows[0]);
            AssertUnknown(await Read(table, fixture.Operation));
        }
    }

    [Fact]
    public async Task PlanPayloadHashAndReservationDigestMustAllAgree()
    {
        var fixture = Fixture.Create();
        foreach (var mutate in new Action<DataRow>[]
        {
            row => row[7] = new string('a', 64),
            row => row[20] = new string('a', 64),
            row => ((byte[])row[29])[0] ^= 0xff,
            row => row[6] = ((string)row[6]).Replace(fixture.Operation.DirectoryObjectId.ToString(), Guid.NewGuid().ToString(), StringComparison.Ordinal),
            row => ((byte[])row[24])[0] ^= 0xff
        })
        {
            var table = fixture.Found(); mutate(table.Rows[0]);
            AssertUnknown(await Read(table, fixture.Operation));
        }
    }

    [Fact]
    public async Task ApprovalReservationAndExpectedOperationBindingsAreExact()
    {
        var fixture = Fixture.Create();
        foreach (var mutate in new Action<DataRow>[]
        {
            row => row[18] = Guid.NewGuid(),
            row => row[21] = Guid.NewGuid(),
            row => row[22] = fixture.Operation.QueuedAt.AddTicks(10).UtcDateTime,
            row => row[23] = fixture.Operation.AuthorizationNotAfter.AddTicks(-10).UtcDateTime,
            row => row[28] = Guid.NewGuid(),
            row => row[30] = fixture.ApprovedAt.AddTicks(10).UtcDateTime,
            row => row[31] = fixture.Operation.QueuedAt.AddTicks(-10).UtcDateTime
        })
        {
            var table = fixture.Found(); mutate(table.Rows[0]);
            AssertUnknown(await Read(table, fixture.Operation));
        }

        var otherOperation = fixture.CopyOperation(directoryObjectId: Guid.NewGuid());
        AssertUnknown(await Read(fixture.Found(), otherOperation));
        AssertUnknown(await Read(fixture.Found(), fixture.CopyOperation(planHash: new string('a', 64))));
        AssertUnknown(await Read(fixture.Found(), fixture.CopyOperation(requesterOperatorId: Guid.NewGuid())));
        AssertUnknown(await Read(fixture.Found(), fixture.CopyOperation(approverOperatorId: Guid.NewGuid())));
        AssertUnknown(await Read(fixture.Found(), fixture.CopyOperation(queuedAt: fixture.Operation.QueuedAt.AddTicks(10))));
        AssertUnknown(await Read(fixture.Found(), fixture.CopyOperation(authorizationNotAfter: fixture.Operation.AuthorizationNotAfter.AddTicks(-10))));
    }

    [Fact]
    public async Task DatesMustBeFiniteUtcAndMicrosecondPrecise()
    {
        var fixture = Fixture.Create();
        var nonUtcValues = fixture.Found().Rows[0].ItemArray;
        var nonUtc = Table(utcDates: false); nonUtc.Rows.Add(nonUtcValues);
        AssertUnknown(await Read(nonUtc, fixture.Operation));

        var subMicrosecond = fixture.Found(); subMicrosecond.Rows[0][31] = fixture.DatabaseCheckedAt.UtcDateTime.AddTicks(1);
        AssertUnknown(await Read(subMicrosecond, fixture.Operation));

        var extreme = fixture.Found(); extreme.Rows[0][31] = DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc);
        AssertUnknown(await Read(extreme, fixture.Operation));
    }

    [Fact]
    public async Task CancellationPropagatesWithoutPartialFound()
    {
        var fixture = Fixture.Create(); using var reader = fixture.Found().CreateDataReader();
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PostgresExecutionContextCodec.ReadAsync(reader, fixture.Operation, cancellation.Token));
    }

    private static async Task<EnrollmentGrantContextReadResult> Read(DataTable table,
        EnrollmentGrantExecutionOperation operation)
    {
        using var reader = table.CreateDataReader();
        return await PostgresExecutionContextCodec.ReadAsync(reader, operation, default);
    }

    private static void AssertUnknown(EnrollmentGrantContextReadResult result)
    {
        Assert.Equal(EnrollmentGrantContextReadOutcome.OutcomeUnknown, result.Outcome);
        Assert.Null(result.Context);
    }

    private static DataTable Table(bool utcDates = true)
    {
        var table = new DataTable(); var types = Types();
        for (var i = 0; i < PostgresExecutionContextCodec.CanonicalColumnNames.Count; i++)
        {
            var column = table.Columns.Add(PostgresExecutionContextCodec.CanonicalColumnNames[i], types[i]);
            if (types[i] == typeof(DateTime))
                column.DateTimeMode = utcDates ? DataSetDateTime.Utc : DataSetDateTime.Unspecified;
        }
        return table;
    }

    private static Type[] Types() =>
    [
        typeof(short), typeof(string), typeof(Guid), typeof(Guid), typeof(Guid), typeof(string), typeof(string),
        typeof(string), typeof(long), typeof(DateTime), typeof(int), typeof(string), typeof(Guid), typeof(Guid),
        typeof(Guid), typeof(string), typeof(long), typeof(Guid), typeof(Guid), typeof(Guid), typeof(string),
        typeof(Guid), typeof(DateTime), typeof(DateTime), typeof(byte[]), typeof(Guid), typeof(Guid), typeof(Guid),
        typeof(Guid), typeof(byte[]), typeof(DateTime), typeof(DateTime), typeof(byte[])
    ];

    private sealed class Fixture
    {
        private readonly ChangePlan _plan;
        private readonly ChangePlanItem _item;
        private readonly ChangeApproval _approval;
        private readonly EnrollmentGrantRecipientReservation _reservation;

        private Fixture(ChangePlan plan, ChangePlanItem item, ChangeApproval approval,
            EnrollmentGrantRecipientReservation reservation, EnrollmentGrantExecutionOperation operation,
            DateTimeOffset databaseCheckedAt)
        {
            _plan = plan; _item = item; _approval = approval; _reservation = reservation;
            Operation = operation; DatabaseCheckedAt = databaseCheckedAt;
        }

        internal EnrollmentGrantExecutionOperation Operation { get; }
        internal DateTimeOffset DatabaseCheckedAt { get; }
        internal DateTimeOffset ApprovedAt => _approval.ApprovedAt;

        internal static Fixture Create()
        {
            var environmentId = Guid.Parse("11111111-1111-1111-1111-111111111111");
            var planId = Guid.Parse("22222222-2222-2222-2222-222222222222");
            var requesterId = Guid.Parse("33333333-3333-3333-3333-333333333333");
            var approverId = Guid.Parse("44444444-4444-4444-4444-444444444444");
            var requestId = Guid.Parse("55555555-5555-5555-5555-555555555555");
            var operationId = Guid.Parse("66666666-6666-6666-6666-666666666666");
            var directoryId = Guid.Parse("77777777-7777-7777-7777-777777777777");
            var deviceId = Guid.Parse("88888888-8888-8888-8888-888888888888");
            var generation = Guid.Parse("99999999-9999-9999-9999-999999999999");
            var itemId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
            var approvalId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
            var mappingAt = At(0); var reservationAt = At(1); var approvedAt = At(2);
            var queuedAt = At(3); var authorizationNotAfter = At(4); var planExpiresAt = At(11);
            using var key = RSA.Create(3072); var spki = key.ExportSubjectPublicKeyInfo();
            var fingerprint = SHA256.HashData(spki); const long version = 17; const string reason = "approved test grant";
            var payload = new EnrollmentGrantPlanPayload(EnrollmentGrantPlanContract.SchemaVersion,
                EnrollmentGrantPlanContract.Action, environmentId, directoryId, deviceId, mappingAt, generation,
                version, Base64Url(spki), Base64Url(fingerprint), requestId, reason, requesterId, operationId,
                EnrollmentGrantPlanContract.GrantTtlSeconds);
            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var item = new ChangePlanItem { Id = itemId, TargetId = environmentId.ToString(), ExpectedVersion = version };
            var plan = new ChangePlanService().Create(environmentId, planId, requesterId,
                EnrollmentGrantPlanContract.Action, json, version, planExpiresAt, [item], reason);
            plan.State = ChangePlanState.Queued;
            item = plan.Items.Single();
            var reservation = new EnrollmentGrantRecipientReservation
            {
                Fingerprint = fingerprint.ToArray(), EnvironmentId = environmentId, PlanId = planId,
                RequesterId = requesterId, RequestId = requestId,
                RequestDigest = EnrollmentGrantPlanValidation.ComputeRequestDigest(environmentId, requesterId, requestId,
                    directoryId, deviceId, mappingAt, version, generation, Base64Url(spki), reason),
                CreatedAt = reservationAt
            };
            var approval = new ChangeApproval
            {
                EnvironmentId = environmentId, Id = approvalId, PlanId = planId, PlanHash = plan.PlanHash,
                ApproverId = approverId, ApprovedAt = approvedAt, ExpiresAt = At(5)
            };
            var operation = new EnrollmentGrantExecutionOperation(environmentId, operationId, planId, requestId,
                approvalId, requesterId, approverId, Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc"),
                Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd"), plan.PlanHash, directoryId, deviceId,
                mappingAt, generation, version, spki, fingerprint, queuedAt, authorizationNotAfter);
            return new(plan, item, approval, reservation, operation, At(12));
        }

        internal EnrollmentGrantExecutionOperation CopyOperation(Guid? directoryObjectId = null, string? planHash = null,
            Guid? requesterOperatorId = null, Guid? approverOperatorId = null,
            DateTimeOffset? queuedAt = null, DateTimeOffset? authorizationNotAfter = null) => new(
            Operation.EnvironmentId, Operation.Id, Operation.PlanId, Operation.RequestId, Operation.ApprovalId,
            Operation.RequesterId, Operation.ApproverId, requesterOperatorId ?? Operation.RequesterOperatorId,
            approverOperatorId ?? Operation.ApproverOperatorId,
            planHash ?? Operation.PlanHash, directoryObjectId ?? Operation.DirectoryObjectId, Operation.ServerDeviceId,
            Operation.MappingCreatedAt, Operation.DirectoryGeneration, Operation.EnvironmentVersion,
            Operation.GetRecipientSpki(), Operation.GetRecipientKeyFingerprint(), queuedAt ?? Operation.QueuedAt,
            authorizationNotAfter ?? Operation.AuthorizationNotAfter);

        internal DataTable Found()
        {
            var table = Table(); var row = table.NewRow();
            row.ItemArray =
            [
                (short)1, "Found", _plan.EnvironmentId, _plan.Id, _plan.RequesterId, _plan.Action,
                _plan.ImmutablePlanJson, _plan.PlanHash, _plan.PolicyVersion, _plan.ExpiresAt.UtcDateTime,
                (int)_plan.State, _plan.Reason!, _item.EnvironmentId, _item.PlanId, _item.Id, _item.TargetId,
                _item.ExpectedVersion, _approval.EnvironmentId, _approval.Id, _approval.PlanId, _approval.PlanHash,
                _approval.ApproverId, _approval.ApprovedAt.UtcDateTime, _approval.ExpiresAt.UtcDateTime,
                _reservation.Fingerprint.ToArray(), _reservation.EnvironmentId, _reservation.PlanId,
                _reservation.RequesterId, _reservation.RequestId, _reservation.RequestDigest.ToArray(),
                _reservation.CreatedAt.UtcDateTime, DatabaseCheckedAt.UtcDateTime,
                SHA256.HashData([.. System.Text.Encoding.UTF8.GetBytes("ITM-ENROLLMENT-CONTEXT-V1"),
                    .. EnrollmentGrantAuthorizationDigest.Compute(Operation,1,Operation.QueuedAt,
                    Operation.AuthorizationNotAfter < Operation.QueuedAt.AddSeconds(60)
                        ? Operation.AuthorizationNotAfter : Operation.QueuedAt.AddSeconds(60),
                    new byte[32],Operation.GetRecipientKeyFingerprint(),new byte[32])])
            ];
            table.Rows.Add(row); return table;
        }

        private static DateTimeOffset At(int minute) =>
            new(2026, 9, 12, 0, minute, 0, TimeSpan.Zero);

        private static string Base64Url(byte[] value) =>
            Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
