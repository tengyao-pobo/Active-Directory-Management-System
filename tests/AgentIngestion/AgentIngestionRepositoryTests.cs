using System.Security.Cryptography;
using System.Text.Json;
using ItManagement.Agent.Collectors;
using ItManagement.Agent.Inventory;
using ItManagement.Agent.Runtime;
using ItManagement.Agent.Spool;
using Npgsql;

namespace ItManagement.AgentIngestion.Tests;

[Collection(AgentIngestionCollection.Name)]
public sealed class AgentIngestionRepositoryTests(AgentIngestionFixture fixture)
{
    [Fact]
    public async Task DedicatedLogin_HasOnlyCallableSurfaceAndPassesPrivilegeAudit()
    {
        await fixture.SeedAsync();
        var audit = await new AgentStorePrivilegeAuditor(fixture.IngestDataSource, fixture.DefinerRole)
            .AuditAsync(CancellationToken.None);

        Assert.True(audit.IsValid, string.Join(',', audit.Issues));
        await using var command = fixture.IngestDataSource.CreateCommand(
            "SELECT count(*) FROM agent_private.receipts");
        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteScalarAsync());
        Assert.Equal("42501", error.SqlState);
    }

    [Fact]
    public async Task Provisioning_IsIdempotentForExactBindingAndRejectsEnvironmentRebind()
    {
        await fixture.ReprovisionAsync(fixture.EnvironmentId);

        var error = await Assert.ThrowsAsync<PostgresException>(() => fixture.ReprovisionAsync(Guid.NewGuid()));

        Assert.Equal("22012", error.SqlState);
        Assert.Equal(fixture.EnvironmentId, await fixture.ScalarOwnerAsync<Guid>(
            "SELECT environment_id FROM agent_private.agent_database_bindings WHERE login_role=@login::name",
            new NpgsqlParameter("login", fixture.IngestRole)));
    }

    [Fact]
    public async Task WebLogin_CannotExecuteIngestionFunction()
    {
        await fixture.SeedAsync();
        await using var command = fixture.WebDataSource.CreateCommand(
            """
            SELECT * FROM agent_private.ingest_attested_envelope(
                decode(repeat('00',32),'hex'),1,gen_random_uuid(),1,1,gen_random_uuid(),1,
                convert_to('{}','UTF8'),repeat('0',64),repeat('0',64))
            """);

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteReaderAsync());
        Assert.Equal("42501", error.SqlState);
    }

    [Theory]
    [InlineData("Missing")]
    [InlineData("Revoked")]
    [InlineData("Expired")]
    public async Task IngestAsync_RejectsUnboundOrInactiveCertificate(string state)
    {
        var now = DateTimeOffset.UtcNow;
        var seed = state switch
        {
            "Revoked" => await fixture.SeedAsync(bindingState: "Revoked"),
            "Expired" => await fixture.SeedAsync(notAfter: now.AddMinutes(-1)),
            _ => await fixture.SeedAsync()
        };
        var fingerprint = state == "Missing" ? RandomNumberGenerator.GetBytes(32) : seed.Fingerprint;

        var result = await Repository().IngestAsync(
            AttestedAgentPeer.FromValidatedChannel(fingerprint),
            Heartbeat(seed),
            CancellationToken.None);

        Assert.Equal(AgentTransportOutcome.IdentityConflict, result.Outcome);
        Assert.Null(result.Acknowledgement);
        Assert.Equal(0, await ReceiptCountAsync());
    }

    [Fact]
    public async Task IngestAsync_RequiresDatabaseBindingEnvironmentAndIgnoresSessionSpoofing()
    {
        var seed = await fixture.SeedAsync();
        await fixture.ExecuteOwnerAsync(
            "UPDATE agent_private.agent_database_bindings SET environment_id=@environment WHERE login_role=@login::name",
            new NpgsqlParameter("environment", Guid.NewGuid()),
            new NpgsqlParameter("login", fixture.IngestRole));

        await using var spoofed = fixture.CreateSpoofedIngestDataSource(seed.EnvironmentId);
        var result = await new AgentIngestionRepository(spoofed)
            .IngestAsync(Peer(seed), Heartbeat(seed), CancellationToken.None);

        Assert.Equal(AgentTransportOutcome.IdentityConflict, result.Outcome);
        Assert.Equal(0, await ReceiptCountAsync());
    }

    [Fact]
    public async Task ExactDuplicate_AllowsCurrentCertificateRotation()
    {
        var seed = await fixture.SeedAsync();
        var envelope = Heartbeat(seed);
        var repository = Repository();
        var accepted = await repository.IngestAsync(Peer(seed), envelope, CancellationToken.None);
        var rotatedFingerprint = await fixture.AddCertificateBindingAsync(seed);

        var duplicate = await repository.IngestAsync(
            AttestedAgentPeer.FromValidatedChannel(rotatedFingerprint), envelope, CancellationToken.None);

        Assert.Equal(AgentTransportOutcome.Accepted, accepted.Outcome);
        Assert.Equal(AgentTransportOutcome.AlreadyAccepted, duplicate.Outcome);
        Assert.Equal(accepted.Acknowledgement, duplicate.Acknowledgement);
    }

    [Fact]
    public async Task StaleHeartbeat_IsStoredWithoutAdvancingLastSeenThenFreshHeartbeatAdvancesIt()
    {
        var seed = await fixture.SeedAsync();
        var repository = Repository();
        var stale = Heartbeat(seed, 1, observedAt: DateTimeOffset.UtcNow.AddMinutes(-10));

        Assert.Equal(AgentTransportOutcome.Accepted,
            (await repository.IngestAsync(Peer(seed), stale, CancellationToken.None)).Outcome);
        var staleState = await DeviceHeartbeatStateAsync(seed);
        Assert.Null(staleState.LastSeen);
        Assert.Null(staleState.ReceiptId);

        var fresh = Heartbeat(seed, 2);
        Assert.Equal(AgentTransportOutcome.Accepted,
            (await repository.IngestAsync(Peer(seed), fresh, CancellationToken.None)).Outcome);
        var state = await DeviceHeartbeatStateAsync(seed);
        Assert.NotNull(state.LastSeen);
        Assert.NotNull(state.ReceiptId);

        Assert.Equal(AgentTransportOutcome.AlreadyAccepted,
            (await repository.IngestAsync(Peer(seed), stale, CancellationToken.None)).Outcome);
        Assert.Equal(state, await DeviceHeartbeatStateAsync(seed));
    }

    [Fact]
    public async Task PayloadWhitespace_IsCanonicalizedLikeOfflineSpool()
    {
        var seed = await fixture.SeedAsync();
        using var document = JsonDocument.Parse(
            """{ "schemaVersion" : 1, "kind" : 0, "body" : { "SchemaVersion" : 1, "AgentVersion" : "test-agent" } }""");
        var envelope = Envelope(seed, 1, Guid.NewGuid(), document.RootElement.Clone());

        var result = await Repository().IngestAsync(Peer(seed), envelope, CancellationToken.None);

        Assert.Equal(AgentTransportOutcome.Accepted, result.Outcome);
    }

    [Fact]
    public async Task PersistedDuplicate_BypassesCurrentInventoryAgeValidation()
    {
        var seed = await fixture.SeedAsync();
        var oldEnvelope = Inventory(seed, 1, "old", DateTimeOffset.UtcNow.AddDays(-31));
        await fixture.SeedAcceptedReceiptAsync(seed, oldEnvelope, kind: 1, schemaVersion: 1);

        var result = await Repository().IngestAsync(Peer(seed), oldEnvelope, CancellationToken.None);

        Assert.Equal(AgentTransportOutcome.AlreadyAccepted, result.Outcome);
        Assert.NotNull(result.Acknowledgement);
    }

    [Fact]
    public async Task HardwareCollector_RequiresCatalogSourceAndAllowlistedRowKeys()
    {
        var seed = await fixture.SeedAsync();
        var valid = HardwareInventory(seed, 1, includeUnknownKey: false);
        var invalid = HardwareInventory(seed, 2, includeUnknownKey: true);

        Assert.Equal(AgentTransportOutcome.Accepted,
            (await Repository().IngestAsync(Peer(seed), valid, CancellationToken.None)).Outcome);
        Assert.Equal(AgentTransportOutcome.PermanentRejected,
            (await Repository().IngestAsync(Peer(seed), invalid, CancellationToken.None)).Outcome);
        Assert.Equal(1, await ReceiptCountAsync());
    }

    [Fact]
    public async Task CollectorRunnerAndOfflineSpool_RoundTripSyntheticCollectorsIntoRepository()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"agent-ingestion-{Guid.NewGuid():N}");
        try
        {
            await using var spool = await OfflineSpool.OpenAsync(directory, registrationEpoch: 1);
            var seed = await fixture.SeedAsync(deviceGuid: spool.Identity.DeviceGuid);
            IInventoryCollector[] collectors =
            [
                new BasicDeviceCollector(new SyntheticBasicDeviceSource()),
                new InstalledSoftwareCollector(new SyntheticSoftwareRegistry()),
                new HardwareCollector(new SyntheticHardwareReader())
            ];
            var snapshot = await new CollectorRunner().CollectAsync(collectors);
            var body = JsonSerializer.SerializeToElement(snapshot);
            var payload = new AgentMessagePayload(1, AgentMessageKind.InventorySnapshot, body);
            var queued = await spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UtcNow, payload);
            var persisted = Assert.Single(await spool.ReadPendingAsync());

            var result = await Repository().IngestAsync(Peer(seed), persisted, CancellationToken.None);

            Assert.Equal(queued with { Payload = default }, persisted with { Payload = default });
            Assert.Equal(queued.Payload.GetRawText(), persisted.Payload.GetRawText());
            Assert.Equal(AgentTransportOutcome.Accepted, result.Outcome);
            Assert.Equal(1, await ReceiptCountAsync());
            Assert.Equal(1, await HistoryCountAsync());
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public async Task InventoryFailure_RollsBackReceiptReplayAndProjectionAtomically()
    {
        var seed = await fixture.SeedAsync();
        await fixture.ExecuteOwnerAsync(
            "ALTER TABLE agent_private.snapshot_history ADD CONSTRAINT synthetic_reject CHECK (false) NOT VALID");
        try
        {
            var result = await Repository().IngestAsync(Peer(seed), Inventory(seed, 1, "rollback"), CancellationToken.None);
            Assert.Equal(AgentTransportOutcome.Unknown, result.Outcome);
            Assert.Equal(0, await ReceiptCountAsync());
            Assert.Equal(0, await HistoryCountAsync());
            Assert.Equal(0, await fixture.ScalarOwnerAsync<long>("SELECT count(*) FROM agent_private.replay_state"));
            Assert.Equal(0, await fixture.ScalarOwnerAsync<long>("SELECT count(*) FROM agent_private.inventory_projection"));
        }
        finally
        {
            await fixture.ExecuteOwnerAsync(
                "ALTER TABLE agent_private.snapshot_history DROP CONSTRAINT synthetic_reject");
        }
    }

    [Fact]
    public async Task ExactHeartbeatDuplicate_ReturnsStoredReceiptWithoutRefreshingLastSeen()
    {
        var seed = await fixture.SeedAsync();
        var envelope = Heartbeat(seed);
        var repository = Repository();

        var first = await repository.IngestAsync(Peer(seed), envelope, CancellationToken.None);
        var firstState = await DeviceHeartbeatStateAsync(seed);
        var second = await repository.IngestAsync(Peer(seed), envelope, CancellationToken.None);
        var secondState = await DeviceHeartbeatStateAsync(seed);

        Assert.Equal(AgentTransportOutcome.Accepted, first.Outcome);
        Assert.Equal(AgentTransportOutcome.AlreadyAccepted, second.Outcome);
        Assert.Equal(first.Acknowledgement, second.Acknowledgement);
        Assert.Equal(firstState, secondState);
        Assert.Equal(1, await ReceiptCountAsync());
        Assert.Equal(0, await HistoryCountAsync());
    }

    [Fact]
    public async Task ReusedSequenceOrRequestWithChangedEnvelope_IsIdentityConflict()
    {
        var seed = await fixture.SeedAsync();
        var first = Heartbeat(seed, sequence: 1);
        var repository = Repository();
        Assert.Equal(AgentTransportOutcome.Accepted,
            (await repository.IngestAsync(Peer(seed), first, CancellationToken.None)).Outcome);

        var changedSequenceEnvelope = Heartbeat(seed, sequence: 1, requestId: Guid.NewGuid());
        var reusedRequest = Heartbeat(seed, sequence: 2, requestId: first.RequestId);

        Assert.Equal(AgentTransportOutcome.IdentityConflict,
            (await repository.IngestAsync(Peer(seed), changedSequenceEnvelope, CancellationToken.None)).Outcome);
        Assert.Equal(AgentTransportOutcome.IdentityConflict,
            (await repository.IngestAsync(Peer(seed), reusedRequest, CancellationToken.None)).Outcome);
        Assert.Equal(1, await ReceiptCountAsync());
    }

    [Fact]
    public async Task ReplayWindow_AcceptsGapsAndInWindowOutOfOrderButRejectsTooOldMissingSequence()
    {
        var seed = await fixture.SeedAsync();
        var repository = Repository();

        Assert.Equal(AgentTransportOutcome.Accepted,
            (await repository.IngestAsync(Peer(seed), Heartbeat(seed, 200), CancellationToken.None)).Outcome);
        Assert.Equal(AgentTransportOutcome.Accepted,
            (await repository.IngestAsync(Peer(seed), Heartbeat(seed, 100), CancellationToken.None)).Outcome);
        Assert.Equal(AgentTransportOutcome.PermanentRejected,
            (await repository.IngestAsync(Peer(seed), Heartbeat(seed, 72), CancellationToken.None)).Outcome);
        Assert.Equal(2, await ReceiptCountAsync());
    }

    [Fact]
    public async Task InventoryProjection_DoesNotRollBackForOlderAcceptedSnapshot()
    {
        var seed = await fixture.SeedAsync();
        var repository = Repository();

        Assert.Equal(AgentTransportOutcome.Accepted,
            (await repository.IngestAsync(Peer(seed), Inventory(seed, 10, "new"), CancellationToken.None)).Outcome);
        var currentReceipt = await ProjectionReceiptAsync(seed);
        Assert.Equal(AgentTransportOutcome.Accepted,
            (await repository.IngestAsync(Peer(seed), Inventory(seed, 9, "old"), CancellationToken.None)).Outcome);

        Assert.Equal(currentReceipt, await ProjectionReceiptAsync(seed));
        Assert.Equal(2, await HistoryCountAsync());
    }

    [Fact]
    public async Task InventoryProjection_HigherRegistrationEpochWinsWithLowerSequence()
    {
        var firstEpoch = await fixture.SeedAsync();
        Assert.Equal(AgentTransportOutcome.Accepted,
            (await Repository().IngestAsync(Peer(firstEpoch), Inventory(firstEpoch, 10, "epoch-one"), CancellationToken.None)).Outcome);
        var firstReceipt = await ProjectionReceiptAsync(firstEpoch);
        var secondEpoch = await fixture.AdvanceRegistrationEpochAsync(firstEpoch);

        Assert.Equal(AgentTransportOutcome.Accepted,
            (await Repository().IngestAsync(Peer(secondEpoch), Inventory(secondEpoch, 1, "epoch-two"), CancellationToken.None)).Outcome);

        var projection = await ProjectionStateAsync(secondEpoch);
        Assert.Equal(2, projection.Epoch);
        Assert.Equal(1, projection.Sequence);
        Assert.NotEqual(firstReceipt, projection.ReceiptId);
    }

    [Fact]
    public async Task InvalidSchemaKindAndOversize_AreRejectedBeforeWrites()
    {
        var seed = await fixture.SeedAsync();
        var repository = Repository();
        var invalidSchema = Envelope(seed, 1, Guid.NewGuid(), JsonSerializer.SerializeToElement(
            new { schemaVersion = 2, kind = 0, body = new { SchemaVersion = 1, AgentVersion = "test" } }));
        var invalidKind = Envelope(seed, 2, Guid.NewGuid(), JsonSerializer.SerializeToElement(
            new { schemaVersion = 1, kind = 99, body = new { } }));
        var oversize = Envelope(seed, 3, Guid.NewGuid(), JsonSerializer.SerializeToElement(
            new { schemaVersion = 1, kind = 0, body = new { value = new string('x', 525_000) } }));
        var stringBodySchema = MalformedInventory(seed, 4, bodySchema: "1", status: 0, quality: 0, itemCount: 1);
        var stringStatus = MalformedInventory(seed, 5, bodySchema: 1, status: "0", quality: 0, itemCount: 1);
        var stringQuality = MalformedInventory(seed, 6, bodySchema: 1, status: 0, quality: "0", itemCount: 1);
        var stringItemCount = MalformedInventory(seed, 7, bodySchema: 1, status: 0, quality: 0, itemCount: "1");

        Assert.Equal(AgentTransportOutcome.PermanentRejected,
            (await repository.IngestAsync(Peer(seed), invalidSchema, CancellationToken.None)).Outcome);
        Assert.Equal(AgentTransportOutcome.PermanentRejected,
            (await repository.IngestAsync(Peer(seed), invalidKind, CancellationToken.None)).Outcome);
        Assert.Equal(AgentTransportOutcome.PermanentRejected,
            (await repository.IngestAsync(Peer(seed), oversize, CancellationToken.None)).Outcome);
        foreach (var malformed in new[] { stringBodySchema, stringStatus, stringQuality, stringItemCount })
        {
            Assert.Equal(AgentTransportOutcome.PermanentRejected,
                (await repository.IngestAsync(Peer(seed), malformed, CancellationToken.None)).Outcome);
        }
        Assert.Equal(0, await ReceiptCountAsync());
        Assert.Equal(0, await fixture.ScalarOwnerAsync<long>("SELECT count(*) FROM agent_private.replay_state"));
        Assert.Equal(0, await HistoryCountAsync());
        Assert.Equal(0, await fixture.ScalarOwnerAsync<long>("SELECT count(*) FROM agent_private.inventory_projection"));
    }

    [Fact]
    public async Task ConcurrentIdenticalAndConflictingEnvelopes_AreSerializedByReplayLock()
    {
        var seed = await fixture.SeedAsync();
        var repository = Repository();
        var identical = Heartbeat(seed, 1);
        var identicalResults = await Task.WhenAll(
            repository.IngestAsync(Peer(seed), identical, CancellationToken.None),
            repository.IngestAsync(Peer(seed), identical, CancellationToken.None));
        Assert.Equal(
            [AgentTransportOutcome.Accepted, AgentTransportOutcome.AlreadyAccepted],
            identicalResults.Select(static result => result.Outcome).Order().ToArray());

        seed = await fixture.SeedAsync();
        var left = Heartbeat(seed, 1);
        var right = Heartbeat(seed, 1, Guid.NewGuid());
        var conflictingResults = await Task.WhenAll(
            repository.IngestAsync(Peer(seed), left, CancellationToken.None),
            repository.IngestAsync(Peer(seed), right, CancellationToken.None));
        Assert.Contains(conflictingResults, result => result.Outcome == AgentTransportOutcome.Accepted);
        Assert.Contains(conflictingResults, result => result.Outcome == AgentTransportOutcome.IdentityConflict);
        Assert.Equal(1, await ReceiptCountAsync());
    }

    [Fact]
    public async Task SqlDigestVector_PreservesExactUtcTicks()
    {
        const long ticks = 639028910456789012;
        var digest = await fixture.ScalarOwnerAsync<string>(
            """
            SELECT encode(sha256(
                int4send(2) || int4send(1) ||
                int4send(octet_length(convert_to('00112233-4455-6677-8899-aabbccddeeff','UTF8'))) ||
                convert_to('00112233-4455-6677-8899-aabbccddeeff','UTF8') ||
                int8send(7) || int8send(42) ||
                int4send(octet_length(convert_to('ffeeddcc-bbaa-9988-7766-554433221100','UTF8'))) ||
                convert_to('ffeeddcc-bbaa-9988-7766-554433221100','UTF8') ||
                int8send(@ticks) || int4send(64) || convert_to(repeat('a',64),'UTF8')), 'hex')
            """,
            new NpgsqlParameter("ticks", ticks));

        Assert.Equal("9d5e37fd0dc090c58fb2e99005e3711bce5f6d5e37492eefc866c6b6ef09eda3", digest);
    }

    [Fact]
    public async Task CallerCancellation_ReturnsUnknownWithoutAcknowledgement()
    {
        var seed = await fixture.SeedAsync();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var result = await Repository().IngestAsync(Peer(seed), Heartbeat(seed), cancellation.Token);

        Assert.Equal(AgentTransportOutcome.Unknown, result.Outcome);
        Assert.Null(result.Acknowledgement);
        Assert.Equal(0, await ReceiptCountAsync());
    }

    private AgentIngestionRepository Repository() => new(fixture.IngestDataSource);

    private static AttestedAgentPeer Peer(TestRegistration seed) =>
        AttestedAgentPeer.FromValidatedChannel(seed.Fingerprint);

    private static SpoolEnvelope Heartbeat(
        TestRegistration seed,
        long sequence = 1,
        Guid? requestId = null,
        DateTimeOffset? observedAt = null)
    {
        var body = JsonSerializer.SerializeToElement(new AgentHeartbeatPayload(1, "test-agent"));
        var payload = JsonSerializer.SerializeToElement(
            new AgentMessagePayload(1, AgentMessageKind.Heartbeat, body),
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        return Envelope(seed, sequence, requestId ?? Guid.NewGuid(), payload, observedAt);
    }

    private static SpoolEnvelope Inventory(
        TestRegistration seed,
        long sequence,
        string marker,
        DateTimeOffset? observedAt = null)
    {
        var body = JsonSerializer.SerializeToElement(new
        {
            SchemaVersion = 1,
            CollectedAt = DateTimeOffset.UtcNow,
            Collectors = new[]
            {
                new
                {
                    Collector = "basic-device",
                    Status = 0,
                    Quality = 0,
                    Source = "synthetic",
                    ObservedAt = DateTimeOffset.UtcNow,
                    Data = new { HostName = marker, OperatingSystem = new { Description = "test", Version = "1", Architecture = "x64" }, NetworkInterfaces = Array.Empty<object>(), IsTruncated = false },
                    ItemCount = 1,
                    ErrorCode = (string?)null
                }
            }
        });
        var payload = JsonSerializer.SerializeToElement(
            new AgentMessagePayload(1, AgentMessageKind.InventorySnapshot, body),
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        return Envelope(seed, sequence, Guid.NewGuid(), payload, observedAt);
    }

    private static SpoolEnvelope HardwareInventory(TestRegistration seed, long sequence, bool includeUnknownKey)
    {
        var row = includeUnknownKey
            ? JsonSerializer.SerializeToElement(new { Manufacturer = "synthetic", Model = "model", TotalPhysicalMemory = 1024UL, Secret = "reject" })
            : JsonSerializer.SerializeToElement(new { Manufacturer = "synthetic", Model = "model", TotalPhysicalMemory = 1024UL });
        var body = JsonSerializer.SerializeToElement(new
        {
            SchemaVersion = 1,
            CollectedAt = DateTimeOffset.UtcNow,
            Collectors = new[]
            {
                new
                {
                    Collector = "hardware",
                    Status = 0,
                    Quality = 0,
                    Source = "synthetic",
                    ObservedAt = DateTimeOffset.UtcNow,
                    Data = new
                    {
                        SchemaVersion = 1,
                        Sections = new[]
                        {
                            new
                            {
                                Kind = 0,
                                Source = "Win32_ComputerSystem",
                                Quality = 0,
                                ObservedAt = DateTimeOffset.UtcNow,
                                Rows = new[] { row },
                                IsTruncated = false,
                                ErrorCode = (string?)null
                            }
                        }
                    },
                    ItemCount = 1,
                    ErrorCode = (string?)null
                }
            }
        });
        var payload = JsonSerializer.SerializeToElement(
            new AgentMessagePayload(1, AgentMessageKind.InventorySnapshot, body),
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        return Envelope(seed, sequence, Guid.NewGuid(), payload);
    }

    private static SpoolEnvelope MalformedInventory(
        TestRegistration seed,
        long sequence,
        object bodySchema,
        object status,
        object quality,
        object itemCount)
    {
        var body = JsonSerializer.SerializeToElement(new
        {
            SchemaVersion = bodySchema,
            CollectedAt = DateTimeOffset.UtcNow,
            Collectors = new[]
            {
                new
                {
                    Collector = "basic-device",
                    Status = status,
                    Quality = quality,
                    Source = "synthetic",
                    ObservedAt = DateTimeOffset.UtcNow,
                    Data = new
                    {
                        HostName = "synthetic",
                        OperatingSystem = new { Description = "test", Version = "1", Architecture = "x64" },
                        NetworkInterfaces = Array.Empty<object>(),
                        IsTruncated = false
                    },
                    ItemCount = itemCount,
                    ErrorCode = (string?)null
                }
            }
        });
        var payload = JsonSerializer.SerializeToElement(
            new AgentMessagePayload(1, AgentMessageKind.InventorySnapshot, body),
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        return Envelope(seed, sequence, Guid.NewGuid(), payload);
    }

    private static SpoolEnvelope Envelope(
        TestRegistration seed,
        long sequence,
        Guid requestId,
        JsonElement payload,
        DateTimeOffset? observedAtOverride = null)
    {
        var observedAt = observedAtOverride ?? DateTimeOffset.UtcNow;
        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var payloadHash = Convert.ToHexStringLower(SHA256.HashData(payloadBytes));
        var envelopeHash = EnvelopeDigest.Compute(
            1,
            seed.DeviceGuid,
            seed.RegistrationEpoch,
            sequence,
            requestId,
            observedAt,
            payloadHash);
        return new SpoolEnvelope(
            1,
            seed.DeviceGuid,
            seed.RegistrationEpoch,
            sequence,
            requestId,
            observedAt,
            payloadHash,
            envelopeHash,
            payload);
    }

    private Task<long> ReceiptCountAsync() =>
        fixture.ScalarOwnerAsync<long>("SELECT count(*) FROM agent_private.receipts");

    private Task<long> HistoryCountAsync() =>
        fixture.ScalarOwnerAsync<long>("SELECT count(*) FROM agent_private.snapshot_history");

    private Task<Guid> ProjectionReceiptAsync(TestRegistration seed) =>
        fixture.ScalarOwnerAsync<Guid>(
            "SELECT receipt_id FROM agent_private.inventory_projection WHERE environment_id=@environment AND device_id=@device",
            new NpgsqlParameter("environment", seed.EnvironmentId),
            new NpgsqlParameter("device", seed.DeviceId));

    private async Task<(long Epoch, long Sequence, Guid ReceiptId)> ProjectionStateAsync(TestRegistration seed)
    {
        await using var command = fixture.OwnerDataSource.CreateCommand(
            "SELECT registration_epoch,sequence,receipt_id FROM agent_private.inventory_projection WHERE environment_id=@environment AND device_id=@device");
        command.Parameters.AddWithValue("environment", seed.EnvironmentId);
        command.Parameters.AddWithValue("device", seed.DeviceId);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (reader.GetInt64(0), reader.GetInt64(1), reader.GetGuid(2));
    }

    private async Task<(DateTimeOffset? LastSeen, Guid? ReceiptId)> DeviceHeartbeatStateAsync(TestRegistration seed)
    {
        await using var command = fixture.OwnerDataSource.CreateCommand(
            "SELECT last_seen_at,last_heartbeat_receipt_id FROM agent_private.devices WHERE environment_id=@environment AND device_id=@device");
        command.Parameters.AddWithValue("environment", seed.EnvironmentId);
        command.Parameters.AddWithValue("device", seed.DeviceId);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (
            reader.IsDBNull(0) ? null : reader.GetFieldValue<DateTimeOffset>(0),
            reader.IsDBNull(1) ? null : reader.GetGuid(1));
    }

    private sealed class SyntheticBasicDeviceSource : IBasicDeviceDataSource
    {
        public ValueTask<BasicDeviceInventory> ReadAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(new BasicDeviceInventory(
                "synthetic-host",
                new OperatingSystemInventory("Synthetic OS", "1.0", "x64"),
                [new NetworkInterfaceInventory("test0", "Ethernet", ["192.0.2.1"], [], ["192.0.2.53"], "001122334455")]));
    }

    private sealed class SyntheticSoftwareRegistry : IInstalledSoftwareRegistry
    {
        public ValueTask<InstalledSoftwareRegistryReadResult> ReadUninstallEntriesAsync(
            RegistryArchitectureView view,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new InstalledSoftwareRegistryReadResult(
                [new RegistrySoftwareEntry("Synthetic App", "1.0", "Test", "20260912", view)],
                false));
    }

    private sealed class SyntheticHardwareReader : IHardwareQueryReader
    {
        public ValueTask<HardwareQueryResult> ReadAsync(HardwareQueryKind kind, CancellationToken cancellationToken)
        {
            var property = HardwareQueryCatalog.Get(kind).Properties.First();
            var row = JsonSerializer.SerializeToElement(new Dictionary<string, object?> { [property] = "synthetic" });
            return ValueTask.FromResult(new HardwareQueryResult(ObservationQuality.Observed, DateTimeOffset.UtcNow, [row]));
        }
    }
}
