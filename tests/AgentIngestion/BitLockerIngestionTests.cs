using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using ItManagement.Agent.Collectors;
using ItManagement.Agent.Inventory;
using ItManagement.Agent.Runtime;
using ItManagement.Agent.Spool;

namespace ItManagement.AgentIngestion.Tests;

[Collection(AgentIngestionCollection.Name)]
public sealed class BitLockerIngestionTests(AgentIngestionFixture fixture)
{
    private const string Source = @"root\cimv2\Security\MicrosoftVolumeEncryption:Win32_EncryptableVolume";
    private static JsonObject Volume() => new()
    {
        ["DeviceId"] = @"\\?\Volume{11111111-1111-1111-1111-111111111111}\", ["PersistentVolumeId"] = "",
        ["DriveLetter"] = "C:", ["VolumeType"] = 0, ["ProtectionStatus"] = 1,
        ["ConversionStatus"] = 1, ["EncryptionMethod"] = 6, ["IsVolumeInitializedForProtection"] = true
    };
    private static JsonObject Collector() => new()
    {
        ["Collector"] = "bitlocker", ["Status"] = 0, ["Quality"] = 0, ["Source"] = Source,
        ["ObservedAt"] = DateTimeOffset.UtcNow, ["ItemCount"] = 1, ["ErrorCode"] = null,
        ["Data"] = new JsonObject { ["SchemaVersion"] = 1, ["Volumes"] = new JsonArray(Volume()), ["IsTruncated"] = false, ["ErrorCode"] = null }
    };
    private static SpoolEnvelope Envelope(TestRegistration seed, JsonObject collector, long sequence)
    {
        var now = DateTimeOffset.UtcNow;
        var body = JsonSerializer.SerializeToElement(new JsonObject { ["SchemaVersion"] = 1, ["CollectedAt"] = now, ["Collectors"] = new JsonArray(collector) });
        var payload = JsonSerializer.SerializeToElement(new AgentMessagePayload(1, AgentMessageKind.InventorySnapshot, body), new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var payloadHash = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web))));
        var request = Guid.NewGuid();
        return new(1, seed.DeviceGuid, seed.RegistrationEpoch, sequence, request, now, payloadHash,
            EnvelopeDigest.Compute(1, seed.DeviceGuid, seed.RegistrationEpoch, sequence, request, now, payloadHash), payload);
    }
    private Task<AgentTransportResult> Ingest(TestRegistration seed, JsonObject collector, long sequence = 1) =>
        new AgentIngestionRepository(fixture.IngestDataSource).IngestAsync(AttestedAgentPeer.FromValidatedChannel(seed.Fingerprint), Envelope(seed, collector, sequence), CancellationToken.None);

    [Fact]
    public async Task Fixed_collector_spool_and_repository_roundtrip_without_secret_material()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"bitlocker-roundtrip-{Guid.NewGuid():N}");
        try
        {
            await using var spool = await OfflineSpool.OpenAsync(directory, registrationEpoch: 1);
            var seed = await fixture.SeedAsync(deviceGuid: spool.Identity.DeviceGuid);
            var snapshot = await new CollectorRunner().CollectAsync([new BitLockerCollector(new SyntheticReader())]);
            var collector = Assert.Single(snapshot.Collectors);
            Assert.Equal(CollectorStatus.Completed, collector.Status);
            Assert.Equal(ObservationQuality.Observed, collector.Quality);
            Assert.Equal(Source, collector.Source);
            var body = JsonSerializer.SerializeToElement(snapshot);
            Assert.DoesNotContain("secret-canary", body.GetRawText());
            Assert.DoesNotContain("RecoveryPassword", body.GetRawText());
            var queue = await spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UtcNow, new AgentMessagePayload(1, AgentMessageKind.InventorySnapshot, body));
            var persisted = Assert.Single(await spool.ReadPendingAsync());
            Assert.Equal(queue.Payload.GetRawText(), persisted.Payload.GetRawText());
            var repository = new AgentIngestionRepository(fixture.IngestDataSource);
            var peer = AttestedAgentPeer.FromValidatedChannel(seed.Fingerprint);
            var first = await repository.IngestAsync(peer, persisted, CancellationToken.None);
            var second = await repository.IngestAsync(peer, persisted, CancellationToken.None);
            Assert.Equal(AgentTransportOutcome.Accepted, first.Outcome);
            Assert.Equal(AgentTransportOutcome.AlreadyAccepted, second.Outcome);
            Assert.Equal(first.Acknowledgement, second.Acknowledgement);
            Assert.Equal(1, await fixture.ScalarOwnerAsync<long>("SELECT count(*) FROM agent_private.snapshot_history"));
            var stored = await fixture.ScalarOwnerAsync<string>("SELECT normalized_payload::text FROM agent_private.inventory_projection");
            Assert.DoesNotContain("secret-canary", stored);
            using var parsed = JsonDocument.Parse(stored);
            var volume = parsed.RootElement.GetProperty("Collectors")[0].GetProperty("Data").GetProperty("Volumes")[0];
            Assert.Equal(uint.MaxValue, volume.GetProperty("ProtectionStatus").GetUInt32());
            Assert.Equal("", volume.GetProperty("PersistentVolumeId").GetString());
            Assert.False(volume.GetProperty("IsVolumeInitializedForProtection").GetBoolean());
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
    }

    private sealed class SyntheticReader : IBitLockerQueryReader
    {
        public ValueTask<BitLockerQueryResult> ReadAsync(CancellationToken cancellationToken) => ValueTask.FromResult(new BitLockerQueryResult(
            ObservationQuality.Observed, DateTimeOffset.UtcNow,
            [JsonSerializer.SerializeToElement(new { DeviceID = "synthetic-volume", PersistentVolumeID = "", DriveLetter = "c:",
                VolumeType = 0u, ProtectionStatus = uint.MaxValue, ConversionStatus = 0u, EncryptionMethod = 0u,
                IsVolumeInitializedForProtection = false, RecoveryPassword = "secret-canary" })]));
    }

    [Theory]
    [InlineData("future_codes")]
    [InlineData("null_unknowns")]
    [InlineData("zero_instances")]
    [InlineData("incomplete")]
    [InlineData("access_denied")]
    [InlineData("query_timeout")]
    [InlineData("query_unavailable")]
    [InlineData("native_query_busy")]
    [InlineData("invalid_output")]
    [InlineData("runner_timeout")]
    [InlineData("conflicting_states")]
    public async Task Valid_metadata_and_explicit_unavailable_states_are_persisted(string variant)
    {
        var seed = await fixture.SeedAsync(); var collector = Collector(); var data = collector["Data"]!.AsObject();
        var row = data["Volumes"]![0]!.AsObject();
        switch (variant)
        {
            case "future_codes": row["ProtectionStatus"] = uint.MaxValue; row["EncryptionMethod"] = 999; break;
            case "null_unknowns": foreach (var key in row.Select(x => x.Key).Where(x => x != "DeviceId").ToArray()) row[key] = null; break;
            case "zero_instances": data["Volumes"] = new JsonArray(); collector["ItemCount"] = 0; break;
            case "incomplete": data["Volumes"] = new JsonArray(); collector["ItemCount"] = 0; data["IsTruncated"] = true; break;
            case "runner_timeout": collector["Status"] = 1; collector["Quality"] = 1; collector["Source"] = "bitlocker"; collector["Data"] = null; collector["ItemCount"] = 0; collector["ErrorCode"] = "timeout"; break;
            case "conflicting_states": row["ProtectionStatus"] = 1; row["ConversionStatus"] = 0; row["EncryptionMethod"] = 0; row["IsVolumeInitializedForProtection"] = false; break;
            default: collector["Quality"] = variant == "access_denied" ? 3 : 1; data["ErrorCode"] = variant; data["Volumes"] = new JsonArray(); collector["ItemCount"] = 0; break;
        }
        var result = await Ingest(seed, collector);
        Assert.Equal(AgentTransportOutcome.Accepted, result.Outcome);
        Assert.Equal(1, await fixture.ScalarOwnerAsync<long>("SELECT count(*) FROM agent_private.snapshot_history"));
    }

    [Theory]
    [InlineData("secret_row")]
    [InlineData("secret_data")]
    [InlineData("missing_key")]
    [InlineData("string_number")]
    [InlineData("negative_number")]
    [InlineData("fractional_number")]
    [InlineData("overflow_number")]
    [InlineData("bad_boolean")]
    [InlineData("lowercase_drive")]
    [InlineData("empty_id")]
    [InlineData("control_id")]
    [InlineData("overlength_id")]
    [InlineData("overlength_persistent")]
    [InlineData("duplicate_id")]
    [InlineData("too_many")]
    [InlineData("item_count")]
    [InlineData("source")]
    [InlineData("not_applicable")]
    [InlineData("error_with_observations")]
    [InlineData("unavailable_with_rows")]
    [InlineData("unavailable_truncated")]
    [InlineData("wrong_error")]
    [InlineData("runner_null_error")]
    public async Task Malformed_or_secret_bearing_payloads_do_not_update_receipts_or_projection(string variant)
    {
        var seed = await fixture.SeedAsync(); var first = await Ingest(seed, Collector());
        Assert.Equal(AgentTransportOutcome.Accepted, first.Outcome);
        var receipt = await fixture.ScalarOwnerAsync<Guid>("SELECT receipt_id FROM agent_private.inventory_projection");
        var collector = Collector(); var data = collector["Data"]!.AsObject(); var row = data["Volumes"]![0]!.AsObject();
        switch (variant)
        {
            case "secret_row": row["RecoveryPassword"] = "synthetic-secret-canary"; break;
            case "secret_data": data["KeyProtectors"] = "synthetic-secret-canary"; break;
            case "missing_key": row.Remove("ProtectionStatus"); break;
            case "string_number": row["ProtectionStatus"] = "1"; break;
            case "negative_number": row["ProtectionStatus"] = -1; break;
            case "fractional_number": row["ProtectionStatus"] = 1.5; break;
            case "overflow_number": row["ProtectionStatus"] = 4294967296L; break;
            case "bad_boolean": row["IsVolumeInitializedForProtection"] = 1; break;
            case "lowercase_drive": row["DriveLetter"] = "c:"; break;
            case "empty_id": row["DeviceId"] = " "; break;
            case "control_id": row["DeviceId"] = "bad\nidentifier"; break;
            case "overlength_id": row["DeviceId"] = new string('x', 513); break;
            case "overlength_persistent": row["PersistentVolumeId"] = new string('x', 513); break;
            case "duplicate_id": var duplicate = row.DeepClone().AsObject(); duplicate["DeviceId"] = row["DeviceId"]!.GetValue<string>().ToUpperInvariant(); data["Volumes"]!.AsArray().Add(duplicate); collector["ItemCount"] = 2; break;
            case "too_many": data["Volumes"] = new JsonArray(Enumerable.Range(0, 129).Select(i => { var value = Volume(); value["DeviceId"] = $"synthetic-{i}"; return (JsonNode)value; }).ToArray()); collector["ItemCount"] = 129; break;
            case "item_count": collector["ItemCount"] = 0; break;
            case "source": collector["Source"] = "caller-controlled"; break;
            case "not_applicable": collector["Quality"] = 2; break;
            case "error_with_observations": data["ErrorCode"] = "query_timeout"; break;
            case "unavailable_with_rows": collector["Quality"] = 3; data["ErrorCode"] = "access_denied"; break;
            case "unavailable_truncated": collector["Quality"] = 1; data["Volumes"] = new JsonArray(); collector["ItemCount"] = 0; data["IsTruncated"] = true; data["ErrorCode"] = "query_timeout"; break;
            case "wrong_error": collector["Quality"] = 3; data["Volumes"] = new JsonArray(); collector["ItemCount"] = 0; data["ErrorCode"] = "query_timeout"; break;
            case "runner_null_error": collector["Status"] = 1; collector["Quality"] = 1; collector["Source"] = "bitlocker"; collector["Data"] = null; collector["ItemCount"] = 0; break;
        }
        Assert.Equal(AgentTransportOutcome.PermanentRejected, (await Ingest(seed, collector, 2)).Outcome);
        Assert.Equal(1, await fixture.ScalarOwnerAsync<long>("SELECT count(*) FROM agent_private.receipts"));
        Assert.Equal(1, await fixture.ScalarOwnerAsync<long>("SELECT count(*) FROM agent_private.snapshot_history"));
        Assert.Equal(receipt, await fixture.ScalarOwnerAsync<Guid>("SELECT receipt_id FROM agent_private.inventory_projection"));
        Assert.Equal(1, await fixture.ScalarOwnerAsync<long>("SELECT high_sequence FROM agent_private.replay_state"));
    }
}
