using System.Data;
using System.Text.Json;
using ItManagement.Agent.Runtime;
using ItManagement.Agent.Spool;
using Npgsql;
using NpgsqlTypes;

namespace ItManagement.AgentIngestion;

public sealed class AgentIngestionRepository
{
    private const int MaxPayloadBytes = 512 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly NpgsqlDataSource _dataSource;

    public AgentIngestionRepository(NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
    }

    public async Task<AgentTransportResult> IngestAsync(
        AttestedAgentPeer peer,
        SpoolEnvelope envelope,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(peer);
        ArgumentNullException.ThrowIfNull(envelope);
        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(envelope.Payload, JsonOptions);
        if (payloadBytes.Length > MaxPayloadBytes)
        {
            return AgentTransportResult.PermanentRejected();
        }

        try
        {
            await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(
                IsolationLevel.ReadCommitted,
                cancellationToken).ConfigureAwait(false);
            await using var command = new NpgsqlCommand(
                """
                SELECT outcome, diagnostic_code, receipt_id, ack_schema_version, ack_protocol_version,
                       ack_device_guid, ack_registration_epoch, ack_sequence, ack_request_id, ack_observed_utc_ticks,
                       ack_payload_hash, ack_envelope_hash
                FROM agent_private.ingest_attested_envelope(
                    @certificate_fingerprint, @protocol_version, @device_guid, @registration_epoch,
                    @sequence, @request_id, @observed_utc_ticks, @payload_bytes,
                    @payload_hash, @envelope_hash)
                """,
                connection,
                transaction);
            command.Parameters.AddWithValue("certificate_fingerprint", NpgsqlDbType.Bytea, peer.GetLeafDerSha256());
            command.Parameters.AddWithValue("protocol_version", NpgsqlDbType.Integer, envelope.ProtocolVersion);
            command.Parameters.AddWithValue("device_guid", NpgsqlDbType.Uuid, envelope.DeviceGuid);
            command.Parameters.AddWithValue("registration_epoch", NpgsqlDbType.Bigint, envelope.RegistrationEpoch);
            command.Parameters.AddWithValue("sequence", NpgsqlDbType.Bigint, envelope.Sequence);
            command.Parameters.AddWithValue("request_id", NpgsqlDbType.Uuid, envelope.RequestId);
            command.Parameters.AddWithValue("observed_utc_ticks", NpgsqlDbType.Bigint, envelope.ObservedAt.UtcTicks);
            command.Parameters.AddWithValue("payload_bytes", NpgsqlDbType.Bytea, payloadBytes);
            command.Parameters.AddWithValue("payload_hash", NpgsqlDbType.Text, envelope.PayloadHash);
            command.Parameters.AddWithValue("envelope_hash", NpgsqlDbType.Text, envelope.EnvelopeHash);

            await using var reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken)
                .ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
                return AgentTransportResult.Unknown();
            }

            var stored = ReadResult(reader);
            await reader.CloseAsync().ConfigureAwait(false);
            if (stored.Outcome is "Accepted" or "AlreadyAccepted")
            {
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return stored.Outcome == "Accepted"
                    ? AgentTransportResult.AcceptedFromAuthenticatedChannel(stored.Acknowledgement!)
                    : AgentTransportResult.AcceptedFromAuthenticatedChannel(
                        stored.Acknowledgement!,
                        alreadyAccepted: true);
            }

            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return stored.Outcome switch
            {
                "PermanentRejected" => AgentTransportResult.PermanentRejected(),
                "IdentityConflict" => AgentTransportResult.IdentityConflict(),
                _ => AgentTransportResult.Unknown()
            };
        }
        catch (OperationCanceledException)
        {
            return AgentTransportResult.Unknown(AgentTransportDiagnosticCode.ResponseUnavailable);
        }
        catch (NpgsqlException)
        {
            return AgentTransportResult.Unknown(AgentTransportDiagnosticCode.ConnectionUnavailable);
        }
    }

    private static StoredResult ReadResult(NpgsqlDataReader reader)
    {
        var outcome = reader.GetString(0);
        var diagnosticCode = reader.GetString(1);
        if (outcome is not ("Accepted" or "AlreadyAccepted"))
        {
            return new StoredResult(outcome, diagnosticCode, null);
        }

        if (diagnosticCode != "None" || reader.IsDBNull(2))
        {
            return new StoredResult("Unknown", "ResponseUnavailable", null);
        }

        var acknowledgement = new EnvelopeAcknowledgement(
            reader.GetInt32(3),
            reader.GetInt32(4),
            reader.GetGuid(5),
            reader.GetInt64(6),
            reader.GetInt64(7),
            reader.GetGuid(8),
            new DateTimeOffset(reader.GetInt64(9), TimeSpan.Zero),
            reader.GetString(10),
            reader.GetString(11));
        return new StoredResult(outcome, diagnosticCode, acknowledgement);
    }

    private sealed record StoredResult(
        string Outcome,
        string DiagnosticCode,
        EnvelopeAcknowledgement? Acknowledgement);
}
