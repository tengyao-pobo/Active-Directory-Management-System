using System.Text.Json;

namespace ItManagement.Agent.Spool;

public sealed record OfflineSpoolOptions(int MaxFiles, long MaxBytes, int MaxPayloadBytes)
{
    private const int HardMaxFiles = 100_000;
    private const long HardMaxBytes = 10L * 1024 * 1024 * 1024;
    private const int HardMaxPayloadBytes = 64 * 1024 * 1024;
    public static OfflineSpoolOptions Default { get; } = new(1_000, 128L * 1024 * 1024, 512 * 1024);

    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxFiles);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxPayloadBytes);
        if (MaxFiles > HardMaxFiles)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxFiles));
        }

        if (MaxBytes > HardMaxBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxBytes));
        }

        if (MaxPayloadBytes > HardMaxPayloadBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxPayloadBytes));
        }
    }
}

public sealed record DeviceSpoolIdentity(Guid DeviceGuid, long RegistrationEpoch, long NextSequence);

public sealed record SpoolEnvelope(
    int ProtocolVersion,
    Guid DeviceGuid,
    long RegistrationEpoch,
    long Sequence,
    Guid RequestId,
    DateTimeOffset ObservedAt,
    string PayloadHash,
    string EnvelopeHash,
    JsonElement Payload);

public sealed class SpoolCapacityExceededException(string message) : InvalidOperationException(message);
