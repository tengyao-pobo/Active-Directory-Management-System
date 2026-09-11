using System.Text.Json;
using ItManagement.Agent.Spool;

namespace ItManagement.Agent.Runtime;

public interface IAgentRunLoop
{
    Task RunAsync(CancellationToken cancellationToken);
}

public enum AgentTransportOutcome
{
    Accepted,
    AlreadyAccepted,
    Retryable,
    PermanentRejected,
    IdentityConflict,
    Unknown,
    NotConfigured
}

public enum AgentTransportDiagnosticCode
{
    None,
    Timeout,
    ConnectionUnavailable,
    AuthenticationFailed,
    ProtocolRejected,
    ResponseUnavailable
}

public sealed class AgentTransportResult
{
    private AgentTransportResult(
        AgentTransportOutcome outcome,
        bool isAuthenticatedChannel,
        EnvelopeAcknowledgement? acknowledgement,
        TimeSpan? retryAfter,
        AgentTransportDiagnosticCode diagnosticCode)
    {
        Outcome = outcome;
        IsAuthenticatedChannel = isAuthenticatedChannel;
        Acknowledgement = acknowledgement;
        RetryAfter = retryAfter;
        DiagnosticCode = diagnosticCode;
    }

    public AgentTransportOutcome Outcome { get; }

    // This is adapter-attested channel state set only after certificate and TLS validation.
    public bool IsAuthenticatedChannel { get; }

    public EnvelopeAcknowledgement? Acknowledgement { get; }

    public TimeSpan? RetryAfter { get; }

    public AgentTransportDiagnosticCode DiagnosticCode { get; }

    public static AgentTransportResult AcceptedFromAuthenticatedChannel(
        EnvelopeAcknowledgement acknowledgement,
        bool alreadyAccepted = false)
    {
        ArgumentNullException.ThrowIfNull(acknowledgement);
        return new AgentTransportResult(
            alreadyAccepted ? AgentTransportOutcome.AlreadyAccepted : AgentTransportOutcome.Accepted,
            true,
            acknowledgement,
            null,
            AgentTransportDiagnosticCode.None);
    }

    public static AgentTransportResult Retryable(
        TimeSpan? retryAfter = null,
        AgentTransportDiagnosticCode diagnosticCode = AgentTransportDiagnosticCode.ConnectionUnavailable) =>
        new(AgentTransportOutcome.Retryable, false, null, retryAfter, diagnosticCode);

    public static AgentTransportResult PermanentRejected() =>
        new(
            AgentTransportOutcome.PermanentRejected,
            false,
            null,
            null,
            AgentTransportDiagnosticCode.ProtocolRejected);

    public static AgentTransportResult IdentityConflict() =>
        new(
            AgentTransportOutcome.IdentityConflict,
            false,
            null,
            null,
            AgentTransportDiagnosticCode.AuthenticationFailed);

    public static AgentTransportResult Unknown(
        AgentTransportDiagnosticCode diagnosticCode = AgentTransportDiagnosticCode.ResponseUnavailable) =>
        new(AgentTransportOutcome.Unknown, false, null, null, diagnosticCode);

    public static AgentTransportResult NotConfigured() =>
        new(
            AgentTransportOutcome.NotConfigured,
            false,
            null,
            null,
            AgentTransportDiagnosticCode.ConnectionUnavailable);
}

public interface IAgentTransport
{
    Task<AgentTransportResult> SendAsync(SpoolEnvelope envelope, CancellationToken cancellationToken);
}

public sealed class NotConfiguredAgentTransport : IAgentTransport
{
    public Task<AgentTransportResult> SendAsync(
        SpoolEnvelope envelope,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(AgentTransportResult.NotConfigured());
    }
}

public interface IRuntimeJitterSource
{
    double NextUnitInterval();
}

public sealed class RandomRuntimeJitterSource : IRuntimeJitterSource
{
    public double NextUnitInterval() => Random.Shared.NextDouble();
}

public enum AgentMessageKind
{
    Heartbeat,
    InventorySnapshot
}

public sealed record AgentMessagePayload(int SchemaVersion, AgentMessageKind Kind, JsonElement Body);

public sealed record AgentHeartbeatPayload(int SchemaVersion, string AgentVersion);

public sealed record AgentRuntimeOptions(
    TimeSpan InventoryInterval,
    TimeSpan HeartbeatInterval,
    double HeartbeatJitterFraction,
    TimeSpan TransportTimeout,
    TimeSpan InitialRetryDelay,
    TimeSpan MaxRetryDelay,
    double RetryJitterFraction,
    int MaxAgentVersionLength,
    int MaxCollectors = 32)
{
    public static AgentRuntimeOptions Default { get; } = new(
        TimeSpan.FromHours(24),
        TimeSpan.FromSeconds(60),
        0.20,
        TimeSpan.FromSeconds(30),
        TimeSpan.FromSeconds(1),
        TimeSpan.FromMinutes(5),
        0.20,
        128,
        32);

    internal void Validate()
    {
        ValidateDelay(InventoryInterval, nameof(InventoryInterval), TimeSpan.FromDays(31));
        ValidateDelay(HeartbeatInterval, nameof(HeartbeatInterval), TimeSpan.FromHours(24));
        ValidateDelay(TransportTimeout, nameof(TransportTimeout), TimeSpan.FromHours(1));
        ValidateDelay(InitialRetryDelay, nameof(InitialRetryDelay), TimeSpan.FromHours(1));
        ValidateDelay(MaxRetryDelay, nameof(MaxRetryDelay), TimeSpan.FromDays(1));
        if (InitialRetryDelay > MaxRetryDelay)
        {
            throw new ArgumentOutOfRangeException(nameof(InitialRetryDelay));
        }

        if (!double.IsFinite(HeartbeatJitterFraction) || HeartbeatJitterFraction is < 0 or > 0.5)
        {
            throw new ArgumentOutOfRangeException(nameof(HeartbeatJitterFraction));
        }

        if (!double.IsFinite(RetryJitterFraction) || RetryJitterFraction is < 0 or > 0.5)
        {
            throw new ArgumentOutOfRangeException(nameof(RetryJitterFraction));
        }

        if (MaxAgentVersionLength is < 1 or > 1_024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxAgentVersionLength));
        }


        if (MaxCollectors is < 1 or > 1_024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxCollectors));
        }
    }

    private static void ValidateDelay(TimeSpan value, string name, TimeSpan maximum)
    {
        if (value <= TimeSpan.Zero || value > maximum)
        {
            throw new ArgumentOutOfRangeException(name);
        }
    }
}
