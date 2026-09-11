namespace ItManagement.Core;

public enum AgentConnectionState { NeverConnected, Online, Stale, Offline, Unknown }

/// <summary>Classifies only server-received heartbeat time, never endpoint wall clock.</summary>
public sealed record AgentConnectivityPolicy
{
    public TimeSpan OnlineWindow { get; }
    public TimeSpan OfflineAfter { get; }

    public static AgentConnectivityPolicy Default { get; } = new(TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(15));

    public AgentConnectivityPolicy(TimeSpan onlineWindow, TimeSpan offlineAfter)
    {
        if (onlineWindow <= TimeSpan.Zero || offlineAfter < onlineWindow || offlineAfter > TimeSpan.FromDays(7))
            throw new ArgumentOutOfRangeException(nameof(offlineAfter), "Heartbeat windows must be positive, ordered and at most seven days.");
        OnlineWindow = onlineWindow;
        OfflineAfter = offlineAfter;
    }

    public AgentConnectionState Classify(DateTimeOffset? lastReceivedAt, DateTimeOffset now)
    {
        if (lastReceivedAt is null) return AgentConnectionState.NeverConnected;
        if (lastReceivedAt > now) return AgentConnectionState.Unknown;
        var elapsed = now - lastReceivedAt.Value;
        if (elapsed < OnlineWindow) return AgentConnectionState.Online;
        return elapsed <= OfflineAfter ? AgentConnectionState.Stale : AgentConnectionState.Offline;
    }
}
