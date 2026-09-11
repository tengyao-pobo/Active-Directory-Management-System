using ItManagement.Core;

namespace ItManagement.UnitTests;

public sealed class AgentConnectivityTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 11, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(0, AgentConnectionState.Online)]
    [InlineData(119, AgentConnectionState.Online)]
    [InlineData(120, AgentConnectionState.Stale)]
    [InlineData(900, AgentConnectionState.Stale)]
    [InlineData(901, AgentConnectionState.Offline)]
    [InlineData(-1, AgentConnectionState.Unknown)]
    public void Uses_server_receipt_time_and_explicit_boundaries(int seconds, AgentConnectionState expected) =>
        Assert.Equal(expected, AgentConnectivityPolicy.Default.Classify(Now.AddSeconds(-seconds), Now));

    [Fact]
    public void No_heartbeat_is_never_connected() =>
        Assert.Equal(AgentConnectionState.NeverConnected, AgentConnectivityPolicy.Default.Classify(null, Now));

    [Fact]
    public void Custom_windows_apply_without_changing_registration_state()
    {
        var policy = new AgentConnectivityPolicy(TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(20));
        Assert.Equal(AgentConnectionState.Stale, policy.Classify(Now.AddSeconds(-10), Now));
        Assert.Equal(AgentConnectionState.Offline, policy.Classify(Now.AddSeconds(-21), Now));
    }

    [Theory]
    [InlineData(0, 20)]
    [InlineData(-1, 20)]
    [InlineData(30, 20)]
    [InlineData(30, 604801)]
    public void Rejects_invalid_windows(int online, int offline) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentConnectivityPolicy(TimeSpan.FromSeconds(online), TimeSpan.FromSeconds(offline)));
}
