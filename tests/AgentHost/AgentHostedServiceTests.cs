using ItManagement.Agent.Runtime;
using ItManagement.AgentHost;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;

namespace ItManagement.AgentHostTests;

public sealed class AgentHostedServiceTests
{
    [Fact]
    public async Task Failure_stops_host_and_does_not_log_exception_details()
    {
        var lifetime = new Lifetime();
        var status = new AgentExitStatus();
        var log = new CapturedLog();
        using var service = new AgentHostedService(new Loop(_ => Task.FromException(new IOException("private-inventory"))), lifetime, status, log);
        await service.StartAsync(default);
        await lifetime.Stopped.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(2, status.Code);
        Assert.Equal(["agent_runtime_unavailable"], log.Messages);
        Assert.Empty(log.Exceptions);
    }

    [Fact]
    public async Task Shutdown_cancels_loop_without_failure_status()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var lifetime = new Lifetime();
        var status = new AgentExitStatus();
        var log = new CapturedLog();
        using var service = new AgentHostedService(new Loop(async ct => { entered.SetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, ct); }), lifetime, status, log);
        await service.StartAsync(default);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync(default);
        Assert.Equal(0, status.Code);
        Assert.Empty(log.Messages);
        Assert.True(lifetime.Stopped.Task.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task Unexpected_completion_is_not_a_healthy_running_service()
    {
        var lifetime = new Lifetime();
        var status = new AgentExitStatus();
        var log = new CapturedLog();
        using var service = new AgentHostedService(new Loop(_ => Task.CompletedTask), lifetime, status, log);
        await service.StartAsync(default);
        await lifetime.Stopped.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(2, status.Code);
        Assert.Equal(["agent_runtime_stopped"], log.Messages);
    }

    [Fact]
    public async Task Unconfigured_composition_cannot_start_collection() =>
        await Assert.ThrowsAsync<InvalidOperationException>(() => new NotConfiguredAgentRunLoop().RunAsync(default));

    private sealed class Loop(Func<CancellationToken, Task> run) : IAgentRunLoop
    {
        public Task RunAsync(CancellationToken ct) => run(ct);
    }
    private sealed class Lifetime : IHostApplicationLifetime
    {
        public TaskCompletionSource Stopped { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public CancellationToken ApplicationStarted => default;
        public CancellationToken ApplicationStopping => default;
        public CancellationToken ApplicationStopped => default;
        public void StopApplication() => Stopped.TrySetResult();
    }
    private sealed class CapturedLog : ILogger<AgentHostedService>
    {
        public List<string> Messages { get; } = [];
        public List<Exception> Exceptions { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
            if (exception is not null) Exceptions.Add(exception);
        }
    }
}
