using ItManagement.Agent.Runtime;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ItManagement.AgentHost;

public sealed class AgentExitStatus
{
    public int Code { get; internal set; }
}

public sealed class AgentHostedService(
    IAgentRunLoop runtime,
    IHostApplicationLifetime lifetime,
    AgentExitStatus exitStatus,
    ILogger<AgentHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await runtime.RunAsync(stoppingToken);
            if (!stoppingToken.IsCancellationRequested)
            {
                exitStatus.Code = 2;
                logger.LogWarning("agent_runtime_stopped");
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // SCM / host shutdown is a normal cancellation, not a delivery acknowledgement.
        }
        catch (Exception)
        {
            exitStatus.Code = 2;
            // Exception messages can contain local paths or inventory; retain only a fixed code.
            logger.LogError("agent_runtime_unavailable");
        }
        finally
        {
            lifetime.StopApplication();
        }
    }
}

/// <summary>No implicit enrollment, local identity creation or successful transport fallback.</summary>
public sealed class NotConfiguredAgentRunLoop : IAgentRunLoop
{
    public Task RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromException(new InvalidOperationException("agent_registration_not_configured"));
    }
}
