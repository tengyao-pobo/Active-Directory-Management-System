using ItManagement.Agent.Runtime;
using ItManagement.AgentHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "IT Management Inventory Agent");
builder.Services.AddSingleton<AgentExitStatus>();
// A reviewed enrollment/credential composition must replace this before activation.
builder.Services.AddSingleton<IAgentRunLoop, NotConfiguredAgentRunLoop>();
builder.Services.AddHostedService<AgentHostedService>();
using var host = builder.Build();
await host.RunAsync();
return host.Services.GetRequiredService<AgentExitStatus>().Code;
