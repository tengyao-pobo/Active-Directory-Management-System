using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace ItManagement.EnrollmentWorker;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        using var stop = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, eventArgs) => { eventArgs.Cancel = true; stop.Cancel(); };
        Console.CancelKeyPress += cancel;
        try
        {
            return await EnrollmentWorkerCommand.RunAsync(args, LoadConfiguration,
                PostgresEnrollmentWorkerEnvironment.CreateAuditedAsync, Console.Out, stop.Token).ConfigureAwait(false);
        }
        finally { Console.CancelKeyPress -= cancel; }
    }

    private static EnrollmentWorkerOptions LoadConfiguration()
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = [],
            ContentRootPath = AppContext.BaseDirectory
        });
        using var host = builder.Build();
        return BindConfiguration(builder.Configuration);
    }

    internal static EnrollmentWorkerOptions BindConfiguration(IConfiguration configuration) =>
        configuration.GetSection("EnrollmentWorker").Get<EnrollmentWorkerOptions>(
            binding => binding.ErrorOnUnknownConfiguration = true)
            ?? throw new InvalidOperationException("EnrollmentWorkerConfigurationMissing");
}
