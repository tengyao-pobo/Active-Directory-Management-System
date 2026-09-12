using ItManagement.EnrollmentGrantExecution;
using ItManagement.EnrollmentWorker;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace EnrollmentWorker.Tests;

public sealed class EnrollmentWorkerCommandTests
{
    [Theory]
    [InlineData("")]
    [InlineData("--process")]
    [InlineData("--enabled")]
    [InlineData("--verify --process")]
    public async Task UnsupportedActivationNeverLoadsConfigurationOrCreatesConnections(string arguments)
    {
        using var output = new StringWriter();
        Assert.Equal(2, await EnrollmentWorkerCommand.RunAsync(arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            () => throw new Exception("configuration must not be loaded"),
            (_, _) => throw new Exception("connection must not be created"), output, CancellationToken.None));
        Assert.Contains("ProcessingUnavailable", output.ToString());
    }

    [Fact]
    public async Task HelpDoesNotRequireConfiguration()
    {
        using var output = new StringWriter();
        Assert.Equal(0, await EnrollmentWorkerCommand.RunAsync(["--help"],
            () => throw new Exception(), (_, _) => throw new Exception(), output, CancellationToken.None));
        Assert.Contains("--verify", output.ToString());
    }

    [Fact]
    public async Task VerificationDisposesAuditedEnvironmentAndNeverProcessesWork()
    {
        using var output = new StringWriter();
        var disposed = false;
        Assert.Equal(0, await EnrollmentWorkerCommand.RunAsync(["--verify"], ValidOptions,
            (options, _) => Task.FromResult<IEnrollmentWorkerEnvironment>(new AuditedEnvironment(options.EnvironmentId,
                () => disposed = true)), output, CancellationToken.None));
        Assert.True(disposed);
        Assert.Contains("VerificationSucceeded", output.ToString());
        Assert.Contains("processing remains unavailable", output.ToString());
    }

    [Fact]
    public async Task ConfigurationAndProviderErrorsAreNeverPrinted()
    {
        foreach (var configurationFailure in new[] { true, false })
        {
            using var output = new StringWriter();
            Assert.Equal(1, await EnrollmentWorkerCommand.RunAsync(["--verify"],
                () => configurationFailure ? throw new Exception("configuration-secret") : ValidOptions(),
                (_, _) => throw new Exception("provider-secret"), output, CancellationToken.None));
            Assert.Equal("EnrollmentWorkerVerificationFailed" + Environment.NewLine, output.ToString());
        }
    }

    [Fact]
    public async Task CancellationDuringDisposalDoesNotReportSuccess()
    {
        using var cancellation = new CancellationTokenSource();
        using var output = new StringWriter();
        Assert.Equal(130, await EnrollmentWorkerCommand.RunAsync(["--verify"], ValidOptions,
            (options, _) => Task.FromResult<IEnrollmentWorkerEnvironment>(new AuditedEnvironment(options.EnvironmentId,
                cancellation.Cancel)), output, cancellation.Token));
        Assert.DoesNotContain("Succeeded", output.ToString());
    }

    [Theory]
    [InlineData("Enabled")]
    [InlineData("ConnectionString")]
    [InlineData("Environments:0:PublicDatabase:Options")]
    public void UnknownConfigurationCannotEnableOrOverrideConnectionSettings(string key)
    {
        using var configuration = new ConfigurationManager();
        configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["EnrollmentWorker:" + key] = "true" });
        Assert.Throws<InvalidOperationException>(() => Program.BindConfiguration(configuration));
    }

    private static EnrollmentWorkerOptions ValidOptions() => new()
    {
        Environments = [new()
        {
            EnvironmentId = Guid.NewGuid(),
            PublicDatabase = new()
            {
                Host = "public.db.example.test", Database = "public_db", Username = "execution_runtime",
                Password = "synthetic-public-password", RootCertificate = Path.Combine(Path.GetTempPath(), "root.pem"),
                ExpectedTableOwner = "public_owner", ExpectedExecutionOwner = "execution_owner", ExpectedQueueOwner = "queue_owner"
            },
            PrivateDatabase = new()
            {
                Host = "private.db.example.test", Database = "private_db", Username = "issue_runtime",
                Password = "synthetic-private-password", RootCertificate = Path.Combine(Path.GetTempPath(), "root.pem"),
                ExpectedTableOwner = "private_owner", ExpectedFunctionOwner = "issue_owner"
            }
        }]
    };

    private sealed class AuditedEnvironment(Guid id, Action dispose) : IEnrollmentWorkerEnvironment
    {
        public Guid EnvironmentId => id;
        public Task<EnrollmentWorkProcessOutcome> ProcessOnceAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Verification must not process work");
        public ValueTask DisposeAsync() { dispose(); return ValueTask.CompletedTask; }
    }
}
