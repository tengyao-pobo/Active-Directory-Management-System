using ItManagement.AgentEnrollmentTargets;
using ItManagement.Api;

namespace ItManagement.IntegrationTests;

public sealed class EnrollmentTargetConfigurationTests
{
    [Fact]
    public async Task EmptyConfigurationAndDisposedReaderStayUnavailable()
    {
        await using var reader = new ConfiguredEnrollmentTargetReader();
        await reader.InitializeAsync(new(), CancellationToken.None);
        var env = Guid.NewGuid(); var directory = Guid.NewGuid();
        var result = await reader.ReadAsync(env, directory, CancellationToken.None);
        Assert.Equal(EnrollmentTargetState.Unavailable, result.State);
        Assert.Equal(env, result.EnvironmentId); Assert.Equal(directory, result.DirectoryObjectId);
        await Assert.ThrowsAsync<InvalidOperationException>(() => reader.InitializeAsync(new(), CancellationToken.None));
        await reader.DisposeAsync();
        Assert.Equal(EnrollmentTargetState.Unavailable, (await reader.ReadAsync(env, directory, CancellationToken.None)).State);
    }

    [Theory]
    [InlineData("environment")] [InlineData("remote-tls")] [InlineData("role")] [InlineData("connection")] [InlineData("limit")]
    public async Task InvalidConfigurationRejectsBeforeOpeningAPoolAndSanitizesDetails(string invalid)
    {
        var options = new EnrollmentTargetOptions();
        var environment = Guid.NewGuid().ToString();
        var entry = new EnrollmentTargetEnvironmentOptions
        {
            TableOwnerRole = "synthetic_table_owner", FunctionOwnerRole = "synthetic_read_definer",
            ConnectionString = "Host=synthetic.invalid;Database=synthetic;Username=synthetic;Password=CONFIG-CANARY;SSL Mode=VerifyFull"
        };
        if (invalid == "environment") environment = "CONFIG-CANARY";
        if (invalid == "remote-tls") entry.ConnectionString = entry.ConnectionString.Replace("VerifyFull", "Disable", StringComparison.Ordinal);
        if (invalid == "role") entry.FunctionOwnerRole = new string('x', 64);
        if (invalid == "connection") entry.ConnectionString = "";
        options.Environments.Add(environment, entry);
        if (invalid == "limit") for (var i = 0; i < 32; i++) options.Environments.Add(Guid.NewGuid().ToString(), new());
        await using var reader = new ConfiguredEnrollmentTargetReader();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => reader.InitializeAsync(options, CancellationToken.None));
        Assert.Equal("EnrollmentTargetConfigurationRejected", error.Message); Assert.Null(error.InnerException);
        Assert.Equal(EnrollmentTargetState.Unavailable, (await reader.ReadAsync(Guid.NewGuid(), Guid.NewGuid(), CancellationToken.None)).State);
    }
}
