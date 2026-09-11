using ItManagement.AgentProjection;

namespace ItManagement.IntegrationTests;

public sealed class AgentProjectionConfigurationTests
{
    [Fact]
    public async Task Empty_configuration_is_unavailable_and_initializes_only_once()
    {
        await using var reader = new ConfiguredAgentProjectionReader(); var env = Guid.NewGuid(); var id = Guid.NewGuid();
        Assert.Equal(ProjectionReadState.Unavailable, (await reader.ReadAsync(env, id, CancellationToken.None)).State);
        await reader.InitializeAsync(new(), CancellationToken.None);
        var result = await reader.ReadAsync(env, id, CancellationToken.None);
        Assert.Equal(ProjectionDiagnostic.ConnectionUnavailable, result.DiagnosticCode);
        Assert.Equal(env, result.EnvironmentId); Assert.Equal(id, result.DirectoryObjectId);
        Assert.Empty(result.Volumes);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => reader.InitializeAsync(new(), CancellationToken.None));
        Assert.Equal("ProjectionAlreadyInitialized", error.Message);
    }

    [Theory]
    [InlineData("invalid-environment")] [InlineData("empty-environment")] [InlineData("no-owner")]
    [InlineData("long-owner")] [InlineData("no-function-owner")] [InlineData("no-connection")]
    [InlineData("remote-no-verify-full")] [InlineData("invalid-connection")]
    public async Task Malformed_configuration_is_rejected_without_exposing_details(string variant)
    {
        var key = variant == "invalid-environment" ? "not-a-guid" : variant == "empty-environment" ? Guid.Empty.ToString() : Guid.NewGuid().ToString();
        var entry = new AgentProjectionEnvironmentOptions { TableOwnerRole = "synthetic_owner", FunctionOwnerRole = "synthetic_reader_owner",
            ConnectionString = "Host=never-connect.invalid;Username=synthetic_projection;Password=CONFIG-SECRET-CANARY;SSL Mode=Disable" };
        if (variant == "no-owner") entry.TableOwnerRole = "";
        if (variant == "long-owner") entry.TableOwnerRole = new string('x', 64);
        if (variant == "no-function-owner") entry.FunctionOwnerRole = " ";
        if (variant == "no-connection") entry.ConnectionString = "";
        if (variant == "invalid-connection") entry.ConnectionString = "CONFIG-SECRET-CANARY=unsupported";
        await using var reader = new ConfiguredAgentProjectionReader();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => reader.InitializeAsync(new() { Environments = new() { [key] = entry } }, CancellationToken.None));
        Assert.Equal("AgentProjectionConfigurationRejected", error.Message); Assert.Null(error.InnerException);
        Assert.DoesNotContain("CONFIG-SECRET-CANARY", error.ToString());
        Assert.Equal(ProjectionReadState.Unavailable, (await reader.ReadAsync(Guid.NewGuid(), Guid.NewGuid(), CancellationToken.None)).State);
    }

    [Fact]
    public async Task Environment_limit_is_checked_before_any_connection()
    {
        var options = new AgentProjectionOptions { Environments = Enumerable.Range(0, 33).ToDictionary(_ => Guid.NewGuid().ToString(), _ => new AgentProjectionEnvironmentOptions()) };
        await using var reader = new ConfiguredAgentProjectionReader();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => reader.InitializeAsync(options, CancellationToken.None));
        Assert.Equal("AgentProjectionConfigurationRejected", error.Message);
    }
}
