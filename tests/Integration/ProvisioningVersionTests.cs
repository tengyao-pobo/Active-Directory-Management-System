using System.Diagnostics;
using System.Security.Cryptography;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class ProvisioningVersionTests(PostgresApiFixture fixture)
{
    [Theory]
    [InlineData("bootstrap-owner", "local")]
    [InlineData("provision-connector-principal", "connector")]
    public async Task ProvisioningMembershipAtomicallyAdvancesAuthorizationVersion(string command, string issuer)
    {
        _ = fixture.UsesRuntimeRole;
        await using var db = Db();
        var environment = await SeedEnvironment(db);
        var operatorId = Guid.NewGuid();
        var name = $"provision-version-{Guid.NewGuid():N}";

        Assert.Equal(0, await RunProvisioning(command, environment.Id, operatorId, name));

        db.ChangeTracker.Clear();
        Assert.Equal(8, (await db.Environments.SingleAsync(x => x.Id == environment.Id)).Version);
        var principal = await db.Principals.SingleAsync(x => x.Issuer == issuer && x.Subject == name);
        Assert.Equal(operatorId, principal.OperatorId);
        Assert.True(await db.Memberships.AnyAsync(x => x.EnvironmentId == environment.Id && x.PrincipalId == principal.Id && x.Active));
        Assert.Equal(command == "bootstrap-owner" ? 1 : 0,
            await db.Assignments.CountAsync(x => x.EnvironmentId == environment.Id && x.PrincipalId == principal.Id));
    }

    [Theory]
    [InlineData("bootstrap-owner", "local")]
    [InlineData("provision-connector-principal", "connector")]
    public async Task FailedProvisioningRollsBackMembershipAndVersion(string command, string issuer)
    {
        await using var db = Db();
        var environment = await SeedEnvironment(db);
        var name = $"provision-conflict-{Guid.NewGuid():N}";
        db.Principals.Add(new Principal { Id = Guid.NewGuid(), OperatorId = Guid.NewGuid(),
            Issuer = issuer, Subject = name, DisplayName = name, Enabled = true });
        await db.SaveChangesAsync();
        var newOperator = Guid.NewGuid();

        Assert.NotEqual(0, await RunProvisioning(command, environment.Id, newOperator, name));

        db.ChangeTracker.Clear();
        Assert.Equal(7, (await db.Environments.SingleAsync(x => x.Id == environment.Id)).Version);
        Assert.False(await db.Principals.AnyAsync(x => x.OperatorId == newOperator));
        Assert.False(await db.Memberships.AnyAsync(x => x.EnvironmentId == environment.Id));
        Assert.False(await db.Assignments.AnyAsync(x => x.EnvironmentId == environment.Id));
    }

    private static async Task<ManagedEnvironment> SeedEnvironment(ConsoleDbContext db)
    {
        var environment = new ManagedEnvironment { Id = Guid.NewGuid(), Name = "Synthetic provisioning",
            CanonicalDns = $"provision-{Guid.NewGuid():N}.test", DefaultLocale = "zh-TW", Version = 7 };
        db.Environments.Add(environment);
        db.Scopes.Add(new Scope { EnvironmentId = environment.Id, Id = Guid.NewGuid(), Kind = ScopeKind.All });
        db.Roles.Add(new Role { EnvironmentId = environment.Id, Id = Guid.NewGuid(), Name = "Owner", BuiltInKind = "Owner" });
        await db.SaveChangesAsync();
        return environment;
    }

    private static ConsoleDbContext Db() => new(new DbContextOptionsBuilder<ConsoleDbContext>()
        .UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")
            ?? throw new InvalidOperationException("Synthetic test database required.")).Options);

    private static async Task<int> RunProvisioning(string command, Guid environmentId, Guid operatorId, string name)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        var configuration = directory.Parent!.Name;
        while (!File.Exists(Path.Combine(directory.FullName, "ITManagement.slnx")))
            directory = directory.Parent ?? throw new InvalidOperationException("Repository root unavailable.");
        var assembly = Path.Combine(directory.FullName, "src", "Server", "Provisioning", "bin", configuration, "net10.0", "Provisioning.dll");
        Assert.True(File.Exists(assembly), "Provisioning project must be built before its integration tests.");
        var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ??
            Path.Combine(Environment.GetEnvironmentVariable("DOTNET_ROOT") ?? "", OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet");
        var start = new ProcessStartInfo(host) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in new[] { assembly, command, environmentId.ToString(), operatorId.ToString(), name })
            start.ArgumentList.Add(argument);
        start.Environment["CONSOLE_PROVISIONING_ALLOWED"] = "true";
        start.Environment["ConnectionStrings__Console"] = Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!;
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Provisioning process unavailable.");
        // Drain generated enrollment tokens and diagnostics without retaining or publishing them.
        var output = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
        var error = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
        if (command == "bootstrap-owner")
            await process.StandardInput.WriteLineAsync(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        process.StandardInput.Close();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await process.WaitForExitAsync(timeout.Token); }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await Task.WhenAll(output, error);
        }
        return process.ExitCode;
    }
}
