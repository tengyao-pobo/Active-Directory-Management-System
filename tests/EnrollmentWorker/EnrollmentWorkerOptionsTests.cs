using Npgsql;
using Xunit;

namespace ItManagement.EnrollmentWorker.Tests;

public sealed class EnrollmentWorkerOptionsTests
{
    [Fact]
    public void ValidConfigurationProducesClosedFixedConnectionSettings()
    {
        var options = ValidOptions();

        var snapshot = options.ValidateAndSnapshot();
        var environment = Assert.Single(snapshot.Environments);
        var publicConnection = new NpgsqlConnectionStringBuilder(environment.PublicDatabase.BuildConnectionString());
        var privateConnection = new NpgsqlConnectionStringBuilder(environment.PrivateDatabase.BuildConnectionString());

        Assert.Equal(4, snapshot.Concurrency);
        Assert.Equal(options.Environments[0].EnvironmentId, environment.EnvironmentId);
        Assert.Equal("public_owner", environment.PublicDatabase.ExpectedTableOwner);
        Assert.Equal("execution_owner", environment.PublicDatabase.ExpectedExecutionOwner);
        Assert.Equal("queue_owner", environment.PublicDatabase.ExpectedQueueOwner);
        Assert.Equal("private_owner", environment.PrivateDatabase.ExpectedTableOwner);
        Assert.Equal("function_owner", environment.PrivateDatabase.ExpectedFunctionOwner);
        AssertFixed(publicConnection, "public0.db.example.test", "public_runtime0", "public-secret");
        AssertFixed(privateConnection, "private0.db.example.test", "private_runtime0", "private-secret");
    }

    [Fact]
    public void SnapshotIsDefensiveAndDoesNotExposePasswordsThroughToString()
    {
        var options = ValidOptions();
        var originalEnvironment = options.Environments[0];
        var snapshot = options.ValidateAndSnapshot();

        options.Concurrency = 8;
        options.Environments.Clear();
        originalEnvironment.EnvironmentId = Guid.NewGuid();
        originalEnvironment.PublicDatabase!.Password = "changed-public-secret";
        originalEnvironment.PrivateDatabase!.Password = "changed-private-secret";

        Assert.Equal(4, snapshot.Concurrency);
        var environment = Assert.Single(snapshot.Environments);
        Assert.Equal("public-secret", new NpgsqlConnectionStringBuilder(
            environment.PublicDatabase.BuildConnectionString()).Password);
        Assert.Equal("private-secret", new NpgsqlConnectionStringBuilder(
            environment.PrivateDatabase.BuildConnectionString()).Password);
        foreach (var text in new object[]
        {
            options, originalEnvironment, originalEnvironment.PublicDatabase,
            originalEnvironment.PrivateDatabase, snapshot, environment,
            environment.PublicDatabase, environment.PrivateDatabase
        }.Select(value => value.ToString()!))
        {
            Assert.DoesNotContain("secret", text, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void RejectsInvalidEnvironmentCollectionsAndConcurrency()
    {
        AssertInvalid(new EnrollmentWorkerOptions());
        AssertInvalid(ValidOptions(value => value.Concurrency = 0));
        AssertInvalid(ValidOptions(value => value.Concurrency = 9));
        AssertInvalid(ValidOptions(value => value.Environments[0].EnvironmentId = Guid.Empty));
        AssertInvalid(ValidOptions(value => value.Environments.Add(value.Environments[0])));
        AssertInvalid(ValidOptions(value => value.Environments[0].PublicDatabase = null));
        AssertInvalid(ValidOptions(value => value.Environments[0].PrivateDatabase = null));

        var tooMany = ValidOptions();
        tooMany.Environments = Enumerable.Range(0, 33)
            .Select(index => Environment(index, Guid.NewGuid()))
            .ToList();
        AssertInvalid(tooMany);
    }

    [Theory]
    [InlineData("")]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("DB.example.test")]
    [InlineData("db.example.test.")]
    [InlineData("db..example.test")]
    [InlineData("-db.example.test")]
    [InlineData("db_.example.test")]
    [InlineData("資料庫.example.test")]
    public void RejectsNonCanonicalHosts(string host) =>
        AssertInvalid(ValidOptions(value => value.Environments[0].PublicDatabase!.Host = host));

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public void RejectsInvalidPorts(int port) =>
        AssertInvalid(ValidOptions(value => value.Environments[0].PublicDatabase!.Port = port));

    [Theory]
    [InlineData("")]
    [InlineData("1database")]
    [InlineData("database-name")]
    [InlineData("資料庫")]
    public void RejectsInvalidDatabaseIdentifiers(string database) =>
        AssertInvalid(ValidOptions(value => value.Environments[0].PublicDatabase!.Database = database));

    [Theory]
    [InlineData("")]
    [InlineData("Runtime")]
    [InlineData("1runtime")]
    [InlineData("runtime-name")]
    [InlineData("rüntime")]
    public void RejectsInvalidLowerIdentifiers(string identifier)
    {
        AssertInvalid(ValidOptions(value => value.Environments[0].PublicDatabase!.Username = identifier));
        AssertInvalid(ValidOptions(value => value.Environments[0].PublicDatabase!.ExpectedQueueOwner = identifier));
    }

    [Fact]
    public void RejectsInvalidPasswordsAndCertificatePaths()
    {
        AssertInvalid(ValidOptions(value => value.Environments[0].PublicDatabase!.Password = " \t "));
        AssertInvalid(ValidOptions(value => value.Environments[0].PublicDatabase!.Password = new string('p', 4097)));
        AssertInvalid(ValidOptions(value => value.Environments[0].PublicDatabase!.RootCertificate = "relative.pem"));
    }

    [Fact]
    public void RejectsPasswordReuseAcrossPurposesAndEnvironments()
    {
        AssertInvalid(ValidOptions(value => value.Environments[0].PrivateDatabase!.Password = "public-secret"));

        var options = ValidOptions();
        var second = Environment(1, Guid.NewGuid());
        second.PrivateDatabase!.Password = "public-secret";
        options.Environments.Add(second);
        AssertInvalid(options);
    }

    [Fact]
    public void RejectsNetworkAndDeviceCertificatePaths()
    {
        var invalidPaths = OperatingSystem.IsWindows()
            ? new[] { @"\\server\share\root.pem", @"\\?\C:\certs\root.pem", @"\\.\C:\certs\root.pem", "//server/share/root.pem" }
            : new[] { "//server/share/root.pem" };

        foreach (var path in invalidPaths)
            AssertInvalid(ValidOptions(value => value.Environments[0].PublicDatabase!.RootCertificate = path));
    }

    [Fact]
    public void RejectsLoginReuseAcrossEnvironmentsAndPurposes()
    {
        AssertInvalid(ValidOptions(value => value.Environments[0].PrivateDatabase!.Username = "public_runtime0"));

        var options = ValidOptions();
        var second = Environment(1, Guid.NewGuid());
        second.PublicDatabase!.Username = "public_runtime0";
        options.Environments.Add(second);
        AssertInvalid(options);
    }

    [Fact]
    public void RejectsAnyLoginThatMatchesAnyConfiguredOwner()
    {
        AssertInvalid(ValidOptions(value =>
            value.Environments[0].PrivateDatabase!.ExpectedFunctionOwner = "public_runtime0"));

        var options = ValidOptions();
        var second = Environment(1, Guid.NewGuid());
        second.PrivateDatabase!.ExpectedTableOwner = "public_runtime0";
        options.Environments.Add(second);
        AssertInvalid(options);
    }

    [Fact]
    public void RejectsPublicPrivateDatabaseOverlapAcrossTheConfiguration()
    {
        AssertInvalid(ValidOptions(value =>
        {
            var source = value.Environments[0].PublicDatabase!;
            var target = value.Environments[0].PrivateDatabase!;
            target.Host = source.Host;
            target.Port = source.Port;
            target.Database = source.Database;
        }));

        var options = ValidOptions();
        var second = Environment(1, Guid.NewGuid());
        var publicDatabase = options.Environments[0].PublicDatabase!;
        second.PrivateDatabase!.Host = publicDatabase.Host;
        second.PrivateDatabase.Port = publicDatabase.Port;
        second.PrivateDatabase.Database = publicDatabase.Database;
        options.Environments.Add(second);
        AssertInvalid(options);
    }

    private static EnrollmentWorkerOptions ValidOptions(Action<EnrollmentWorkerOptions>? change = null)
    {
        var value = new EnrollmentWorkerOptions { Environments = [Environment(0, Guid.NewGuid())] };
        change?.Invoke(value);
        return value;
    }

    private static EnrollmentWorkerEnvironmentOptions Environment(int suffix, Guid environmentId)
    {
        var certificate = Path.GetFullPath($"root-{suffix}.pem");
        return new EnrollmentWorkerEnvironmentOptions
        {
            EnvironmentId = environmentId,
            PublicDatabase = new EnrollmentWorkerPublicDatabaseOptions
            {
                Host = $"public{suffix}.db.example.test",
                Database = $"PublicDb{suffix}",
                Username = $"public_runtime{suffix}",
                Password = suffix == 0 ? "public-secret" : $"public-secret-{suffix}",
                RootCertificate = certificate,
                ExpectedTableOwner = "public_owner",
                ExpectedExecutionOwner = "execution_owner",
                ExpectedQueueOwner = "queue_owner"
            },
            PrivateDatabase = new EnrollmentWorkerPrivateDatabaseOptions
            {
                Host = $"private{suffix}.db.example.test",
                Database = $"PrivateDb{suffix}",
                Username = $"private_runtime{suffix}",
                Password = suffix == 0 ? "private-secret" : $"private-secret-{suffix}",
                RootCertificate = certificate,
                ExpectedTableOwner = "private_owner",
                ExpectedFunctionOwner = "function_owner"
            }
        };
    }

    private static void AssertFixed(
        NpgsqlConnectionStringBuilder value,
        string expectedHost,
        string expectedUsername,
        string expectedPassword)
    {
        Assert.Equal(expectedHost, value.Host);
        Assert.Equal(5432, value.Port);
        Assert.Equal(expectedUsername, value.Username);
        Assert.Equal(expectedPassword, value.Password);
        Assert.Equal(SslMode.VerifyFull, value.SslMode);
        Assert.True(value.CheckCertificateRevocation);
        Assert.Equal(GssEncryptionMode.Disable, value.GssEncryptionMode);
        Assert.Equal("pg_catalog,pg_temp", value.SearchPath);
        Assert.Equal("UTC", value.Timezone);
        Assert.True(value.Pooling);
        Assert.Equal(0, value.MinPoolSize);
        Assert.Equal(1, value.MaxPoolSize);
        Assert.Equal(10, value.Timeout);
        Assert.Equal(30, value.CommandTimeout);
        Assert.Equal(2_000, value.CancellationTimeout);
        Assert.False(value.Enlist);
        Assert.False(value.Multiplexing);
        Assert.False(value.NoResetOnClose);
        Assert.False(value.IncludeErrorDetail);
        Assert.False(value.LogParameters);
        Assert.NotNull(value.RootCertificate);
        Assert.True(Path.IsPathFullyQualified(value.RootCertificate));
    }

    private static void AssertInvalid(EnrollmentWorkerOptions options)
    {
        var exception = Assert.Throws<InvalidOperationException>(() => options.ValidateAndSnapshot());
        Assert.Equal("EnrollmentWorkerConfigurationInvalid", exception.Message);
    }
}
