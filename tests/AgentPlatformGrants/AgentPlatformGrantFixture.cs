using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Npgsql;

namespace ItManagement.AgentPlatformGrants.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class PlatformGrantCollection : ICollectionFixture<AgentPlatformGrantFixture>
{
    public const string Name = "Agent platform grant database";
}

public sealed partial class AgentPlatformGrantFixture : IAsyncLifetime
{
    private const long LockKey = 7912040301;
    private readonly string _connectionString = Environment.GetEnvironmentVariable("AGENT_PLATFORM_GRANT_TEST_DB") ??
        Environment.GetEnvironmentVariable("CONSOLE_TEST_DB") ?? throw new InvalidOperationException("AGENT_PLATFORM_GRANT_TEST_DB or CONSOLE_TEST_DB is required.");
    private readonly string _suffix = Guid.NewGuid().ToString("N")[..12];
    private NpgsqlConnection? _lease;
    private bool _rolesCreated;
    private bool _disposed;
    private readonly List<(string Role, NpgsqlDataSource DataSource)> _additionalPlatformRoles = [];
    private string _ingestPassword = null!, _enrollPassword = null!, _issuePassword = null!, _projectionPassword = null!, _platformPassword = null!, _revokerPassword = null!;

    public string TableOwnerRole => $"agp_tbl_{_suffix}";
    public string IngestRole => $"agp_ing_{_suffix}";
    public string EnrollmentDefinerRole => $"agp_enf_{_suffix}";
    public string EnrollRole => $"agp_enr_{_suffix}";
    public string IssueRole => $"agp_iss_{_suffix}";
    public string ProjectionDefinerRole => $"agp_prf_{_suffix}";
    public string ProjectionRole => $"agp_pro_{_suffix}";
    public string PlatformDefinerRole => $"agp_gdf_{_suffix}";
    public string PlatformRole => $"agp_grt_{_suffix}";
    public string RevokerRole => $"agp_rev_{_suffix}";
    public Guid EnvironmentId { get; } = Guid.NewGuid();
    public NpgsqlDataSource Owner { get; private set; } = null!;
    public NpgsqlDataSource Platform { get; private set; } = null!;
    public NpgsqlDataSource Revoker { get; private set; } = null!;
    public NpgsqlDataSource Ingest { get; private set; } = null!;
    public NpgsqlDataSource Enroll { get; private set; } = null!;
    public NpgsqlDataSource Issue { get; private set; } = null!;
    public NpgsqlDataSource Projection { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        var builder = new NpgsqlConnectionStringBuilder(_connectionString);
        Validate(builder);
        try
        {
            Owner = NpgsqlDataSource.Create(builder.ConnectionString);
            _lease = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(builder.ConnectionString) { Pooling = false }.ConnectionString);
            await _lease.OpenAsync();
            await using (var command = new NpgsqlCommand("SELECT pg_catalog.pg_advisory_lock(@key)", _lease) { CommandTimeout = 120 })
            {
                command.Parameters.AddWithValue("key", LockKey);
                await command.ExecuteNonQueryAsync();
            }
            if (await Scalar<long>("SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname='agent_private'") != 0)
                throw new InvalidOperationException("agent_private already exists; refusing to overwrite state.");
            _ingestPassword = Secret(); _enrollPassword = Secret(); _issuePassword = Secret(); _projectionPassword = Secret(); _platformPassword = Secret(); _revokerPassword = Secret();
            await Execute($"""
                BEGIN;
                CREATE ROLE {Id(TableOwnerRole)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
                CREATE ROLE {Id(IngestRole)} LOGIN PASSWORD {Lit(_ingestPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
                CREATE ROLE {Id(EnrollmentDefinerRole)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
                CREATE ROLE {Id(EnrollRole)} LOGIN PASSWORD {Lit(_enrollPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
                CREATE ROLE {Id(IssueRole)} LOGIN PASSWORD {Lit(_issuePassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
                CREATE ROLE {Id(ProjectionDefinerRole)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
                CREATE ROLE {Id(ProjectionRole)} LOGIN PASSWORD {Lit(_projectionPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
                CREATE ROLE {Id(PlatformDefinerRole)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
                CREATE ROLE {Id(PlatformRole)} LOGIN PASSWORD {Lit(_platformPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
                CREATE ROLE {Id(RevokerRole)} LOGIN PASSWORD {Lit(_revokerPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
                COMMIT;
                """);
            _rolesCreated = true;
            var database = builder.Database!;
            await Script("agent-store.sql", new() { [":\"agent_definer_role\""] = Id(TableOwnerRole) });
            await Script("provision-agent-store.sql", new() { [":\"agent_definer_role\""] = Id(TableOwnerRole), [":\"agent_ingest_role\""] = Id(IngestRole), [":'agent_definer_role'"] = Lit(TableOwnerRole), [":'agent_ingest_role'"] = Lit(IngestRole), [":'environment_id'"] = Lit(EnvironmentId.ToString()), [":DBNAME"] = Id(database) });
            await Script("agent-enrollment-store.sql", new() { [":\"agent_table_owner_role\""] = Id(TableOwnerRole), [":\"agent_enrollment_definer_role\""] = Id(EnrollmentDefinerRole), [":'agent_table_owner_role'"] = Lit(TableOwnerRole), [":'agent_enrollment_definer_role'"] = Lit(EnrollmentDefinerRole) });
            await Script("provision-agent-enrollment.sql", new() { [":\"agent_table_owner_role\""] = Id(TableOwnerRole), [":\"agent_enrollment_definer_role\""] = Id(EnrollmentDefinerRole), [":\"agent_enroll_role\""] = Id(EnrollRole), [":\"agent_issue_role\""] = Id(IssueRole), [":'agent_table_owner_role'"] = Lit(TableOwnerRole), [":'agent_enrollment_definer_role'"] = Lit(EnrollmentDefinerRole), [":'agent_enroll_role'"] = Lit(EnrollRole), [":'agent_issue_role'"] = Lit(IssueRole), [":'environment_id'"] = Lit(EnvironmentId.ToString()), [":DBNAME"] = Id(database) });
            await Script("agent-projection-store.sql", ProjectionStore());
            await Script("provision-agent-projection.sql", ProjectionProvision(database));
            await AssertStorePreflightRejected();
            Assert.Equal(0, await Scalar<long>("SELECT count(*) FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relname IN('platform_grant_database_bindings','platform_grant_receipts')"));
            await Script("upgrade-agent-platform-grant-isolation-v1.sql", IsolationUpgrade());
            var legacyIsolationFingerprint = await LegacyIsolationFingerprint();
            Assert.Equal(0, await Scalar<long>("SELECT count(*) FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure('agent_private.agent_capability_isolation_profile()')"));
            await Script("upgrade-agent-platform-grant-isolation-v1.sql", IsolationUpgrade());
            Assert.Equal(legacyIsolationFingerprint, await LegacyIsolationFingerprint());
            await Execute($"ALTER ROLE {Id(ProjectionDefinerRole)} INHERIT");
            try
            {
                Assert.Equal(0, await Scalar<long>("SELECT count(*) FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure('agent_private.agent_capability_isolation_profile()')"));
                await AssertScriptRejected(() => Script("upgrade-agent-platform-grant-isolation-v1.sql", IsolationUpgrade()));
                Assert.Equal(legacyIsolationFingerprint, await LegacyIsolationFingerprint());
            }
            finally { await Execute($"ALTER ROLE {Id(ProjectionDefinerRole)} NOINHERIT"); }
            await Execute($"GRANT EXECUTE ON FUNCTION agent_private.platform_grant_role_is_unbound(name) TO {Id(PlatformRole)}");
            var helperDriftFingerprint = await LegacyIsolationFingerprint();
            try
            {
                Assert.Equal(0, await Scalar<long>("SELECT count(*) FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure('agent_private.agent_capability_isolation_profile()')"));
                await AssertScriptRejected(() => Script("upgrade-agent-platform-grant-isolation-v1.sql", IsolationUpgrade()));
                Assert.Equal(helperDriftFingerprint, await LegacyIsolationFingerprint());
            }
            finally { await Execute($"REVOKE EXECUTE ON FUNCTION agent_private.platform_grant_role_is_unbound(name) FROM {Id(PlatformRole)}"); }
            await Script("downgrade-v2-to-v1.sql", ProjectionDowngrade());
            Assert.Equal(0, await Scalar<long>("SELECT count(*) FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure('agent_private.platform_grant_isolation_profile()')"));
            await AssertStorePreflightRejected();
            Assert.Equal(0, await Scalar<long>("SELECT count(*) FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relname IN('platform_grant_database_bindings','platform_grant_receipts')"));
            await Script("upgrade-v1-to-v2.sql", ProjectionProvision(database));
            await Script("upgrade-agent-platform-grant-isolation-v1.sql", IsolationUpgrade());
            await Script("v1-agent-platform-grants-store.sql", PlatformStore());
            await Script("v1-provision-agent-platform-grants.sql", LegacyPlatformProvision(database));
            await Script("upgrade-agent-capability-isolation-v2.sql", CapabilityUpgrade());
            await Script("upgrade-agent-platform-grants-v1-to-v2.sql", PlatformStore());
            await Script("provision-agent-platform-grants.sql", PlatformProvision(database));
            Platform = DataSource(builder, PlatformRole, _platformPassword);
            Revoker = DataSource(builder, RevokerRole, _revokerPassword);
            Ingest = DataSource(builder, IngestRole, _ingestPassword);
            Enroll = DataSource(builder, EnrollRole, _enrollPassword);
            Issue = DataSource(builder, IssueRole, _issuePassword);
            Projection = DataSource(builder, ProjectionRole, _projectionPassword);
        }
        catch { await DisposeAsync(); throw; }
    }

    public Task<TestMapping> SeedMapping(string deviceState = "Active") => SeedMapping(EnvironmentId, deviceState);

    public async Task<TestMapping> SeedMapping(Guid environmentId, string deviceState = "Active")
    {
        var value = new TestMapping(environmentId, Guid.NewGuid(), Guid.NewGuid(), default);
        await Execute("INSERT INTO agent_private.devices(environment_id,device_id,state) VALUES(@env,@device,@state); INSERT INTO agent_private.agent_device_directory_bindings(environment_id,directory_object_id,device_id,creation_source) VALUES(@env,@directory,@device,'OwnerProvisioning')",
            P("env", value.EnvironmentId), P("device", value.DeviceId), P("state", deviceState), P("directory", value.DirectoryObjectId));
        var createdUtc = await Scalar<DateTime>("SELECT created_at FROM agent_private.agent_device_directory_bindings WHERE environment_id=@env AND directory_object_id=@directory", P("env", value.EnvironmentId), P("directory", value.DirectoryObjectId));
        var created = new DateTimeOffset(DateTime.SpecifyKind(createdUtc, DateTimeKind.Utc));
        return value with { MappingCreatedAt = created };
    }

    public async Task Reset()
    {
        await RemoveAdditionalPlatformRoles();
        await Execute("DELETE FROM agent_private.platform_grant_revocation_receipts; DELETE FROM agent_private.platform_grant_receipts; DELETE FROM agent_private.enrollment_results; DELETE FROM agent_private.enrollment_requests; DELETE FROM agent_private.enrollment_grants; DELETE FROM agent_private.certificate_bindings; DELETE FROM agent_private.registrations; DELETE FROM agent_private.agent_device_directory_bindings; DELETE FROM agent_private.devices;");
    }

    public async Task<AdditionalPlatformEnvironment> AddPlatformEnvironment()
    {
        var additional = await CreateUnprovisionedPlatformEnvironment();
        await ProvisionPlatformEnvironment(additional);
        return additional;
    }

    internal async Task<AdditionalPlatformEnvironment> CreateUnprovisionedPlatformEnvironment()
    {
        var environmentId = Guid.NewGuid();
        var role = $"agp_alt_{Guid.NewGuid():N}"[..20];
        var revokerRole = $"agp_arv_{Guid.NewGuid():N}"[..20];
        var password = Secret(); var revokerPassword = Secret();
        await Execute($"CREATE ROLE {Id(role)} LOGIN PASSWORD {Lit(password)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION; CREATE ROLE {Id(revokerRole)} LOGIN PASSWORD {Lit(revokerPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;");
        var dataSource = DataSource(new NpgsqlConnectionStringBuilder(_connectionString), role, password);
        var revokerDataSource = DataSource(new NpgsqlConnectionStringBuilder(_connectionString), revokerRole, revokerPassword);
        _additionalPlatformRoles.Add((role, dataSource));
        _additionalPlatformRoles.Add((revokerRole, revokerDataSource));
        return new(environmentId, role, dataSource, revokerRole, revokerDataSource);
    }

    internal async Task ProvisionPlatformEnvironment(AdditionalPlatformEnvironment additional)
    {
        var database = new NpgsqlConnectionStringBuilder(_connectionString).Database!;
        var replacements = PlatformProvision(database);
        replacements[":\"agent_platform_grant_role\""] = Id(additional.Role);
        replacements[":'agent_platform_grant_role'"] = Lit(additional.Role);
        replacements[":\"agent_platform_grant_revoker_role\""] = Id(additional.RevokerRole);
        replacements[":'agent_platform_grant_revoker_role'"] = Lit(additional.RevokerRole);
        replacements[":'environment_id'"] = Lit(additional.EnvironmentId.ToString());
        await Script("provision-agent-platform-grants.sql", replacements);
    }

    public async Task Execute(string sql, params NpgsqlParameter[] parameters) { await using var command = Owner.CreateCommand(sql); command.Parameters.AddRange(parameters); await command.ExecuteNonQueryAsync(); }
    public async Task<T> Scalar<T>(string sql, params NpgsqlParameter[] parameters) { await using var command = Owner.CreateCommand(sql); command.Parameters.AddRange(parameters); return (T)(await command.ExecuteScalarAsync())!; }
    public Task DisposeAsync() => Cleanup();

    private async Task RemoveAdditionalPlatformRoles()
    {
        if (_additionalPlatformRoles.Count == 0) return;
        foreach (var additional in _additionalPlatformRoles) await additional.DataSource.DisposeAsync();
        var database = new NpgsqlConnectionStringBuilder(_connectionString).Database!;
        foreach (var additional in _additionalPlatformRoles)
        {
            await Execute($"DELETE FROM agent_private.platform_grant_database_bindings WHERE login_role={Lit(additional.Role)}::name; DELETE FROM agent_private.agent_capability_roles WHERE role_name={Lit(additional.Role)}::name; DROP OWNED BY {Id(additional.Role)}; REVOKE CONNECT ON DATABASE {Id(database)} FROM {Id(additional.Role)}; DROP ROLE {Id(additional.Role)};");
        }
        _additionalPlatformRoles.Clear();
    }

    private async Task Cleanup()
    {
        if (_disposed) return; _disposed = true;
        try
        {
            foreach (var additional in _additionalPlatformRoles) await additional.DataSource.DisposeAsync();
            try { if (Revoker is not null) await Revoker.DisposeAsync(); }
            finally { try { if (Platform is not null) await Platform.DisposeAsync(); }
            finally { try { if (Projection is not null) await Projection.DisposeAsync(); } finally { try { if (Issue is not null) await Issue.DisposeAsync(); } finally { try { if (Enroll is not null) await Enroll.DisposeAsync(); } finally { if (Ingest is not null) await Ingest.DisposeAsync(); } } } }
            }
            if (Owner is not null && _rolesCreated)
            {
                if (await Scalar<long>("SELECT count(*) FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE nspname='agent_private' AND rolname=@owner", P("owner", TableOwnerRole)) == 1) await Execute("DROP SCHEMA agent_private CASCADE");
                var database = new NpgsqlConnectionStringBuilder(_connectionString).Database!;
                var additional = string.Concat(_additionalPlatformRoles.Select(value => $"REVOKE CONNECT ON DATABASE {Id(database)} FROM {Id(value.Role)}; DROP ROLE IF EXISTS {Id(value.Role)};"));
                await Execute($"{additional} REVOKE CONNECT ON DATABASE {Id(database)} FROM {Id(IngestRole)},{Id(EnrollRole)},{Id(IssueRole)},{Id(ProjectionRole)},{Id(PlatformRole)},{Id(RevokerRole)}; DROP ROLE IF EXISTS {Id(RevokerRole)},{Id(PlatformRole)},{Id(PlatformDefinerRole)},{Id(ProjectionRole)},{Id(ProjectionDefinerRole)},{Id(IssueRole)},{Id(EnrollRole)},{Id(EnrollmentDefinerRole)},{Id(IngestRole)},{Id(TableOwnerRole)};");
            }
        }
        finally { try { if (_lease is not null) await _lease.DisposeAsync(); } finally { if (Owner is not null) await Owner.DisposeAsync(); } }
    }

    internal Dictionary<string, string> ProjectionStore() => new() { [":\"agent_table_owner_role\""] = Id(TableOwnerRole), [":\"agent_projection_definer_role\""] = Id(ProjectionDefinerRole), [":'agent_table_owner_role'"] = Lit(TableOwnerRole), [":'agent_projection_definer_role'"] = Lit(ProjectionDefinerRole) };
    internal Dictionary<string, string> ProjectionProvision(string database) => new(ProjectionStore()) { [":\"agent_projection_role\""] = Id(ProjectionRole), [":'agent_projection_role'"] = Lit(ProjectionRole), [":'environment_id'"] = Lit(EnvironmentId.ToString()), [":DBNAME"] = Id(database) };
    internal Dictionary<string, string> PlatformStore() => new() { [":\"agent_table_owner_role\""] = Id(TableOwnerRole), [":\"agent_platform_grant_definer_role\""] = Id(PlatformDefinerRole), [":'agent_table_owner_role'"] = Lit(TableOwnerRole), [":'agent_platform_grant_definer_role'"] = Lit(PlatformDefinerRole), [":\"agent_platform_grant_role\""] = Id(PlatformRole), [":'agent_platform_grant_role'"] = Lit(PlatformRole) };
    internal Dictionary<string, string> LegacyPlatformProvision(string database) => new(PlatformStore()) { [":\"agent_platform_grant_role\""] = Id(PlatformRole), [":'agent_platform_grant_role'"] = Lit(PlatformRole), [":'environment_id'"] = Lit(EnvironmentId.ToString()), [":DBNAME"] = Id(database) };
    internal Dictionary<string, string> PlatformProvision(string database) => new(PlatformStore()) { [":\"agent_platform_grant_role\""] = Id(PlatformRole), [":'agent_platform_grant_role'"] = Lit(PlatformRole), [":\"agent_platform_grant_revoker_role\""] = Id(RevokerRole), [":'agent_platform_grant_revoker_role'"] = Lit(RevokerRole), [":'environment_id'"] = Lit(EnvironmentId.ToString()), [":DBNAME"] = Id(database) };
    internal Dictionary<string, string> PlatformDowngrade() => new(PlatformStore()) { [":\"agent_platform_grant_role\""] = Id(PlatformRole), [":'agent_platform_grant_role'"] = Lit(PlatformRole), [":\"agent_platform_grant_revoker_role\""] = Id(RevokerRole), [":'agent_platform_grant_revoker_role'"] = Lit(RevokerRole), [":'DBNAME'"] = Lit(new NpgsqlConnectionStringBuilder(_connectionString).Database!), [":\"DBNAME\""] = Id(new NpgsqlConnectionStringBuilder(_connectionString).Database!) };
    internal Dictionary<string, string> IsolationUpgrade() => new()
    {
        [":\"agent_table_owner_role\""] = Id(TableOwnerRole),
        [":\"agent_enrollment_definer_role\""] = Id(EnrollmentDefinerRole),
        [":\"agent_projection_definer_role\""] = Id(ProjectionDefinerRole),
        [":'agent_table_owner_role'"] = Lit(TableOwnerRole),
        [":'agent_enrollment_definer_role'"] = Lit(EnrollmentDefinerRole),
        [":'agent_projection_definer_role'"] = Lit(ProjectionDefinerRole)
    };
    internal Dictionary<string, string> CapabilityUpgrade() => new()
    {
        [":\"agent_table_owner_role\""] = Id(TableOwnerRole), [":\"agent_definer_role\""] = Id(TableOwnerRole),
        [":\"agent_enrollment_definer_role\""] = Id(EnrollmentDefinerRole), [":\"agent_projection_definer_role\""] = Id(ProjectionDefinerRole),
        [":\"agent_platform_grant_definer_role\""] = Id(PlatformDefinerRole), [":'agent_table_owner_role'"] = Lit(TableOwnerRole),
        [":'agent_platform_grant_definer_role'"] = Lit(PlatformDefinerRole)
    };
    internal Dictionary<string, string> ProjectionDowngrade() => new(ProjectionProvision(new NpgsqlConnectionStringBuilder(_connectionString).Database!));
    internal Task RunOldProvisionWithPlatformDefinerAlias(string capability)
    {
        var database = new NpgsqlConnectionStringBuilder(_connectionString).Database!;
        var projection = ProjectionProvision(database);
        projection[":\"agent_projection_role\""] = Id(PlatformDefinerRole);
        projection[":'agent_projection_role'"] = Lit(PlatformDefinerRole);
        projection[":'environment_id'"] = Lit(Guid.NewGuid().ToString());
        return capability switch
        {
            "ingest" => Script("provision-agent-store.sql", new()
            {
                [":\"agent_definer_role\""] = Id(TableOwnerRole), [":\"agent_ingest_role\""] = Id(PlatformDefinerRole),
                [":'agent_definer_role'"] = Lit(TableOwnerRole), [":'agent_ingest_role'"] = Lit(PlatformDefinerRole),
                [":'environment_id'"] = Lit(Guid.NewGuid().ToString()), [":DBNAME"] = Id(database)
            }),
            "enrollment" => Script("provision-agent-enrollment.sql", new()
            {
                [":\"agent_table_owner_role\""] = Id(TableOwnerRole), [":\"agent_enrollment_definer_role\""] = Id(EnrollmentDefinerRole),
                [":\"agent_enroll_role\""] = Id(PlatformDefinerRole), [":\"agent_issue_role\""] = Id(IssueRole),
                [":'agent_table_owner_role'"] = Lit(TableOwnerRole), [":'agent_enrollment_definer_role'"] = Lit(EnrollmentDefinerRole),
                [":'agent_enroll_role'"] = Lit(PlatformDefinerRole), [":'agent_issue_role'"] = Lit(IssueRole),
                [":'environment_id'"] = Lit(Guid.NewGuid().ToString()), [":DBNAME"] = Id(database)
            }),
            "projection" => Script("provision-agent-projection.sql", projection),
            _ => throw new ArgumentOutOfRangeException(nameof(capability))
        };
    }
    private async Task AssertStorePreflightRejected()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Script("agent-platform-grants-store.sql", PlatformStore()));
        Assert.Equal(PostgresErrorCodes.DivisionByZero, Assert.IsType<PostgresException>(error.InnerException).SqlState);
    }
    private async Task AssertScriptRejected(Func<Task> action)
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(action);
        while (error is not PostgresException && error.InnerException is not null) error = error.InnerException;
        Assert.Equal(PostgresErrorCodes.DivisionByZero, Assert.IsType<PostgresException>(error).SqlState);
    }
    private Task<string> LegacyIsolationFingerprint() => Scalar<string>("""
        SELECT pg_catalog.md5(pg_catalog.string_agg(pg_catalog.pg_get_functiondef(function.oid)||function.proowner::text||COALESCE(function.proacl::text,''), E'\n' ORDER BY function.oid))
        FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function.pronamespace
        WHERE namespace.nspname='agent_private'
        """);
    internal async Task Script(string file, Dictionary<string, string> replacements)
    {
        await Script(file, replacements, static sql => sql);
    }

    internal async Task Script(string file, Dictionary<string, string> replacements, Func<string, string> transform)
    {
        var sql = transform(await Render(file, replacements));
        try { await Execute(sql); }
        catch (PostgresException error)
        {
            var line = error.Position > 0
                ? sql[..Math.Min(error.Position, sql.Length)].Count(character => character == '\n') + 1
                : 0;
            throw new InvalidOperationException(line > 0
                ? $"{file} failed near line {line}; internal position {error.InternalPosition}; where {error.Where}."
                : $"{file} failed with database error {error.SqlState}.", error);
        }
    }
    private static async Task<string> Render(string file, Dictionary<string, string> replacements) { var lines = await File.ReadAllLinesAsync(Path.Combine(AppContext.BaseDirectory, file)); var sql = string.Join('\n', lines.Where(line => !line.StartsWith('\\'))); foreach (var replacement in replacements.OrderByDescending(value => value.Key.Length)) sql = sql.Replace(replacement.Key, replacement.Value, StringComparison.Ordinal); return sql; }
    private static NpgsqlDataSource DataSource(NpgsqlConnectionStringBuilder source, string role, string password) => NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(source.ConnectionString) { Username = role, Password = password, Pooling = false }.ConnectionString);
    private static NpgsqlParameter P(string name, object value) => new(name, value);
    private static string Secret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    private static string Lit(string value) => $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";
    private static string Id(string value) { if (!Safe().IsMatch(value)) throw new ArgumentException("Unsafe identifier"); return $"\"{value}\""; }
    private static void Validate(NpgsqlConnectionStringBuilder value) { if (value.Host is not ("127.0.0.1" or "localhost" or "::1") || value.Database is not ("console_test" or "console_ci")) throw new InvalidOperationException("Platform grant tests require loopback console_test or console_ci."); }
    [GeneratedRegex("^[a-z][a-z0-9_]{0,62}$")] private static partial Regex Safe();
}

public sealed record TestMapping(Guid EnvironmentId, Guid DirectoryObjectId, Guid DeviceId, DateTimeOffset MappingCreatedAt);
public sealed record AdditionalPlatformEnvironment(Guid EnvironmentId, string Role, NpgsqlDataSource DataSource,
    string RevokerRole, NpgsqlDataSource RevokerDataSource);
