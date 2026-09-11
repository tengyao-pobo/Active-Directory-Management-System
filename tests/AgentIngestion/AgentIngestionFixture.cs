using System.Security.Cryptography;
using System.Text.RegularExpressions;
using ItManagement.Agent.Spool;
using Npgsql;

namespace ItManagement.AgentIngestion.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class AgentIngestionCollection : ICollectionFixture<AgentIngestionFixture>
{
    public const string Name = "Agent ingestion database";
}

public sealed partial class AgentIngestionFixture : IAsyncLifetime
{
    private readonly string _ownerConnectionString =
        Environment.GetEnvironmentVariable("AGENT_INGESTION_TEST_DB") ??
        Environment.GetEnvironmentVariable("CONSOLE_TEST_DB") ??
        throw new InvalidOperationException("AGENT_INGESTION_TEST_DB or CONSOLE_TEST_DB is required.");
    private readonly string _suffix = Guid.NewGuid().ToString("N")[..12];
    private string _ingestPassword = null!;
    private string _webPassword = null!;
    private bool _rolesCreated;

    public string DefinerRole => $"ai_def_{_suffix}";

    public string IngestRole => $"ai_ing_{_suffix}";

    public string WebRole => $"ai_web_{_suffix}";

    public Guid EnvironmentId { get; } = Guid.NewGuid();

    public NpgsqlDataSource OwnerDataSource { get; private set; } = null!;

    public NpgsqlDataSource IngestDataSource { get; private set; } = null!;

    public NpgsqlDataSource WebDataSource { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        OwnerDataSource = NpgsqlDataSource.Create(_ownerConnectionString);
        _ingestPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        _webPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        var builder = new NpgsqlConnectionStringBuilder(_ownerConnectionString);
        ValidateTestTarget(builder);
        var database = builder.Database ?? throw new InvalidOperationException("Test database name is required.");
        var existingSchema = await ScalarOwnerAsync<long>(
            "SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname='agent_private'");
        if (existingSchema != 0)
        {
            throw new InvalidOperationException("agent_private already exists; refusing to overwrite existing state.");
        }

        await ExecuteOwnerAsync($"""
            CREATE ROLE {QuoteIdentifier(DefinerRole)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            CREATE ROLE {QuoteIdentifier(IngestRole)} LOGIN PASSWORD {QuoteLiteral(_ingestPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            CREATE ROLE {QuoteIdentifier(WebRole)} LOGIN PASSWORD {QuoteLiteral(_webPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            GRANT CONNECT ON DATABASE {QuoteIdentifier(database)} TO {QuoteIdentifier(WebRole)};
            """);
        _rolesCreated = true;

        await ExecuteScriptAsync("agent-store.sql", new Dictionary<string, string>
        {
            [":\"agent_definer_role\""] = QuoteIdentifier(DefinerRole)
        });
        await ExecuteScriptAsync("provision-agent-store.sql", new Dictionary<string, string>
        {
            [":\"agent_definer_role\""] = QuoteIdentifier(DefinerRole),
            [":\"agent_ingest_role\""] = QuoteIdentifier(IngestRole),
            [":'agent_definer_role'"] = QuoteLiteral(DefinerRole),
            [":'agent_ingest_role'"] = QuoteLiteral(IngestRole),
            [":'environment_id'"] = QuoteLiteral(EnvironmentId.ToString()),
            [":DBNAME"] = QuoteIdentifier(database)
        });

        builder.Username = IngestRole;
        builder.Password = _ingestPassword;
        builder.Pooling = false;
        IngestDataSource = NpgsqlDataSource.Create(builder.ConnectionString);
        builder.Username = WebRole;
        builder.Password = _webPassword;
        WebDataSource = NpgsqlDataSource.Create(builder.ConnectionString);
    }

    public async Task<TestRegistration> SeedAsync(
        string bindingState = "Active",
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        Guid? deviceGuid = null)
    {
        var seed = new TestRegistration(
            EnvironmentId,
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            deviceGuid ?? Guid.NewGuid(),
            1,
            RandomNumberGenerator.GetBytes(32));
        var now = DateTimeOffset.UtcNow;
        await ExecuteOwnerAsync(
            """
            TRUNCATE TABLE agent_private.devices CASCADE;
            UPDATE agent_private.agent_database_bindings
               SET environment_id = @environment_id, purpose = 'Ingest'
             WHERE login_role = @login_role::name;
            INSERT INTO agent_private.devices(environment_id,device_id,state)
            VALUES (@environment_id,@device_id,'Active');
            INSERT INTO agent_private.registrations(
                environment_id,registration_id,device_id,registration_epoch,device_guid,state)
            VALUES (@environment_id,@registration_id,@device_id,@registration_epoch,@device_guid,'Active');
            INSERT INTO agent_private.certificate_bindings(
                environment_id,binding_id,registration_id,leaf_der_sha256,state,not_before,not_after)
            VALUES (@environment_id,@binding_id,@registration_id,@fingerprint,@binding_state,@not_before,@not_after);
            """,
            new NpgsqlParameter("environment_id", seed.EnvironmentId),
            new NpgsqlParameter("login_role", IngestRole),
            new NpgsqlParameter("device_id", seed.DeviceId),
            new NpgsqlParameter("registration_id", seed.RegistrationId),
            new NpgsqlParameter("registration_epoch", seed.RegistrationEpoch),
            new NpgsqlParameter("device_guid", seed.DeviceGuid),
            new NpgsqlParameter("binding_id", seed.BindingId),
            new NpgsqlParameter("fingerprint", seed.Fingerprint),
            new NpgsqlParameter("binding_state", bindingState),
            new NpgsqlParameter("not_before", notBefore ?? now.AddMinutes(-5)),
            new NpgsqlParameter("not_after", notAfter ?? now.AddHours(1)));
        return seed;
    }

    public async Task<byte[]> AddCertificateBindingAsync(TestRegistration seed)
    {
        var fingerprint = RandomNumberGenerator.GetBytes(32);
        await ExecuteOwnerAsync(
            """
            INSERT INTO agent_private.certificate_bindings(
                environment_id,binding_id,registration_id,leaf_der_sha256,state,not_before,not_after)
            VALUES (@environment_id,@binding_id,@registration_id,@fingerprint,'Active',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour')
            """,
            new NpgsqlParameter("environment_id", seed.EnvironmentId),
            new NpgsqlParameter("binding_id", Guid.NewGuid()),
            new NpgsqlParameter("registration_id", seed.RegistrationId),
            new NpgsqlParameter("fingerprint", fingerprint));
        return fingerprint;
    }

    public async Task SeedAcceptedReceiptAsync(TestRegistration seed, SpoolEnvelope envelope, int kind, int schemaVersion)
    {
        await ExecuteOwnerAsync(
            """
            INSERT INTO agent_private.replay_state(environment_id,registration_id,registration_epoch,high_sequence)
            VALUES (@environment_id,@registration_id,@registration_epoch,@sequence);
            INSERT INTO agent_private.receipts(
                environment_id,registration_id,registration_epoch,sequence,receipt_id,device_id,binding_id,
                hash_version,protocol_version,device_guid,request_id,observed_utc_ticks,received_at,
                payload_hash,envelope_hash,kind,schema_version)
            VALUES (@environment_id,@registration_id,@registration_epoch,@sequence,@receipt_id,@device_id,@binding_id,
                2,@protocol_version,@device_guid,@request_id,@observed_utc_ticks,clock_timestamp(),
                @payload_hash,@envelope_hash,@kind,@schema_version)
            """,
            new NpgsqlParameter("environment_id", seed.EnvironmentId),
            new NpgsqlParameter("registration_id", seed.RegistrationId),
            new NpgsqlParameter("registration_epoch", seed.RegistrationEpoch),
            new NpgsqlParameter("sequence", envelope.Sequence),
            new NpgsqlParameter("receipt_id", Guid.NewGuid()),
            new NpgsqlParameter("device_id", seed.DeviceId),
            new NpgsqlParameter("binding_id", seed.BindingId),
            new NpgsqlParameter("protocol_version", envelope.ProtocolVersion),
            new NpgsqlParameter("device_guid", envelope.DeviceGuid),
            new NpgsqlParameter("request_id", envelope.RequestId),
            new NpgsqlParameter("observed_utc_ticks", envelope.ObservedAt.UtcTicks),
            new NpgsqlParameter("payload_hash", envelope.PayloadHash),
            new NpgsqlParameter("envelope_hash", envelope.EnvelopeHash),
            new NpgsqlParameter("kind", kind),
            new NpgsqlParameter("schema_version", schemaVersion));
    }

    public async Task<TestRegistration> AdvanceRegistrationEpochAsync(TestRegistration seed)
    {
        var next = seed with
        {
            RegistrationId = Guid.NewGuid(),
            BindingId = Guid.NewGuid(),
            RegistrationEpoch = seed.RegistrationEpoch + 1,
            Fingerprint = RandomNumberGenerator.GetBytes(32)
        };
        await ExecuteOwnerAsync(
            """
            UPDATE agent_private.registrations SET state='Replaced'
             WHERE environment_id=@environment_id AND registration_id=@old_registration_id;
            UPDATE agent_private.certificate_bindings SET state='Revoked', revoked_at=clock_timestamp()
             WHERE environment_id=@environment_id AND registration_id=@old_registration_id;
            INSERT INTO agent_private.registrations(
                environment_id,registration_id,device_id,registration_epoch,device_guid,state)
            VALUES (@environment_id,@registration_id,@device_id,@registration_epoch,@device_guid,'Active');
            INSERT INTO agent_private.certificate_bindings(
                environment_id,binding_id,registration_id,leaf_der_sha256,state,not_before,not_after)
            VALUES (@environment_id,@binding_id,@registration_id,@fingerprint,'Active',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour')
            """,
            new NpgsqlParameter("environment_id", seed.EnvironmentId),
            new NpgsqlParameter("old_registration_id", seed.RegistrationId),
            new NpgsqlParameter("registration_id", next.RegistrationId),
            new NpgsqlParameter("device_id", next.DeviceId),
            new NpgsqlParameter("registration_epoch", next.RegistrationEpoch),
            new NpgsqlParameter("device_guid", next.DeviceGuid),
            new NpgsqlParameter("binding_id", next.BindingId),
            new NpgsqlParameter("fingerprint", next.Fingerprint));
        return next;
    }

    public NpgsqlDataSource CreateSpoofedIngestDataSource(Guid claimedEnvironment)
    {
        var builder = new NpgsqlConnectionStringBuilder(_ownerConnectionString)
        {
            Username = IngestRole,
            Password = _ingestPassword,
            Pooling = false,
            Options = $"-c app.environment_id={claimedEnvironment}"
        };
        return NpgsqlDataSource.Create(builder.ConnectionString);
    }

    public Task ReprovisionAsync(Guid environmentId)
    {
        var database = new NpgsqlConnectionStringBuilder(_ownerConnectionString).Database!;
        return ExecuteScriptAsync("provision-agent-store.sql", new Dictionary<string, string>
        {
            [":\"agent_definer_role\""] = QuoteIdentifier(DefinerRole),
            [":\"agent_ingest_role\""] = QuoteIdentifier(IngestRole),
            [":'agent_definer_role'"] = QuoteLiteral(DefinerRole),
            [":'agent_ingest_role'"] = QuoteLiteral(IngestRole),
            [":'environment_id'"] = QuoteLiteral(environmentId.ToString()),
            [":DBNAME"] = QuoteIdentifier(database)
        });
    }

    public async Task ExecuteOwnerAsync(string sql, params NpgsqlParameter[] parameters)
    {
        await using var command = OwnerDataSource.CreateCommand(sql);
        command.Parameters.AddRange(parameters);
        await command.ExecuteNonQueryAsync();
    }

    public async Task<T> ScalarOwnerAsync<T>(string sql, params NpgsqlParameter[] parameters)
    {
        await using var command = OwnerDataSource.CreateCommand(sql);
        command.Parameters.AddRange(parameters);
        var value = await command.ExecuteScalarAsync();
        return (T)value!;
    }

    public async Task DisposeAsync()
    {
        if (WebDataSource is not null)
        {
            await WebDataSource.DisposeAsync();
        }
        if (IngestDataSource is not null)
        {
            await IngestDataSource.DisposeAsync();
        }

        if (OwnerDataSource is not null)
        {
            var ownedSchema = await ScalarOwnerAsync<long>(
                """
                SELECT count(*)
                FROM pg_catalog.pg_namespace namespace
                JOIN pg_catalog.pg_roles owner ON owner.oid=namespace.nspowner
                WHERE namespace.nspname='agent_private' AND owner.rolname=@owner
                """,
                new NpgsqlParameter("owner", DefinerRole));
            if (ownedSchema == 1)
            {
                await ExecuteOwnerAsync("DROP SCHEMA agent_private CASCADE");
            }
            if (_rolesCreated)
            {
                var database = new NpgsqlConnectionStringBuilder(_ownerConnectionString).Database!;
                await ExecuteOwnerAsync($"""
                    REVOKE CONNECT ON DATABASE {QuoteIdentifier(database)} FROM {QuoteIdentifier(WebRole)}, {QuoteIdentifier(IngestRole)};
                    DROP ROLE IF EXISTS {QuoteIdentifier(WebRole)};
                    DROP ROLE IF EXISTS {QuoteIdentifier(IngestRole)};
                    DROP ROLE IF EXISTS {QuoteIdentifier(DefinerRole)};
                    """);
            }
            await OwnerDataSource.DisposeAsync();
        }
    }

    private async Task ExecuteScriptAsync(string fileName, IReadOnlyDictionary<string, string> replacements)
    {
        var lines = await File.ReadAllLinesAsync(Path.Combine(AppContext.BaseDirectory, fileName));
        var script = string.Join('\n', lines.Where(static line => !line.StartsWith('\\')));
        foreach (var replacement in replacements.OrderByDescending(static pair => pair.Key.Length))
        {
            script = script.Replace(replacement.Key, replacement.Value, StringComparison.Ordinal);
        }
        await ExecuteOwnerAsync(script);
    }

    private static string QuoteIdentifier(string value)
    {
        if (!SafeIdentifier().IsMatch(value))
        {
            throw new ArgumentException("Unsafe PostgreSQL identifier.", nameof(value));
        }
        return $"\"{value}\"";
    }

    private static string QuoteLiteral(string value) => $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";

    private static void ValidateTestTarget(NpgsqlConnectionStringBuilder builder)
    {
        var loopback = builder.Host is "127.0.0.1" or "localhost" or "::1";
        var testDatabase = builder.Database is "console_test" or "console_ci";
        if (!loopback || !testDatabase)
        {
            throw new InvalidOperationException(
                "Agent ingestion tests require a loopback console_test or console_ci database.");
        }
    }

    [GeneratedRegex("^[a-z][a-z0-9_]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeIdentifier();
}

public sealed record TestRegistration(
    Guid EnvironmentId,
    Guid DeviceId,
    Guid RegistrationId,
    Guid BindingId,
    Guid DeviceGuid,
    long RegistrationEpoch,
    byte[] Fingerprint);
