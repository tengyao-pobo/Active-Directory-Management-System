using ItManagement.AgentProjection;
using Npgsql;

namespace ItManagement.Api;

public sealed class AgentProjectionEnvironmentOptions
{
    public string ConnectionString { get; set; } = string.Empty;
    public string TableOwnerRole { get; set; } = string.Empty;
    public string FunctionOwnerRole { get; set; } = string.Empty;
}

public sealed class AgentProjectionOptions
{
    public Dictionary<string, AgentProjectionEnvironmentOptions> Environments { get; set; } = new();
}

public sealed class ConfiguredAgentProjectionReader : IAgentBitLockerProjectionReader, IAsyncDisposable
{
    private readonly Dictionary<Guid, IAgentBitLockerProjectionReader> _readers = new();
    private readonly List<NpgsqlDataSource> _sources = [];
    private bool _initialized;

    public async Task InitializeAsync(AgentProjectionOptions options, CancellationToken ct)
    {
        if (_initialized) throw new InvalidOperationException("ProjectionAlreadyInitialized");
        try
        {
            if (options.Environments.Count > 32) throw new InvalidOperationException();
            foreach (var (key, entry) in options.Environments)
            {
                if (!Guid.TryParse(key, out var environmentId) || environmentId == Guid.Empty || _readers.ContainsKey(environmentId) ||
                    string.IsNullOrWhiteSpace(entry.TableOwnerRole) || string.IsNullOrWhiteSpace(entry.FunctionOwnerRole) ||
                    entry.TableOwnerRole.Length > 63 || entry.FunctionOwnerRole.Length > 63 || string.IsNullOrWhiteSpace(entry.ConnectionString))
                    throw new InvalidOperationException();
                var connection = new NpgsqlConnectionStringBuilder(entry.ConnectionString) { IncludeErrorDetail = false };
                if (connection.Host is not ("localhost" or "127.0.0.1" or "::1") && connection.SslMode != SslMode.VerifyFull)
                    throw new InvalidOperationException();
                connection.Timeout = connection.Timeout is > 0 and <= 10 ? connection.Timeout : 10;
                connection.CommandTimeout = connection.CommandTimeout is > 0 and <= 10 ? connection.CommandTimeout : 10;
                var source = NpgsqlDataSource.Create(connection.ConnectionString);
                _sources.Add(source);
                var reader = await PostgresAgentBitLockerProjectionReader.CreateAuditedAsync(source, environmentId,
                    entry.TableOwnerRole, entry.FunctionOwnerRole, ct);
                _readers.Add(environmentId, reader);
            }
            _initialized = true;
        }
        catch
        {
            await DisposeAsync();
            // Configuration and provider errors may contain connection details. Do not propagate their messages.
            throw new InvalidOperationException("AgentProjectionConfigurationRejected");
        }
    }

    public Task<BitLockerProjection> ReadAsync(Guid environmentId, Guid directoryObjectId, CancellationToken ct) =>
        _initialized && _readers.TryGetValue(environmentId, out var reader)
            ? reader.ReadAsync(environmentId, directoryObjectId, ct)
            : Task.FromResult(BitLockerProjection.Unavailable(environmentId, directoryObjectId, ProjectionDiagnostic.ConnectionUnavailable));

    public async ValueTask DisposeAsync()
    {
        _initialized = false;
        _readers.Clear();
        foreach (var source in _sources) await source.DisposeAsync();
        _sources.Clear();
    }
}
