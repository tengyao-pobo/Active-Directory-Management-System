using ItManagement.AgentEnrollmentTargets;
using Npgsql;

namespace ItManagement.Api;

public sealed class EnrollmentTargetEnvironmentOptions
{
    public string ConnectionString { get; set; } = string.Empty;
    public string TableOwnerRole { get; set; } = string.Empty;
    public string FunctionOwnerRole { get; set; } = string.Empty;
}

public sealed class EnrollmentTargetOptions
{
    public Dictionary<string, EnrollmentTargetEnvironmentOptions> Environments { get; set; } = new();
}

public sealed class ConfiguredEnrollmentTargetReader : IEnrollmentTargetReader, IAsyncDisposable
{
    private readonly Dictionary<Guid, IEnrollmentTargetReader> _readers = new();
    private readonly List<NpgsqlDataSource> _sources = [];
    private bool _initialized;

    public async Task InitializeAsync(EnrollmentTargetOptions options, CancellationToken ct)
    {
        if (_initialized) throw new InvalidOperationException("EnrollmentTargetAlreadyInitialized");
        try
        {
            if (options.Environments.Count > 32) throw new InvalidOperationException();
            foreach (var (key, entry) in options.Environments)
            {
                if (!Guid.TryParseExact(key, "D", out var environmentId) || environmentId == Guid.Empty || _readers.ContainsKey(environmentId) ||
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
                _readers.Add(environmentId, await PostgresEnrollmentTargetReader.CreateAuditedAsync(source, environmentId,
                    entry.TableOwnerRole, entry.FunctionOwnerRole, ct));
            }
            _initialized = true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            await DisposeAsync();
            throw;
        }
        catch
        {
            await DisposeAsync();
            throw new InvalidOperationException("EnrollmentTargetConfigurationRejected");
        }
    }

    public Task<EnrollmentTargetResult> ReadAsync(Guid environmentId, Guid directoryObjectId, CancellationToken ct) =>
        _initialized && _readers.TryGetValue(environmentId, out var reader)
            ? reader.ReadAsync(environmentId, directoryObjectId, ct)
            : Task.FromResult(EnrollmentTargetResult.Unavailable(environmentId, directoryObjectId, EnrollmentTargetDiagnostic.ConnectionUnavailable));

    public async ValueTask DisposeAsync()
    {
        _initialized = false;
        _readers.Clear();
        foreach (var source in _sources) await source.DisposeAsync();
        _sources.Clear();
    }
}
