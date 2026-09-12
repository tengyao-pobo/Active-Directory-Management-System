using System.Collections.ObjectModel;
using System.Net;
using Npgsql;

namespace ItManagement.EnrollmentWorker;

public sealed class EnrollmentWorkerOptions
{
    public int Concurrency { get; set; } = 4;
    public List<EnrollmentWorkerEnvironmentOptions> Environments { get; set; } = [];

    internal ValidatedEnrollmentWorkerOptions ValidateAndSnapshot()
    {
        if (Concurrency is < 1 or > 8 || Environments is null || Environments.Count is < 1 or > 32)
            throw Invalid();

        var environmentIds = new HashSet<Guid>();
        var logins = new HashSet<string>(StringComparer.Ordinal);
        var passwords = new HashSet<string>(StringComparer.Ordinal);
        var owners = new HashSet<string>(StringComparer.Ordinal);
        var publicDatabases = new HashSet<DatabaseIdentity>();
        var privateDatabases = new HashSet<DatabaseIdentity>();
        var snapshots = new ValidatedEnrollmentWorkerEnvironment[Environments.Count];

        for (var index = 0; index < Environments.Count; index++)
        {
            var environment = Environments[index];
            if (environment is null || environment.EnvironmentId == Guid.Empty ||
                !environmentIds.Add(environment.EnvironmentId) ||
                environment.PublicDatabase is null || environment.PrivateDatabase is null)
                throw Invalid();

            var publicDatabase = ValidatePublic(environment.PublicDatabase);
            var privateDatabase = ValidatePrivate(environment.PrivateDatabase);
            if (!logins.Add(publicDatabase.Username) || !logins.Add(privateDatabase.Username))
                throw Invalid();
            if (!passwords.Add(environment.PublicDatabase.Password) ||
                !passwords.Add(environment.PrivateDatabase.Password))
                throw Invalid();

            owners.Add(publicDatabase.ExpectedTableOwner);
            owners.Add(publicDatabase.ExpectedExecutionOwner);
            owners.Add(publicDatabase.ExpectedQueueOwner);
            owners.Add(privateDatabase.ExpectedTableOwner);
            owners.Add(privateDatabase.ExpectedFunctionOwner);

            publicDatabases.Add(publicDatabase.Identity);
            privateDatabases.Add(privateDatabase.Identity);
            snapshots[index] = new ValidatedEnrollmentWorkerEnvironment(
                environment.EnvironmentId,
                publicDatabase,
                privateDatabase);
        }

        if (logins.Overlaps(owners) || publicDatabases.Overlaps(privateDatabases))
            throw Invalid();

        return new ValidatedEnrollmentWorkerOptions(
            Concurrency,
            Array.AsReadOnly(snapshots));
    }

    public override string ToString() => nameof(EnrollmentWorkerOptions);

    private static ValidatedPublicDatabase ValidatePublic(EnrollmentWorkerPublicDatabaseOptions value)
    {
        var database = ValidateDatabase(value);
        if (!LowerIdentifier(value.ExpectedTableOwner) ||
            !LowerIdentifier(value.ExpectedExecutionOwner) ||
            !LowerIdentifier(value.ExpectedQueueOwner))
            throw Invalid();

        return new ValidatedPublicDatabase(
            database,
            value.ExpectedTableOwner,
            value.ExpectedExecutionOwner,
            value.ExpectedQueueOwner);
    }

    private static ValidatedPrivateDatabase ValidatePrivate(EnrollmentWorkerPrivateDatabaseOptions value)
    {
        var database = ValidateDatabase(value);
        if (!LowerIdentifier(value.ExpectedTableOwner) || !LowerIdentifier(value.ExpectedFunctionOwner))
            throw Invalid();

        return new ValidatedPrivateDatabase(database, value.ExpectedTableOwner, value.ExpectedFunctionOwner);
    }

    private static ValidatedDatabase ValidateDatabase(EnrollmentWorkerDatabaseOptions value)
    {
        if (!CanonicalFqdn(value.Host) || value.Port is < 1 or > 65_535 ||
            !AsciiIdentifier(value.Database) || !LowerIdentifier(value.Username) ||
            string.IsNullOrWhiteSpace(value.Password) || value.Password.Length > 4_096 ||
            string.IsNullOrWhiteSpace(value.RootCertificate) ||
            !SafeRootCertificatePath(value.RootCertificate))
            throw Invalid();

        return new ValidatedDatabase(
            value.Host,
            value.Port,
            value.Database,
            value.Username,
            value.Password,
            value.RootCertificate);
    }

    private static bool CanonicalFqdn(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 253 || value[^1] == '.' ||
            !value.Contains('.', StringComparison.Ordinal) || IPAddress.TryParse(value, out _))
            return false;

        foreach (var label in value.Split('.'))
        {
            if (label.Length is < 1 or > 63 || !AsciiLowerAlphaNumeric(label[0]) ||
                !AsciiLowerAlphaNumeric(label[^1]))
                return false;
            foreach (var character in label)
                if (!AsciiLowerAlphaNumeric(character) && character != '-') return false;
        }
        return true;
    }

    private static bool AsciiIdentifier(string? value) =>
        value is { Length: >= 1 and <= 63 } &&
        (AsciiLetter(value[0]) || value[0] == '_') &&
        value.All(character => AsciiLetter(character) || char.IsAsciiDigit(character) || character == '_');

    private static bool LowerIdentifier(string? value) =>
        value is { Length: >= 1 and <= 63 } &&
        (AsciiLower(value[0]) || value[0] == '_') &&
        value.All(character => AsciiLower(character) || char.IsAsciiDigit(character) || character == '_');

    private static bool AsciiLetter(char value) => AsciiLower(value) || value is >= 'A' and <= 'Z';
    private static bool AsciiLower(char value) => value is >= 'a' and <= 'z';
    private static bool AsciiLowerAlphaNumeric(char value) => AsciiLower(value) || char.IsAsciiDigit(value);
    private static bool SafeRootCertificatePath(string value)
    {
        if (!Path.IsPathFullyQualified(value)) return false;
        if (!OperatingSystem.IsWindows()) return !value.StartsWith("//", StringComparison.Ordinal);

        return value.Length >= 3 && AsciiLetter(value[0]) && value[1] == ':' &&
            value[2] is '\\' or '/' &&
            !value.StartsWith(@"\\", StringComparison.Ordinal) &&
            !value.StartsWith("//", StringComparison.Ordinal);
    }

    private static InvalidOperationException Invalid() => new("EnrollmentWorkerConfigurationInvalid");
}

public sealed class EnrollmentWorkerEnvironmentOptions
{
    public Guid EnvironmentId { get; set; }
    public EnrollmentWorkerPublicDatabaseOptions? PublicDatabase { get; set; }
    public EnrollmentWorkerPrivateDatabaseOptions? PrivateDatabase { get; set; }
    public override string ToString() => nameof(EnrollmentWorkerEnvironmentOptions);
}

public abstract class EnrollmentWorkerDatabaseOptions
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 5432;
    public string Database { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string RootCertificate { get; set; } = "";
    public override string ToString() => GetType().Name;
}

public sealed class EnrollmentWorkerPublicDatabaseOptions : EnrollmentWorkerDatabaseOptions
{
    public string ExpectedTableOwner { get; set; } = "";
    public string ExpectedExecutionOwner { get; set; } = "";
    public string ExpectedQueueOwner { get; set; } = "";
}

public sealed class EnrollmentWorkerPrivateDatabaseOptions : EnrollmentWorkerDatabaseOptions
{
    public string ExpectedTableOwner { get; set; } = "";
    public string ExpectedFunctionOwner { get; set; } = "";
}

internal sealed class ValidatedEnrollmentWorkerOptions(
    int concurrency,
    ReadOnlyCollection<ValidatedEnrollmentWorkerEnvironment> environments)
{
    public int Concurrency { get; } = concurrency;
    public IReadOnlyList<ValidatedEnrollmentWorkerEnvironment> Environments { get; } = environments;
    public override string ToString() => nameof(ValidatedEnrollmentWorkerOptions);
}

internal sealed class ValidatedEnrollmentWorkerEnvironment(
    Guid environmentId,
    ValidatedPublicDatabase publicDatabase,
    ValidatedPrivateDatabase privateDatabase)
{
    public Guid EnvironmentId { get; } = environmentId;
    public ValidatedPublicDatabase PublicDatabase { get; } = publicDatabase;
    public ValidatedPrivateDatabase PrivateDatabase { get; } = privateDatabase;
    public override string ToString() => nameof(ValidatedEnrollmentWorkerEnvironment);
}

internal abstract class ValidatedDatabaseConnection
{
    private readonly ValidatedDatabase _database;

    protected ValidatedDatabaseConnection(ValidatedDatabase database) => _database = database;

    public string Host => _database.Host;
    public int Port => _database.Port;
    public string Database => _database.Database;
    public string Username => _database.Username;
    public string RootCertificate => _database.RootCertificate;
    internal DatabaseIdentity Identity => _database.Identity;

    internal string BuildConnectionString() => new NpgsqlConnectionStringBuilder
    {
        Host = _database.Host,
        Port = _database.Port,
        Database = _database.Database,
        Username = _database.Username,
        Password = _database.Password,
        RootCertificate = _database.RootCertificate,
        SslMode = SslMode.VerifyFull,
        CheckCertificateRevocation = true,
        GssEncryptionMode = GssEncryptionMode.Disable,
        SearchPath = "pg_catalog,pg_temp",
        Timezone = "UTC",
        Pooling = true,
        MinPoolSize = 0,
        MaxPoolSize = 1,
        Timeout = 10,
        CommandTimeout = 30,
        CancellationTimeout = 2_000,
        Enlist = false,
        Multiplexing = false,
        NoResetOnClose = false,
        IncludeErrorDetail = false,
        LogParameters = false
    }.ConnectionString;

    public override string ToString() => GetType().Name;
}

internal sealed class ValidatedPublicDatabase(
    ValidatedDatabase database,
    string expectedTableOwner,
    string expectedExecutionOwner,
    string expectedQueueOwner) : ValidatedDatabaseConnection(database)
{
    public string ExpectedTableOwner { get; } = expectedTableOwner;
    public string ExpectedExecutionOwner { get; } = expectedExecutionOwner;
    public string ExpectedQueueOwner { get; } = expectedQueueOwner;
}

internal sealed class ValidatedPrivateDatabase(
    ValidatedDatabase database,
    string expectedTableOwner,
    string expectedFunctionOwner) : ValidatedDatabaseConnection(database)
{
    public string ExpectedTableOwner { get; } = expectedTableOwner;
    public string ExpectedFunctionOwner { get; } = expectedFunctionOwner;
}

internal sealed class ValidatedDatabase(
    string host,
    int port,
    string database,
    string username,
    string password,
    string rootCertificate)
{
    public string Host { get; } = host;
    public int Port { get; } = port;
    public string Database { get; } = database;
    public string Username { get; } = username;
    public string Password { get; } = password;
    public string RootCertificate { get; } = rootCertificate;
    public DatabaseIdentity Identity { get; } = new(host, port, database);
    public override string ToString() => nameof(ValidatedDatabase);
}

internal readonly record struct DatabaseIdentity(string Host, int Port, string Database);
