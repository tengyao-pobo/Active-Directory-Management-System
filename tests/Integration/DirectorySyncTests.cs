using ItManagement.ConnectorHost;
using ItManagement.DirectoryConnector;
using Npgsql;

namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class DirectorySyncTests(PostgresApiFixture fixture)
{
    private static ConsoleDbContext Owner() => new(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Options);
    private const string BaseDn = "DC=example,DC=test";
    private static DirectorySnapshot Snapshot() => new("dc.example.test", BaseDn, DateTimeOffset.UtcNow, [
        new(Guid.NewGuid(), DirectoryObjectKind.OrganizationalUnit, "OU=People," + BaseDn, "People", null, null, null, 1, false, false, BaseDn),
        new(Guid.NewGuid(), DirectoryObjectKind.User, "CN=Alice,OU=People," + BaseDn, "Alice", "alice", "IT", null, 2, false, false, "OU=People," + BaseDn)]);

    [Fact]
    public async Task Complete_snapshot_is_atomic_and_failed_read_preserves_generation_but_marks_unavailable()
    {
        var data = await fixture.SeedAsync();
        await using var role = await ConnectorRole.Create(data.Environment.Id, data.Viewer.Id);
        await using var db = role.Db();
        var snapshot = Snapshot();
        var sync = new DirectorySynchronizer(db, TimeProvider.System);
        Assert.True(await sync.RunAsync(data.Environment.Id, data.Viewer.Id, new Reader(snapshot), CancellationToken.None));
        await using var owner = Owner();
        var before = await owner.DirectorySync.AsNoTracking().SingleAsync(x => x.EnvironmentId == data.Environment.Id);
        var user = await owner.DirectoryObjects.SingleAsync(x => x.EnvironmentId == data.Environment.Id && x.Kind == "User");
        Assert.Equal(snapshot.Entries[0].ObjectId, user.ParentOuId);
        Assert.Contains(snapshot.Entries[0].ObjectId, user.OuAncestry);
        Assert.False(user.ProtectionKnown);
        Assert.False(await sync.RunAsync(data.Environment.Id, data.Viewer.Id, new Reader(null), CancellationToken.None));
        var after = await owner.DirectorySync.AsNoTracking().SingleAsync(x => x.EnvironmentId == data.Environment.Id);
        Assert.Equal(before.Generation, after.Generation);
        Assert.Equal("Failed", after.Status);
        Assert.Equal(2, await owner.DirectoryObjects.CountAsync(x => x.EnvironmentId == data.Environment.Id));
    }

    [Fact]
    public async Task Invalid_snapshot_does_not_publish_partial_projection()
    {
        var data = await fixture.SeedAsync();
        await using var role = await ConnectorRole.Create(data.Environment.Id, data.Viewer.Id);
        await using var db = role.Db();
        var snapshot = Snapshot();
        var invalid = snapshot with { Entries = [snapshot.Entries[0], snapshot.Entries[0]] };
        Assert.False(await new DirectorySynchronizer(db, TimeProvider.System).RunAsync(data.Environment.Id, data.Viewer.Id, new Reader(invalid), CancellationToken.None));
        await using var owner = Owner();
        Assert.Empty(await owner.DirectoryObjects.Where(x => x.EnvironmentId == data.Environment.Id).ToListAsync());
        Assert.Equal("Failed", (await owner.DirectorySync.SingleAsync(x => x.EnvironmentId == data.Environment.Id)).Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Connector_login_cannot_impersonate_a_known_member_in_another_environment(bool audit)
    {
        var own = await fixture.SeedAsync(); var other = await fixture.SeedAsync();
        await using var role = await ConnectorRole.Create(own.Environment.Id, own.Viewer.Id);
        await using var db = role.Db();
        await using var tx = await db.BeginEnvironment(other.Environment.Id, other.Viewer.Id, CancellationToken.None);
        if (audit) db.Audit.Add(new AuditRecord { EnvironmentId = other.Environment.Id, Id = Guid.NewGuid(), ActorId = other.Viewer.Id, Action = "Spoof", Result = "Spoof", OccurredAt = DateTimeOffset.UtcNow });
        else db.DirectoryObjects.Add(new DirectoryObjectRecord { EnvironmentId = other.Environment.Id, Id = Guid.NewGuid(), Kind = "User", Name = "Spoof" });
        var error = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        Assert.Equal("42501", Assert.IsType<PostgresException>(error.InnerException).SqlState);
    }

    [Fact]
    public async Task Revocation_during_network_scan_is_rechecked_before_publication()
    {
        var data = await fixture.SeedAsync();
        await using var role = await ConnectorRole.Create(data.Environment.Id, data.Viewer.Id);
        await using var db = role.Db();
        var reader = new CallbackReader(async () => {
            await using var owner = Owner();
            await owner.Memberships.Where(x => x.EnvironmentId == data.Environment.Id && x.PrincipalId == data.Viewer.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.Active, false));
            return Snapshot();
        });
        Assert.False(await new DirectorySynchronizer(db, TimeProvider.System).RunAsync(data.Environment.Id, data.Viewer.Id, reader, CancellationToken.None));
        await using var check = Owner();
        Assert.Empty(await check.DirectoryObjects.Where(x => x.EnvironmentId == data.Environment.Id).ToListAsync());
    }

    [Fact]
    public async Task Cancelled_scan_preserves_rows_and_records_failure_with_cleanup_token()
    {
        var data = await fixture.SeedAsync();
        await using var role = await ConnectorRole.Create(data.Environment.Id, data.Viewer.Id);
        await using var db = role.Db();
        var sync = new DirectorySynchronizer(db, TimeProvider.System);
        Assert.True(await sync.RunAsync(data.Environment.Id, data.Viewer.Id, new Reader(Snapshot()), CancellationToken.None));
        var reader = new CallbackReader(() => throw new OperationCanceledException());
        Assert.False(await sync.RunAsync(data.Environment.Id, data.Viewer.Id, reader, CancellationToken.None));
        await using var owner = Owner();
        var status = await owner.DirectorySync.SingleAsync(x => x.EnvironmentId == data.Environment.Id);
        Assert.Equal("Failed", status.Status); Assert.Equal("Cancelled", status.ErrorCode);
        Assert.Equal(2, await owner.DirectoryObjects.CountAsync(x => x.EnvironmentId == data.Environment.Id));
    }

    private sealed class CallbackReader(Func<Task<DirectorySnapshot>> read) : IDirectoryReader
    {
        public Task<DirectorySnapshot> ReadSnapshotAsync(CancellationToken cancellationToken) => read();
    }

    private sealed class Reader(DirectorySnapshot? snapshot) : IDirectoryReader
    {
        public Task<DirectorySnapshot> ReadSnapshotAsync(CancellationToken cancellationToken) => snapshot is null
            ? throw new DirectoryReadException(DirectoryReadErrorCode.Timeout) : Task.FromResult(snapshot);
    }

    // Role names and passwords below are generated hex, never caller inputs; DDL cannot parameterize identifiers.
#pragma warning disable EF1002
    private sealed class ConnectorRole(string name, string connection) : IAsyncDisposable
    {
        public ConsoleDbContext Db() => new(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(connection).Options);
        public static async Task<ConnectorRole> Create(Guid environment, Guid principal)
        {
            var name = "test_connector_" + Guid.NewGuid().ToString("N");
            var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            await using var owner = Owner();
            // PostgreSQL ACL updates touch shared catalog rows even for distinct generated roles.
            // Use the same cross-suite lock as the Agent database fixtures for role DDL.
            owner.Database.SetCommandTimeout(120);
            await using var roleDdl = await owner.Database.BeginTransactionAsync();
            await owner.Database.ExecuteSqlRawAsync("SELECT pg_catalog.pg_advisory_xact_lock(7912040301)");
            await owner.Database.ExecuteSqlRawAsync($"CREATE ROLE \"{name}\" LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE");
            var builder = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
            var scriptPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../build/provision-connector.sql"));
            var script = (await File.ReadAllTextAsync(scriptPath))
                .Replace(":\"connector_role\"", $"\"{name}\"").Replace(":'connector_role'", $"'{name}'")
                .Replace(":'environment_id'", $"'{environment}'").Replace(":'principal_id'", $"'{principal}'")
                .Replace(":DBNAME", $"\"{builder.Database}\"");
            await owner.Database.ExecuteSqlRawAsync(script);
            await roleDdl.CommitAsync();
            builder.Username = name; builder.Password = password; builder.Pooling = false;
            return new ConnectorRole(name, builder.ConnectionString);
        }
        public async ValueTask DisposeAsync()
        {
            await using var owner = Owner();
            owner.Database.SetCommandTimeout(120);
            await using var roleDdl = await owner.Database.BeginTransactionAsync();
            await owner.Database.ExecuteSqlRawAsync("SELECT pg_catalog.pg_advisory_xact_lock(7912040301)");
            await owner.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM \"DirectoryDatabaseBindings\" WHERE \"LoginRole\"={name}");
            // This generated role owns no objects; revoke only its test grants before dropping it.
            await owner.Database.ExecuteSqlRawAsync($"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM \"{name}\"; REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM \"{name}\"; REVOKE ALL ON SCHEMA public FROM \"{name}\"; REVOKE ALL ON DATABASE \"{new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Database}\" FROM \"{name}\"; DROP ROLE \"{name}\"");
            await roleDdl.CommitAsync();
        }
    }
#pragma warning restore EF1002
}
