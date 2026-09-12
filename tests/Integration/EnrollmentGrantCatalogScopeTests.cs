using ItManagement.Api;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData(false, 0)]
    [InlineData(false, 1)]
    [InlineData(false, 2)]
    [InlineData(false, 3)]
    [InlineData(false, 4)]
    [InlineData(false, 5)]
    [InlineData(false, 6)]
    [InlineData(true, 0)]
    [InlineData(true, 1)]
    [InlineData(true, 2)]
    [InlineData(true, 3)]
    [InlineData(true, 4)]
    public async Task CatalogScopeRestoresApiConnectionAndCallerTransaction(bool enclosing, int outcome)
    {
        var seeded = await Seed();
        var info = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")!) { Pooling = false };
        await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(info.ConnectionString).Options);
        await db.Database.OpenConnectionAsync();
        await db.Database.ExecuteSqlRawAsync("SELECT pg_catalog.set_config('search_path','public,pg_catalog',false),pg_catalog.set_config('app.catalog_probe','session',false)");
        async Task<string> Setting(string setting) => await db.Database.SqlQuery<string>($"SELECT pg_catalog.current_setting({setting}) AS \"Value\"").SingleAsync();
        IDbContextTransaction? caller = null;
        var auditId = Guid.NewGuid();
        try
        {
            if (enclosing)
            {
                caller = await db.BeginEnvironment(seeded.Data.Environment.Id, seeded.Data.Requester.Id, CancellationToken.None);
                db.Audit.Add(new AuditRecord { EnvironmentId = seeded.Data.Environment.Id, Id = auditId,
                    ActorId = seeded.Data.Requester.Id, Action = "CatalogScope.CallerWrite", Result = "Probe", OccurredAt = seeded.Now });
                await db.SaveChangesAsync();
                await db.Database.ExecuteSqlRawAsync("SELECT pg_catalog.set_config('app.catalog_probe','caller',true)");
            }
            var originalPath = await Setting("search_path");
            var originalProbe = await Setting("app.catalog_probe");
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            if (outcome == 6) await cancellation.CancelAsync();
            var entered = false;
            var attempt = CatalogAuditScope.RunAsync(db, CatalogAuditPath.Profile4, async (auditDb, token) =>
            {
                entered = true;
                Assert.Same(db, auditDb);
                Assert.Equal("pg_catalog,pg_temp", await Setting("search_path"));
                Assert.Equal(enclosing ? "off" : "on", await Setting("transaction_read_only"));
                await auditDb.Database.ExecuteSqlRawAsync("SELECT pg_catalog.set_config('app.catalog_probe','inside_audit',true)", token);
                if (outcome == 1)
                    return await auditDb.Database.SqlQueryRaw<int>("SELECT 1/(pg_catalog.pg_backend_pid()-pg_catalog.pg_backend_pid()) AS \"Value\"").SingleAsync(token) == 1;
                if (outcome == 2)
                {
                    cancellation.CancelAfter(TimeSpan.FromMilliseconds(100));
                    await auditDb.Database.ExecuteSqlRawAsync("SELECT pg_catalog.pg_sleep(10)", token);
                }
                if (outcome == 3)
                    return await auditDb.Database.SqlQueryRaw<int>("SELECT 1 AS \"Value\" WHERE false").SingleAsync(token) == 1;
                if (outcome == 4) return false;
                if (outcome == 5)
                {
                    var denied = await Assert.ThrowsAsync<PostgresException>(() => auditDb.Database.ExecuteSqlRawAsync("UPDATE public.\"Plans\" SET \"State\"=\"State\" WHERE false", token));
                    Assert.Equal("25006", denied.SqlState);
                    throw denied;
                }
                return true;
            }, cancellation.Token);
            if (outcome is 2 or 6) await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { await attempt; });
            else Assert.Equal(outcome == 0, await attempt);
            Assert.Equal(outcome != 6, entered);
            Assert.Equal(originalPath, await Setting("search_path"));
            Assert.Equal(originalProbe, await Setting("app.catalog_probe"));
            Assert.Same(caller, db.Database.CurrentTransaction);
            Assert.Equal(1, await db.Database.SqlQueryRaw<int>("SELECT 1 AS \"Value\"").SingleAsync());
            if (caller is not null)
                Assert.True(await db.Audit.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Id == auditId));
        }
        finally
        {
            if (caller is not null)
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try { await caller.RollbackAsync(cleanup.Token); }
                finally { await caller.DisposeAsync(); }
            }
        }
        await using var verify = Db();
        Assert.False(await verify.Audit.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Id == auditId));
    }

    [Fact]
    public async Task CatalogScopeErrorPreservesCallerWritesAndAllowsCommit()
    {
        var seeded = await Seed();
        var ids = new[] { Guid.NewGuid(), Guid.NewGuid() };
        var info = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")!) { Pooling = false };
        await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(info.ConnectionString).Options);
        await using var caller = await db.BeginEnvironment(seeded.Data.Environment.Id, seeded.Data.Requester.Id, CancellationToken.None);
        ChangePlan Plan(Guid id) => new() { EnvironmentId = seeded.Data.Environment.Id, Id = id, RequesterId = seeded.Data.Requester.Id,
            Action = "catalog-scope.probe", ImmutablePlanJson = "{}", PlanHash = new string('a', 64), PolicyVersion = 1,
            ExpiresAt = seeded.Now.AddMinutes(1), State = ChangePlanState.PendingApproval };
        try
        {
            db.Plans.Add(Plan(ids[0]));
            await db.SaveChangesAsync();
            Assert.False(await CatalogAuditScope.RunAsync(db, CatalogAuditPath.Profile4,
                async (auditDb, token) => await auditDb.Database.SqlQueryRaw<int>("SELECT 1/(pg_catalog.pg_backend_pid()-pg_catalog.pg_backend_pid()) AS \"Value\"").SingleAsync(token) == 1, CancellationToken.None));
            Assert.Same(caller, db.Database.CurrentTransaction);
            db.Plans.Add(Plan(ids[1]));
            await db.SaveChangesAsync();
            await caller.CommitAsync();
            await using var verify = Db();
            Assert.Equal(2, await verify.Plans.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && ids.Contains(x.Id)));
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            if (db.Database.CurrentTransaction is not null) await caller.RollbackAsync(cleanup.Token);
            await using var admin = Db();
            await admin.Plans.Where(x => x.EnvironmentId == seeded.Data.Environment.Id && ids.Contains(x.Id)).ExecuteDeleteAsync(cleanup.Token);
            Assert.False(await admin.Plans.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && ids.Contains(x.Id), cleanup.Token));
        }
    }
}
