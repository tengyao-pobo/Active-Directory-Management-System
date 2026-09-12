using System.Net;
using System.Text.Json;
using ItManagement.Core;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ExecutionReportsDatabasePublicationClosureAndRollsBack(bool recognized)
    {
        var seeded = await Seed();
        using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var plan = await ApprovedExecutionPlan(seeded, factory);
        using var client = Client(factory, seeded.Data.RequesterToken);
        using var request = await client.MutationAsync(HttpMethod.Post, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        await using var blocker = Db();
        await using var transaction = await blocker.Database.BeginTransactionAsync();
        await blocker.Database.ExecuteSqlRawAsync("SELECT pg_catalog.pg_advisory_xact_lock(1162235478,1)");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var pending = client.SendAsync(request, cancellation.Token);
        var name = "test_publication_closed_" + Guid.NewGuid().ToString("N");
        using var identifiers = new NpgsqlCommandBuilder();
        var sqlName = identifiers.QuoteIdentifier(name);
        var installed = false;
        var diagnostic = recognized ? "Enrollment grant publication is unavailable." : "Unrelated database invariant.";
        try
        {
            var blocked = false;
            for (var i = 0; i < 500 && !blocked; i++)
            {
                blocked = await blocker.Database.SqlQueryRaw<bool>("""
                    SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l
                      WHERE l.locktype='advisory' AND l.classid=1162235478 AND l.objid=1 AND l.objsubid=2
                        AND l.mode='ShareLock' AND NOT l.granted
                        AND pg_catalog.pg_backend_pid()=ANY(pg_catalog.pg_blocking_pids(l.pid))) AS "Value"
                    """).SingleAsync(cancellation.Token);
                if (!blocked) await Task.Delay(20, cancellation.Token);
            }
            Assert.True(blocked);
            // Install a disposable error-producing trigger after the endpoint's
            // catalog preflight, while final publication is waiting. This exercises
            // the actual provider exception chain and rollback, not v4 activation.
            await using (var install = new NpgsqlCommand($"""
                CREATE FUNCTION public.{sqlName}() RETURNS trigger LANGUAGE plpgsql AS $f$
                BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='{diagnostic}'; END
                $f$;
                REVOKE ALL ON FUNCTION public.{sqlName}() FROM PUBLIC;
                CREATE TRIGGER {sqlName} BEFORE INSERT ON public."EnrollmentGrantOperations"
                FOR EACH ROW EXECUTE FUNCTION public.{sqlName}();
                """, (NpgsqlConnection)blocker.Database.GetDbConnection()))
                await install.ExecuteNonQueryAsync(cancellation.Token);
            await transaction.CommitAsync(cancellation.Token);
            installed = true;
            using var response = await pending;
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            var problem = await response.Content.ReadAsStringAsync(cancellation.Token);
            using var parsed = JsonDocument.Parse(problem);
            Assert.Equal(recognized ? "EnrollmentGrantExecutionUnavailable" : "ServiceUnavailable", parsed.RootElement.GetProperty("title").GetString());
            Assert.DoesNotContain(name, problem, StringComparison.Ordinal);
            await using var verify = Db();
            Assert.Equal(ChangePlanState.Approved, await verify.Plans.Where(x => x.Id == plan.Id).Select(x => x.State).SingleAsync(cancellation.Token));
            Assert.False(await verify.EnrollmentGrantOperations.AnyAsync(x => x.PlanId == plan.Id, cancellation.Token));
            Assert.False(await verify.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id, cancellation.Token));
            Assert.False(await verify.Audit.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == "EnrollmentGrantExecution.Queued", cancellation.Token));
        }
        finally
        {
            await cancellation.CancelAsync();
            try { if (blocker.Database.CurrentTransaction is not null) await transaction.RollbackAsync(CancellationToken.None); }
            finally
            {
                await ObserveExecutionRequests(pending);
                if (installed)
                {
                    await using var cleanup = Db();
                    await cleanup.Database.OpenConnectionAsync(CancellationToken.None);
                    await using var drop = new NpgsqlCommand($"DROP TRIGGER {sqlName} ON public.\"EnrollmentGrantOperations\"; DROP FUNCTION public.{sqlName}()", (NpgsqlConnection)cleanup.Database.GetDbConnection()) { CommandTimeout = 10 };
                    await drop.ExecuteNonQueryAsync(CancellationToken.None);
                    Assert.Equal(0, await cleanup.Database.SqlQuery<int>($"SELECT count(*)::integer AS \"Value\" FROM pg_catalog.pg_proc WHERE pronamespace='public'::regnamespace AND proname={name}").SingleAsync(CancellationToken.None));
                }
            }
        }
    }
}
