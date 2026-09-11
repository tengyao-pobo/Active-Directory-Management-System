using System.Net;
using ItManagement.Core;
using ItManagement.AgentEnrollmentTargets;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Fact]
    public async Task ConcurrentIdenticalRequestsRecoverOnePlanAndOneAudit()
    {
        var seeded = await Seed(); var requestId = Guid.NewGuid(); var arrivals = 0;
        var reader = new AsyncReader((env, directory) =>
        {
            Interlocked.Increment(ref arrivals);
            return Task.FromResult(EnrollmentTargetResult.Resolved(env, directory, seeded.DeviceId, seeded.Now.AddMinutes(-1)));
        });
        using var factory = Factory(reader, seeded.Now);
        using var firstClient = Client(factory, seeded.Data.RequesterToken);
        using var secondClient = Client(factory, seeded.Data.RequesterToken);
        await using var blocker = Db();
        await using var blockerTransaction = await blocker.Database.BeginTransactionAsync();
        var lockKey = $"EnrollmentGrantPlanRequest.v1|{seeded.Data.Environment.Id:D}|{seeded.Data.Requester.Id:D}|{requestId:D}";
        await blocker.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtextextended({lockKey}, 709763624))");
        var concurrentRequests = Task.WhenAll(
            Post(firstClient, CreatePath(seeded), Body(seeded, requestId)),
            Post(secondClient, CreatePath(seeded), Body(seeded, requestId)));
        try
        {
            var waiters = 0;
            try
            {
                // Both final transactions must already hold their snapshots and wait on the same request lock.
                // Releasing only after observing both waiters forces the loser through serialization recovery.
                var deadline = DateTime.UtcNow.AddSeconds(15);
                do
                {
                    waiters = await blocker.Database.SqlQueryRaw<int>("""
                        SELECT count(*)::integer AS "Value" FROM pg_catalog.pg_locks holder
                        JOIN pg_catalog.pg_locks waiter ON waiter.locktype=holder.locktype
                            AND waiter.database=holder.database AND waiter.classid=holder.classid
                            AND waiter.objid=holder.objid AND waiter.objsubid=holder.objsubid
                        WHERE holder.pid=pg_catalog.pg_backend_pid() AND holder.locktype='advisory'
                            AND holder.granted AND NOT waiter.granted
                        """).SingleAsync();
                    if (waiters != 2) await Task.Delay(20);
                } while (waiters != 2 && DateTime.UtcNow < deadline);
            }
            finally { await blockerTransaction.RollbackAsync(); }
            var results = await concurrentRequests.WaitAsync(TimeSpan.FromSeconds(20));
            Assert.Equal(2, waiters);
            Assert.Equal([HttpStatusCode.OK, HttpStatusCode.Created], results.Select(x => x.Status).Order().ToArray());
            Assert.Equal(3, arrivals);
            Assert.Equal(results[0].Json.GetProperty("id").GetGuid(), results[1].Json.GetProperty("id").GetGuid());
            await using var db = Db();
            Assert.Equal(1, await db.Plans.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == EnrollmentGrantPlanContract.Action));
            Assert.Equal(1, await db.EnrollmentGrantRecipientReservations.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
            Assert.Equal(1, await db.Audit.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == "EnrollmentGrantPlan.Created"));
            Assert.False(await db.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        }
        finally
        {
            firstClient.CancelPendingRequests();
            secondClient.CancelPendingRequests();
            // Observe both HTTP tasks after releasing the blocker, including assertion and timeout paths.
            try { await concurrentRequests; } catch { }
        }
    }

    [Theory]
    [InlineData("recipientSpki")]
    [InlineData("reason")]
    public async Task NullStoredPayloadFailsClosedForReadApprovalAndExactRecovery(string field)
    {
        var seeded = await Seed(); var requestId = Guid.NewGuid();
        using var factory = Factory(ResolvedReader(seeded), seeded.Now);
        using var requester = Client(factory, seeded.Data.RequesterToken);
        var created = await Post(requester, CreatePath(seeded), Body(seeded, requestId));
        Assert.Equal(HttpStatusCode.Created, created.Status);
        var id = created.Json.GetProperty("id").GetGuid(); var hash = created.Json.GetProperty("planHash").GetString()!;
        await using (var db = Db())
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE public."Plans" SET "ImmutablePlanJson" =
                    pg_catalog.jsonb_set("ImmutablePlanJson", ARRAY[{field}]::text[], 'null'::jsonb, false)
                WHERE "EnvironmentId"={seeded.Data.Environment.Id} AND "Id"={id}
                """);
            if (field == "reason")
                await db.Plans.Where(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Id == id)
                    .ExecuteUpdateAsync(x => x.SetProperty(p => p.Reason, (string?)null));
        }
        using var read = await requester.GetAsync(ReadPath(seeded, id));
        Assert.Equal(HttpStatusCode.Conflict, read.StatusCode);
        using var reviewer = Client(factory, seeded.Data.ReviewerToken);
        Assert.Equal(HttpStatusCode.Conflict, (await Post(reviewer, ApprovalPath(seeded, id), new { planHash = hash })).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await Post(requester, CreatePath(seeded), Body(seeded, requestId))).Status);
        await using var verify = Db();
        Assert.Equal(1, await verify.Plans.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == EnrollmentGrantPlanContract.Action));
        Assert.Equal(1, await verify.EnrollmentGrantRecipientReservations.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.Equal(1, await verify.Audit.CountAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == "EnrollmentGrantPlan.Created"));
        Assert.False(await verify.Approvals.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.False(await verify.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
    }

    [Fact]
    public async Task FingerprintCollisionRollsBackLosingPlanAndAuditAcrossEnvironments()
    {
        var winner = await Seed(); var loser = await Seed();
        loser = loser with { SubjectPublicKeyInfo = winner.SubjectPublicKeyInfo };
        using var winnerFactory = Factory(ResolvedReader(winner), winner.Now);
        using var winnerClient = Client(winnerFactory, winner.Data.RequesterToken);
        Assert.Equal(HttpStatusCode.Created, (await Post(winnerClient, CreatePath(winner), Body(winner, Guid.NewGuid()))).Status);
        using var loserFactory = Factory(ResolvedReader(loser), loser.Now);
        using var loserClient = Client(loserFactory, loser.Data.RequesterToken);
        Assert.Equal(HttpStatusCode.Conflict, (await Post(loserClient, CreatePath(loser), Body(loser, Guid.NewGuid()))).Status);
        await using var db = Db();
        Assert.False(await db.Plans.AnyAsync(x => x.EnvironmentId == loser.Data.Environment.Id && x.Action == EnrollmentGrantPlanContract.Action));
        Assert.False(await db.EnrollmentGrantRecipientReservations.AnyAsync(x => x.EnvironmentId == loser.Data.Environment.Id));
        Assert.False(await db.Audit.AnyAsync(x => x.EnvironmentId == loser.Data.Environment.Id && x.Action.StartsWith("EnrollmentGrantPlan.")));
        Assert.False(await db.Outbox.AnyAsync(x => x.EnvironmentId == loser.Data.Environment.Id));
        Assert.Equal(1, await db.Plans.CountAsync(x => x.EnvironmentId == winner.Data.Environment.Id && x.Action == EnrollmentGrantPlanContract.Action));
        Assert.Equal(1, await db.Audit.CountAsync(x => x.EnvironmentId == winner.Data.Environment.Id && x.Action == "EnrollmentGrantPlan.Created"));
    }

    [Theory]
    [InlineData("membership", HttpStatusCode.NotFound)]
    [InlineData("disabled", HttpStatusCode.BadRequest)]
    [InlineData("owner", HttpStatusCode.NotFound)]
    [InlineData("view", HttpStatusCode.NotFound)]
    [InlineData("manage", HttpStatusCode.NotFound)]
    [InlineData("disjoint", HttpStatusCode.NotFound)]
    [InlineData("step-up", HttpStatusCode.Forbidden)]
    [InlineData("version", HttpStatusCode.PreconditionFailed)]
    [InlineData("generation", HttpStatusCode.PreconditionFailed)]
    [InlineData("object-generation", HttpStatusCode.NotFound)]
    [InlineData("kind", HttpStatusCode.NotFound)]
    [InlineData("missing-object", HttpStatusCode.NotFound)]
    [InlineData("stale", HttpStatusCode.ServiceUnavailable)]
    [InlineData("future", HttpStatusCode.ServiceUnavailable)]
    [InlineData("incomplete", HttpStatusCode.ServiceUnavailable)]
    [InlineData("status", HttpStatusCode.ServiceUnavailable)]
    public async Task ProposalAuthorizationFailuresNeverResolveOrReserveARecipient(string fault, HttpStatusCode expected)
    {
        var seeded = await Seed(); var reader = ResolvedReader(seeded);
        using var factory = Factory(reader, seeded.Now); using var client = Client(factory, seeded.Data.RequesterToken);
        using var request = await client.MutationAsync(HttpMethod.Post, CreatePath(seeded), Body(seeded, Guid.NewGuid()));
        await using (var db = Db())
        {
            var env = seeded.Data.Environment.Id; var requester = seeded.Data.Requester.Id;
            switch (fault)
            {
                case "membership":
                    (await db.Memberships.SingleAsync(x => x.EnvironmentId == env && x.PrincipalId == requester)).Active = false;
                    break;
                case "disabled":
                    (await db.Principals.SingleAsync(x => x.Id == requester)).Enabled = false;
                    break;
                case "owner":
                    var role = new Role { EnvironmentId = env, Id = Guid.NewGuid(), Name = "Owner", BuiltInKind = null };
                    db.Roles.Add(role);
                    var copiedPermissions = await db.RolePermissions.Where(x => x.EnvironmentId == env && x.RoleId == seeded.Data.RequesterRoleId)
                        .Select(x => x.Permission).ToListAsync();
                    db.RolePermissions.AddRange(copiedPermissions.Select(permission => new RolePermission
                        { EnvironmentId = env, RoleId = role.Id, Permission = permission }));
                    foreach (var assignment in await db.Assignments.Where(x => x.EnvironmentId == env && x.PrincipalId == requester).ToListAsync())
                        assignment.RoleId = role.Id;
                    break;
                case "view":
                case "manage":
                    var permission = fault == "view" ? PermissionCatalog.ComputerView : PermissionCatalog.AgentEnrollmentGrantManage;
                    db.RolePermissions.Remove(await db.RolePermissions.SingleAsync(x => x.EnvironmentId == env && x.RoleId == seeded.Data.RequesterRoleId && x.Permission == permission));
                    break;
                case "disjoint":
                    db.RolePermissions.Remove(await db.RolePermissions.SingleAsync(x => x.EnvironmentId == env && x.RoleId == seeded.Data.RequesterRoleId && x.Permission == PermissionCatalog.AgentEnrollmentGrantManage));
                    var otherRole = new Role { EnvironmentId = env, Id = Guid.NewGuid(), Name = "Scoped enrollment owner", BuiltInKind = BuiltInRoleKinds.Owner };
                    var otherScope = new Scope { EnvironmentId = env, Id = Guid.NewGuid(), Kind = ScopeKind.OrganizationalUnit, Value = Guid.NewGuid().ToString("D") };
                    db.AddRange(otherRole, otherScope,
                        new RolePermission { EnvironmentId = env, RoleId = otherRole.Id, Permission = PermissionCatalog.AgentEnrollmentGrantManage },
                        new RoleAssignment { EnvironmentId = env, Id = Guid.NewGuid(), PrincipalId = requester, RoleId = otherRole.Id, ScopeId = otherScope.Id });
                    break;
                case "step-up":
                    foreach (var session in await db.Sessions.Where(x => x.PrincipalId == requester).ToListAsync()) session.StepUpAt = null;
                    break;
                case "version":
                    (await db.Environments.SingleAsync(x => x.Id == env)).Version++;
                    break;
                case "generation":
                    var generation = Guid.NewGuid();
                    (await db.DirectorySync.SingleAsync(x => x.EnvironmentId == env)).Generation = generation;
                    (await db.DirectoryObjects.SingleAsync(x => x.EnvironmentId == env && x.Id == seeded.DirectoryObjectId)).Generation = generation;
                    break;
                case "object-generation":
                    (await db.DirectoryObjects.SingleAsync(x => x.EnvironmentId == env && x.Id == seeded.DirectoryObjectId)).Generation = Guid.NewGuid();
                    break;
                case "kind":
                    (await db.DirectoryObjects.SingleAsync(x => x.EnvironmentId == env && x.Id == seeded.DirectoryObjectId)).Kind = "User";
                    break;
                case "missing-object":
                    db.DirectoryObjects.Remove(await db.DirectoryObjects.SingleAsync(x => x.EnvironmentId == env && x.Id == seeded.DirectoryObjectId));
                    break;
                default:
                    var sync = await db.DirectorySync.SingleAsync(x => x.EnvironmentId == env);
                    if (fault == "stale") sync.CompletedAt = seeded.Now.AddMinutes(-15).AddTicks(-10);
                    if (fault == "future") sync.CompletedAt = seeded.Now.AddTicks(10);
                    if (fault == "incomplete") sync.CompletedAt = null;
                    if (fault == "status") sync.Status = "Failed";
                    break;
            }
            await db.SaveChangesAsync();
        }
        using var response = await client.SendAsync(request);
        Assert.Equal(expected, response.StatusCode); Assert.Equal(0, reader.Calls);
        // Disabling the principal changes the antiforgery identity before the endpoint can run.
        if (fault == "disabled") Assert.Contains("AntiforgeryRejected", await response.Content.ReadAsStringAsync());
        await using var verify = Db();
        Assert.False(await verify.Plans.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == EnrollmentGrantPlanContract.Action));
        Assert.False(await verify.EnrollmentGrantRecipientReservations.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.False(await verify.Approvals.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.False(await verify.Audit.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action.StartsWith("EnrollmentGrantPlan.")));
        Assert.False(await verify.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
    }

    [Fact]
    public async Task ExactlyFifteenMinuteDirectorySnapshotCanProposeWithCanonicalTenMinuteExpiry()
    {
        var seeded = await Seed(); var reader = ResolvedReader(seeded);
        await using (var db = Db())
        {
            (await db.DirectorySync.SingleAsync(x => x.EnvironmentId == seeded.Data.Environment.Id)).CompletedAt = seeded.Now.AddMinutes(-15);
            await db.SaveChangesAsync();
        }
        using var factory = Factory(reader, seeded.Now); using var client = Client(factory, seeded.Data.RequesterToken);
        var response = await Post(client, CreatePath(seeded), Body(seeded, Guid.NewGuid()));
        Assert.Equal(HttpStatusCode.Created, response.Status);
        Assert.Equal(seeded.Now.AddMinutes(10), response.Json.GetProperty("expiresAt").GetDateTimeOffset());
        Assert.Equal(seeded.Now, response.Json.GetProperty("queriedAt").GetDateTimeOffset());
        Assert.Equal(1, reader.Calls);
    }

    [Theory]
    [InlineData("disabled", HttpStatusCode.NotFound)]
    [InlineData("membership", HttpStatusCode.NotFound)]
    [InlineData("manage", HttpStatusCode.NotFound)]
    [InlineData("generation", HttpStatusCode.Conflict)]
    [InlineData("scope", HttpStatusCode.NotFound)]
    public async Task PublicAuthorizationDriftDuringResolverCannotCommitAProposal(string fault, HttpStatusCode expected)
    {
        var seeded = await Seed();
        var reader = new AsyncReader(async (env, directory) =>
        {
            await using var db = Db();
            if (fault == "disabled") (await db.Principals.SingleAsync(x => x.Id == seeded.Data.Requester.Id)).Enabled = false;
            if (fault == "membership") (await db.Memberships.SingleAsync(x => x.EnvironmentId == env && x.PrincipalId == seeded.Data.Requester.Id)).Active = false;
            if (fault == "manage") db.RolePermissions.Remove(await db.RolePermissions.SingleAsync(x => x.EnvironmentId == env && x.RoleId == seeded.Data.RequesterRoleId && x.Permission == PermissionCatalog.AgentEnrollmentGrantManage));
            if (fault == "generation")
            {
                var next = Guid.NewGuid();
                (await db.DirectorySync.SingleAsync(x => x.EnvironmentId == env)).Generation = next;
                (await db.DirectoryObjects.SingleAsync(x => x.EnvironmentId == env && x.Id == directory)).Generation = next;
            }
            if (fault == "scope")
            {
                var scope = await db.Scopes.SingleAsync(x => x.EnvironmentId == env && x.Id == seeded.Data.AllScopeId);
                scope.Kind = ScopeKind.Department; scope.Value = "No matching department";
            }
            await db.SaveChangesAsync();
            return EnrollmentTargetResult.Resolved(env, directory, seeded.DeviceId, seeded.Now.AddMinutes(-1));
        });
        using var factory = Factory(reader, seeded.Now); using var client = Client(factory, seeded.Data.RequesterToken);
        var response = await Post(client, CreatePath(seeded), Body(seeded, Guid.NewGuid()));
        Assert.Equal(expected, response.Status); Assert.Equal(1, reader.Calls);
        await using var verify = Db();
        Assert.False(await verify.Plans.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action == EnrollmentGrantPlanContract.Action));
        Assert.False(await verify.EnrollmentGrantRecipientReservations.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
        Assert.False(await verify.Audit.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id && x.Action.StartsWith("EnrollmentGrantPlan.")));
        Assert.False(await verify.Outbox.AnyAsync(x => x.EnvironmentId == seeded.Data.Environment.Id));
    }
}
