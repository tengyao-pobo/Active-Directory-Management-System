using System.Text.Json;
using System.Text.RegularExpressions;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

public sealed class EnvironmentAccess(ConsoleDbContext db, AuthorizationEvaluator evaluator)
{
    public async Task<bool> Allows(Guid env, Guid actor, string permission, CancellationToken ct)
    {
        var resource = new ResourceScope(env, env.ToString(), null, new HashSet<string>(), new HashSet<string>(), new HashSet<string>(), false, ProtectionKnown: true);
        return evaluator.IsAllowed(env, actor, permission, resource,
            await db.Principals.Where(x => x.Id == actor).ToListAsync(ct),
            await db.Memberships.Where(x => x.EnvironmentId == env && x.PrincipalId == actor).ToListAsync(ct),
            await db.Roles.Where(x => x.EnvironmentId == env).ToListAsync(ct),
            await db.RolePermissions.Where(x => x.EnvironmentId == env).ToListAsync(ct),
            await db.Scopes.Where(x => x.EnvironmentId == env).ToListAsync(ct),
            await db.Assignments.Where(x => x.EnvironmentId == env && x.PrincipalId == actor).ToListAsync(ct));
    }
}

// Typed management intent: never accepts a script, raw SQL, arbitrary fields or credentials.
public sealed record ManagementChange(string Kind, string? Name = null, string? CanonicalDns = null,
    string? DefaultLocale = null, Guid? RoleId = null, Guid? PrincipalId = null, Guid? ScopeId = null,
    Guid? AssignmentId = null, ScopeKind? ScopeKind = null, string? ScopeValue = null,
    bool IncludeDescendants = false, string? GroupSid = null, string[]? Permissions = null,
    Guid? TagId = null, string? TagKey = null, Guid? ObjectId = null, long? ExpectedTagVersion = null);
public sealed record PlanRequest(ManagementChange Change, long ExpectedVersion, string Reason);
public sealed record ApprovalRequest(string PlanHash);

public static class EnvironmentApi
{
    public static void MapEnvironmentApi(this WebApplication app)
    {
        app.MapGet("/api/v1/environments", async (HttpContext http, ConsoleDbContext db, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT set_config('app.principal_id', {actor.ToString()}, true)", ct);
            var rows = await (from m in db.Memberships where m.PrincipalId == actor && m.Active
                              join e in db.Environments on m.EnvironmentId equals e.Id
                              orderby e.Name, e.Id select new { e.Id, e.Name, e.CanonicalDns, e.DefaultLocale, e.Version }).Take(200).ToListAsync(ct);
            await tx.CommitAsync(ct);
            return Results.Ok(new { items = rows });
        });
        var group = app.MapGroup("/api/v1/environments/{environmentId:guid}");
        group.MapGet("/access", async (Guid environmentId, HttpContext http, ConsoleDbContext db, EnvironmentAccess access, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await db.Memberships.AnyAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor && x.Active, ct)) return Results.NotFound();
            var permissions = new List<string>();
            foreach (var p in PermissionCatalog.All.Order()) if (await access.Allows(environmentId, actor, p, ct)) permissions.Add(p);
            return Results.Ok(new { permissions });
        });
        group.MapGet("/rbac", async (Guid environmentId, HttpContext http, ConsoleDbContext db, EnvironmentAccess access, CancellationToken ct) =>
        {
            await using var tx = await db.BeginEnvironment(environmentId, AuthEndpoints.Actor(http), ct);
            if (!await access.Allows(environmentId, AuthEndpoints.Actor(http), PermissionCatalog.RbacManage, ct)) return Results.NotFound();
            return Results.Ok(new
            {
                roles = await db.Roles.Where(x => x.EnvironmentId == environmentId).ToListAsync(ct),
                permissions = await db.RolePermissions.Where(x => x.EnvironmentId == environmentId).ToListAsync(ct),
                scopes = await db.Scopes.Where(x => x.EnvironmentId == environmentId).ToListAsync(ct),
                assignments = await db.Assignments.Where(x => x.EnvironmentId == environmentId).ToListAsync(ct),
                groupMappings = await db.GroupMappings.Where(x => x.EnvironmentId == environmentId).ToListAsync(ct)
            });
        });
        group.MapGet("/audit", async (Guid environmentId, string? cursor, int? limit, HttpContext http, ConsoleDbContext db, EnvironmentAccess access, CancellationToken ct) =>
        {
            AuditCursor? position = null;
            if (cursor is not null)
            {
                if (cursor.Length > 512) return Results.BadRequest();
                try { position = JsonSerializer.Deserialize<AuditCursor>(Convert.FromBase64String(cursor)); }
                catch (Exception e) when (e is FormatException or JsonException) { return Results.BadRequest(); }
                if (position is null) return Results.BadRequest();
            }
            await using var tx = await db.BeginEnvironment(environmentId, AuthEndpoints.Actor(http), ct);
            if (!await access.Allows(environmentId, AuthEndpoints.Actor(http), PermissionCatalog.AuditView, ct)) return Results.NotFound();
            var take = Math.Clamp(limit ?? 50, 1, 200);
            var query = db.Audit.Where(x => x.EnvironmentId == environmentId);
            if (position is not null) query = query.Where(x => x.OccurredAt < position.At || (x.OccurredAt == position.At && x.Id.CompareTo(position.Id) < 0));
            var rows = await query.OrderByDescending(x => x.OccurredAt).ThenByDescending(x => x.Id).Take(take + 1).ToListAsync(ct);
            var items = rows.Take(take).ToList();
            var nextCursor = rows.Count > take ? Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new AuditCursor(items[^1].OccurredAt, items[^1].Id))) : null;
            return Results.Ok(new { items, nextCursor });
        });

        group.MapPost("/change-plans", async (Guid environmentId, PlanRequest input, HttpContext http, ConsoleDbContext db,
            EnvironmentAccess access, ChangePlanService plans, TimeProvider time, ConsoleOptions config, CancellationToken ct) =>
        {
            if (input.Change is null || input.Reason is not { Length: >= 5 and <= 512 })
                return Results.Problem(statusCode: 400, title: "InvalidPlanRequest");
            var error = Validate(input.Change);
            if (error is not null) return Results.Problem(statusCode: 400, title: error);
            await using var tx = await db.BeginEnvironment(environmentId, AuthEndpoints.Actor(http), ct);
            if (!await access.Allows(environmentId, AuthEndpoints.Actor(http), Permission(input.Change), ct)) return Results.NotFound();
            if (DeviceTagChanges.IsTagChange(input.Change) && !await DeviceTagChanges.Allows(db, access, environmentId, AuthEndpoints.Actor(http), ct)) return Results.NotFound();
            if (!AuthEndpoints.FreshStepUp(http, time, config)) return Results.Problem(statusCode: 403, title: "StepUpRequired");
            var env = await db.Environments.SingleAsync(x => x.Id == environmentId, ct);
            if (env.Version != input.ExpectedVersion) return Results.Problem(statusCode: 412, title: "StaleVersion");
            // The immutable plan contains the server-generated identity that execution will use.
            if (input.Change.Kind == "device-tag.create") input = input with { Change = input.Change with { TagId = Guid.NewGuid() } };
            var tagError = await DeviceTagChanges.Check(db, environmentId, input.Change, time.GetUtcNow(), ct);
            if (tagError is not null) return Results.Problem(statusCode: 409, title: tagError);
            var plan = plans.Create(environmentId, Guid.NewGuid(), AuthEndpoints.Actor(http), input.Change.Kind,
                JsonSerializer.Serialize(input.Change), env.Version, time.GetUtcNow().AddMinutes(15),
                [new ChangePlanItem { Id = Guid.NewGuid(), TargetId = environmentId.ToString(), ExpectedVersion = env.Version }], input.Reason);
            db.Plans.Add(plan);
            Audit(db, http, time, environmentId, "ChangePlan.Created", plan.Id.ToString(), "PendingApproval");
            await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
            return Results.Created($"/api/v1/environments/{environmentId}/change-plans/{plan.Id}", PlanDto(plan));
        });
        group.MapGet("/change-plans/{id:guid}", async (Guid environmentId, Guid id, HttpContext http, ConsoleDbContext db, EnvironmentAccess access, CancellationToken ct) =>
        {
            await using var tx = await db.BeginEnvironment(environmentId, AuthEndpoints.Actor(http), ct);
            if (!await access.Allows(environmentId, AuthEndpoints.Actor(http), PermissionCatalog.ChangeApprove, ct)) return Results.NotFound();
            var plan = await db.Plans.Include(x => x.Items).SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == id, ct);
            return plan is null ? Results.NotFound() : Results.Ok(PlanDto(plan));
        });
        group.MapPost("/change-plans/{id:guid}/approval", async (Guid environmentId, Guid id, ApprovalRequest input, HttpContext http, ConsoleDbContext db,
            EnvironmentAccess access, ChangePlanService plans, TimeProvider time, ConsoleOptions config, CancellationToken ct) =>
        {
            if (input.PlanHash is not { Length: 64 }) return Results.BadRequest();
            await using var tx = await db.BeginEnvironment(environmentId, AuthEndpoints.Actor(http), ct);
            if (!await access.Allows(environmentId, AuthEndpoints.Actor(http), PermissionCatalog.ChangeApprove, ct)) return Results.NotFound();
            if (!AuthEndpoints.FreshStepUp(http, time, config)) return Results.Problem(statusCode: 403, title: "StepUpRequired");
            var plan = await db.Plans.Include(x => x.Items).SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == id, ct);
            if (plan is null) return Results.NotFound();
            if (!await DistinctOperators(db, plan.RequesterId, AuthEndpoints.Actor(http), ct))
                return Results.Problem(statusCode: 409, title: "IndependentOperatorRequired");
            ChangeApproval approval;
            try { approval = plans.Approve(plan, Guid.NewGuid(), AuthEndpoints.Actor(http), input.PlanHash, time.GetUtcNow(), plan.ExpiresAt); }
            catch (InvalidOperationException) { return Results.Problem(statusCode: 409, title: "ApprovalRejected"); }
            db.Approvals.Add(approval);
            Audit(db, http, time, environmentId, "ChangePlan.Approved", plan.Id.ToString(), "Approved");
            await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
            return Results.Ok(PlanDto(plan));
        });
        group.MapPost("/change-plans/{id:guid}/execution", Execute);
    }

    private static async Task<IResult> Execute(Guid environmentId, Guid id, HttpContext http, ConsoleDbContext db,
        EnvironmentAccess access, ChangePlanService plans, TimeProvider time, ConsoleOptions config, CancellationToken ct)
    {
        var actor = AuthEndpoints.Actor(http);
        await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        if (!AuthEndpoints.FreshStepUp(http, time, config)) return Results.Problem(statusCode: 403, title: "StepUpRequired");
        var plan = await db.Plans.Include(x => x.Items).SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == id, ct);
        if (plan is null || plan.RequesterId != actor) return Results.NotFound();
        var approval = await db.Approvals.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PlanId == id, ct);
        if (approval is null) return Results.Problem(statusCode: 409, title: "ApprovalRequired");
        if (!await DistinctOperators(db, actor, approval.ApproverId, ct))
            return Results.Problem(statusCode: 409, title: "IndependentOperatorRequired");
        var change = JsonSerializer.Deserialize<ManagementChange>(plan.ImmutablePlanJson)!;
        if (Validate(change) is not null) return Results.BadRequest();
        if (!await access.Allows(environmentId, actor, Permission(change), ct) ||
            !await access.Allows(environmentId, approval.ApproverId, PermissionCatalog.ChangeApprove, ct)) return Results.NotFound();
        if (DeviceTagChanges.IsTagChange(change) && !await DeviceTagChanges.Allows(db, access, environmentId, actor, ct)) return Results.NotFound();
        var env = await db.Environments.SingleAsync(x => x.Id == environmentId, ct);
        if (!plans.ValidateForExecution(plan, approval, env.Version, new Dictionary<string, long> { [environmentId.ToString()] = env.Version }, time.GetUtcNow()).IsValid)
            return Results.Problem(statusCode: 409, title: "PlanChangedOrExpired");
        var invalid = await DeviceTagChanges.Check(db, environmentId, change, time.GetUtcNow(), ct);
        if (invalid is not null) return Results.Problem(statusCode: 409, title: invalid);
        if (DeviceTagChanges.IsTagChange(change)) await DeviceTagChanges.Apply(db, environmentId, change, actor, time.GetUtcNow(), ct);
        else invalid = await Apply(db, env, change, ct);
        if (invalid is not null) return Results.Problem(statusCode: 409, title: invalid);
        env.Version++;
        plan.State = ChangePlanState.Executed;
        Audit(db, http, time, environmentId, "ChangePlan.Executed", plan.Id.ToString(), "Success");
        db.Outbox.Add(new OutboxMessage { EnvironmentId = environmentId, Id = Guid.NewGuid(), EventType = "EnvironmentChanged", Version = 1,
            Payload = JsonSerializer.Serialize(new { environmentId, planId = id, version = env.Version }), CreatedAt = time.GetUtcNow() });
        await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
        return Results.Ok(new { plan.Id, state = plan.State.ToString(), version = env.Version });
    }

    private static async Task<string?> Apply(ConsoleDbContext db, ManagedEnvironment env, ManagementChange c, CancellationToken ct)
    {
        switch (c.Kind)
        {
            case "environment.update":
                env.Name = c.Name!; env.CanonicalDns = c.CanonicalDns!; env.DefaultLocale = c.DefaultLocale!; break;
            case "role.create":
                if (await db.Roles.AnyAsync(x => x.EnvironmentId == env.Id && x.Name == c.Name, ct)) return "RoleExists";
                var role = new Role { EnvironmentId = env.Id, Id = Guid.NewGuid(), Name = c.Name!, BuiltInKind = null };
                db.Roles.Add(role);
                foreach (var p in c.Permissions!.Distinct()) db.RolePermissions.Add(new RolePermission { EnvironmentId = env.Id, RoleId = role.Id, Permission = p });
                break;
            case "scope.create":
                db.Scopes.Add(new Scope { EnvironmentId = env.Id, Id = Guid.NewGuid(), Kind = c.ScopeKind!.Value, Value = c.ScopeValue, IncludeDescendants = c.IncludeDescendants }); break;
            case "membership.add":
                if (!await db.Principals.AnyAsync(x => x.Id == c.PrincipalId && x.Enabled, ct)) return "PrincipalUnavailable";
                if (await db.Memberships.AnyAsync(x => x.EnvironmentId == env.Id && x.PrincipalId == c.PrincipalId, ct)) return "MembershipExists";
                db.Memberships.Add(new EnvironmentMembership { EnvironmentId = env.Id, PrincipalId = c.PrincipalId!.Value, Active = true }); break;
            case "assignment.add":
            case "group-mapping.add":
                var selected = await db.Roles.SingleOrDefaultAsync(x => x.EnvironmentId == env.Id && x.Id == c.RoleId, ct);
                if (selected is null || selected.BuiltInKind == BuiltInRoleKinds.Owner) return "OwnerAssignmentRequiresDedicatedWorkflow";
                if (!await db.Scopes.AnyAsync(x => x.EnvironmentId == env.Id && x.Id == c.ScopeId, ct)) return "ScopeUnavailable";
                if (c.Kind == "group-mapping.add")
                {
                    if (!RolePolicy.CanUseForDirectoryGroupMapping(selected)) return "MappingRejected";
                    db.GroupMappings.Add(new DirectoryGroupMapping { EnvironmentId = env.Id, Id = Guid.NewGuid(), GroupSid = c.GroupSid!, RoleId = selected.Id, ScopeId = c.ScopeId!.Value });
                }
                else
                {
                    if (!await db.Memberships.AnyAsync(x => x.EnvironmentId == env.Id && x.PrincipalId == c.PrincipalId && x.Active, ct)) return "MembershipUnavailable";
                    db.Assignments.Add(new RoleAssignment { EnvironmentId = env.Id, Id = Guid.NewGuid(), PrincipalId = c.PrincipalId!.Value, RoleId = selected.Id, ScopeId = c.ScopeId!.Value });
                }
                break;
            case "assignment.remove":
                var assignment = await db.Assignments.SingleOrDefaultAsync(x => x.EnvironmentId == env.Id && x.Id == c.AssignmentId, ct);
                if (assignment is null) return "AssignmentUnavailable";
                if (await db.Roles.AnyAsync(x => x.EnvironmentId == env.Id && x.Id == assignment.RoleId && x.BuiltInKind == BuiltInRoleKinds.Owner, ct)) return "OwnerRemovalRequiresDedicatedWorkflow";
                db.Assignments.Remove(assignment); break;
            default: return "UnsupportedChange";
        }
        return null;
    }
    private static string Permission(ManagementChange c) => DeviceTagChanges.IsTagChange(c) ? PermissionCatalog.DeviceTagManage :
        c.Kind == "environment.update" ? PermissionCatalog.EnvironmentManage : PermissionCatalog.RbacManage;
    private sealed record AuditCursor(DateTimeOffset At, Guid Id);
    private static async Task<bool> DistinctOperators(ConsoleDbContext db, Guid requester, Guid approver, CancellationToken ct)
    {
        var people = await db.Principals.Where(x => x.Id == requester || x.Id == approver).Select(x => x.OperatorId).ToListAsync(ct);
        return people.Count == 2 && people.All(x => x != Guid.Empty) && people.Distinct().Count() == 2;
    }
    private static string? Validate(ManagementChange c) => c.Kind switch
    {
        _ when DeviceTagChanges.Valid(c) => null,
        "environment.update" when c.Name?.Length is > 0 and <= 160 && c.CanonicalDns?.Length is > 0 and <= 253 &&
            Uri.CheckHostName(c.CanonicalDns) == UriHostNameType.Dns && c.DefaultLocale is "zh-TW" or "en-US" => null,
        "role.create" when c.Name?.Length is > 0 and <= 128 && !new[] { "Owner", "Admin", "Manager", "Member", "Viewer", "HR" }.Contains(c.Name, StringComparer.OrdinalIgnoreCase) &&
            c.Permissions is { Length: > 0 and <= 100 } && c.Permissions.All(p => PermissionCatalog.IsKnown(p) && !PermissionCatalog.IsOwnerOnly(p)) => null,
        "scope.create" when c.ScopeKind is { } k && Enum.IsDefined(k) &&
            (k == ScopeKind.DeviceTag ? DeviceTagCatalog.IsCanonicalId(c.ScopeValue) && !c.IncludeDescendants :
                k == ScopeKind.All ? c.ScopeValue is null : c.ScopeValue?.Length is > 0 and <= 256) => null,
        "membership.add" when c.PrincipalId is { } p && p != Guid.Empty => null,
        "assignment.add" when c.PrincipalId is not null && c.RoleId is not null && c.ScopeId is not null => null,
        "assignment.remove" when c.AssignmentId is not null => null,
        "group-mapping.add" when c.RoleId is not null && c.ScopeId is not null && c.GroupSid is { Length: < 256 } sid && Regex.IsMatch(sid, "^S-1-[0-9]+(-[0-9]+)+$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50)) => null,
        _ => "InvalidManagementChange"
    };
    internal static object PlanDto(ChangePlan p) => new { p.Id, p.EnvironmentId, p.RequesterId, p.Action, change = JsonSerializer.Deserialize<ManagementChange>(p.ImmutablePlanJson), p.PlanHash, p.PolicyVersion, p.ExpiresAt, state = p.State.ToString(), p.Reason };
    private static void Audit(ConsoleDbContext db, HttpContext http, TimeProvider time, Guid env, string action, string target, string result) =>
        db.Audit.Add(new AuditRecord { EnvironmentId = env, Id = Guid.NewGuid(), ActorId = AuthEndpoints.Actor(http), Action = action, TargetId = target,
            Result = result, OccurredAt = time.GetUtcNow(), SourceIp = http.Connection.RemoteIpAddress?.ToString(), CorrelationId = http.TraceIdentifier });
}
