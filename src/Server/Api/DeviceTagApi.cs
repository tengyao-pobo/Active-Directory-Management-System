using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

public static class DeviceTagApi
{
    public static void MapDeviceTags(this WebApplication app)
    {
        var group = app.MapGroup("/api/v1/environments/{environmentId:guid}");
        group.MapGet("/device-tags", async (Guid environmentId, HttpContext http, ConsoleDbContext db, EnvironmentAccess access, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await db.Memberships.AnyAsync(m => m.EnvironmentId == environmentId && m.PrincipalId == actor && m.Active, ct)) return Results.NotFound();
            var items = await db.DeviceTags.Where(t => t.EnvironmentId == environmentId).OrderBy(t => t.Key)
                .Select(t => new { t.Id, t.Key, t.Version, t.ArchivedAt }).Take(8).ToListAsync(ct);
            return Results.Ok(new { items, version = await db.Environments.Where(e => e.Id == environmentId).Select(e => e.Version).SingleAsync(ct),
                canManage = await DeviceTagChanges.Allows(db, access, environmentId, actor, ct),
                canApprove = await access.Allows(environmentId, actor, PermissionCatalog.ChangeApprove, ct) });
        });
        group.MapGet("/devices/{objectId:guid}/tags", async (Guid environmentId, Guid objectId, HttpContext http, ConsoleDbContext db, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await db.Memberships.AnyAsync(m => m.EnvironmentId == environmentId && m.PrincipalId == actor && m.Active, ct)) return Results.NotFound();
            var state = await db.DirectorySync.SingleOrDefaultAsync(s => s.EnvironmentId == environmentId, ct);
            if (state?.Status != "Ready" || state.CompletedAt is null || state.CompletedAt < DateTimeOffset.UtcNow.AddMinutes(-15))
                return Results.Problem(statusCode: 503, title: "DirectoryUnavailable");
            var scoped = await DirectoryApi.Scoped(db, environmentId, actor, PermissionCatalog.ComputerView, state.Generation, ct);
            if (!await scoped.AnyAsync(d => d.Id == objectId && d.Kind == "Computer", ct)) return Results.NotFound();
            var items = await (from a in db.DeviceTagAssignments join t in db.DeviceTags
                               on new { a.EnvironmentId, Id = a.TagId } equals new { t.EnvironmentId, t.Id }
                               where a.EnvironmentId == environmentId && a.ObjectId == objectId
                               orderby t.Key select new { t.Id, t.Key, t.ArchivedAt }).Take(8).ToListAsync(ct);
            return Results.Ok(new { items });
        });
        group.MapGet("/device-tags/plans", async (Guid environmentId, HttpContext http, ConsoleDbContext db, EnvironmentAccess access, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            var approve = await access.Allows(environmentId, actor, PermissionCatalog.ChangeApprove, ct);
            if (!approve && !await DeviceTagChanges.Allows(db, access, environmentId, actor, ct)) return Results.NotFound();
            var rows = await db.Plans.Where(p => p.EnvironmentId == environmentId && p.Action.StartsWith("device-tag.") &&
                (approve || p.RequesterId == actor)).OrderByDescending(p => p.ExpiresAt).ThenBy(p => p.Id).Take(100).ToListAsync(ct);
            return Results.Ok(new { items = rows.Select(EnvironmentApi.PlanDto), queriedAt = DateTimeOffset.UtcNow });
        });
    }
}
