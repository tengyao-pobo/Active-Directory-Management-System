using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text.Json;

namespace ItManagement.Api;

public static class DashboardApi
{
    private sealed record Cursor(Guid Environment, Guid Actor, Guid Generation, Guid After);
    public static void MapDashboard(this WebApplication app) => app.MapGet("/api/v1/environments/{environmentId:guid}/dashboard", async
        (Guid environmentId, string? cursor, HttpContext http, ConsoleDbContext db, IDataProtectionProvider protection, CancellationToken ct) =>
    {
        var actor = AuthEndpoints.Actor(http);
        await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        if (!await db.Memberships.AnyAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor && x.Active, ct)) return Results.NotFound();
        var sync = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId, ct);
        if (sync?.Status != "Ready" || sync.CompletedAt is null || sync.CompletedAt < DateTimeOffset.UtcNow.AddMinutes(-15))
            return Results.Problem(statusCode: 503, title: "DirectoryUnavailable");
        var protector = protection.CreateProtector("DashboardRepairCursor.v1");
        Guid? after = null;
        if (cursor is not null)
        {
            if (cursor.Length > 4096) return Results.BadRequest();
            Cursor? position;
            try { position = JsonSerializer.Deserialize<Cursor>(protector.Unprotect(cursor)); }
            catch (Exception error) when (error is CryptographicException or JsonException or FormatException) { return Results.BadRequest(); }
            if (position is null || position.Environment != environmentId || position.Actor != actor) return Results.BadRequest();
            if (position.Generation != sync.Generation) return Results.StatusCode(409);
            after = position.After;
        }
        var counts = new Dictionary<string, int>();
        foreach (var (kind, permission) in new[] { ("User", PermissionCatalog.UserView), ("Group", PermissionCatalog.GroupView), ("Computer", PermissionCatalog.ComputerView), ("OrganizationalUnit", PermissionCatalog.EnvironmentView) })
            counts[kind] = await (await DirectoryApi.Scoped(db, environmentId, actor, permission, sync.Generation, ct)).CountAsync(x => x.Kind == kind, ct);
        var computers = (await DirectoryApi.Scoped(db, environmentId, actor, PermissionCatalog.ComputerView, sync.Generation, ct)).Where(x => x.Kind == "Computer");
        // Both statistics and repair rows derive from this same scoped, current-generation query.
        var assets = from computer in computers
            join asset in db.DeviceAssets on new { computer.EnvironmentId, computer.Id } equals new { asset.EnvironmentId, asset.Id } into matched
            from asset in matched.DefaultIfEmpty()
            select new { computer.Id, computer.Name, lifecycle = asset == null ? "Unknown" : asset.Lifecycle };
        var grouped = await assets.GroupBy(x => x.lifecycle).Select(g => new { state = g.Key, count = g.Count() }).ToListAsync(ct);
        var lifecycle = new[] { "Unknown", "Active", "Spare", "Repair", "Retired" }.ToDictionary(state => state, state => grouped.SingleOrDefault(x => x.state == state)?.count ?? 0);
        var repairs = await assets.Where(x => x.lifecycle == "Repair" && (after == null || x.Id.CompareTo(after.Value) > 0)).OrderBy(x => x.Id)
            .Select(x => new { x.Id, x.Name }).Take(51).ToListAsync(ct);
        var more = repairs.Count > 50; if (more) repairs.RemoveAt(50);
        var next = more ? protector.Protect(JsonSerializer.Serialize(new Cursor(environmentId, actor, sync.Generation, repairs[^1].Id))) : null;
        return Results.Ok(new { counts, lifecycle, repairs, nextCursor = next, asOf = sync.CompletedAt, queriedAt = DateTimeOffset.UtcNow, health = "Unknown", agent = "Unknown" });
    });
}
