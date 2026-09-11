using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text.Json;

namespace ItManagement.Api;

public static class DeviceAuditApi
{
    private sealed record Cursor(Guid Environment, Guid Actor, Guid Computer, Guid Generation, DateTimeOffset At, Guid Id);
    public static void MapDeviceAudit(this WebApplication app) => app.MapGet("/api/v1/environments/{environmentId:guid}/devices/{id:guid}/audit", async
        (Guid environmentId, Guid id, string? cursor, HttpContext http, ConsoleDbContext db, IDataProtectionProvider protection, CancellationToken ct) =>
    {
        var actor = AuthEndpoints.Actor(http);
        await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        if (!await db.Memberships.AnyAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor && x.Active, ct)) return Results.NotFound();
        var sync = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId, ct);
        if (sync?.Status != "Ready" || sync.CompletedAt is null || sync.CompletedAt < DateTimeOffset.UtcNow.AddMinutes(-15)) return Results.StatusCode(503);
        foreach (var permission in new[] { PermissionCatalog.ComputerView, PermissionCatalog.AuditView })
            if (!await (await DirectoryApi.Scoped(db, environmentId, actor, permission, sync.Generation, ct)).AnyAsync(x => x.Id == id && x.Kind == "Computer", ct)) return Results.NotFound();
        var protector = protection.CreateProtector("DeviceAuditCursor.v1"); Cursor? position = null;
        if (cursor is not null)
        {
            if (cursor.Length > 4096) return Results.BadRequest();
            try { position = JsonSerializer.Deserialize<Cursor>(protector.Unprotect(cursor)); }
            catch (Exception error) when (error is CryptographicException or JsonException or FormatException) { return Results.BadRequest(); }
            if (position is null || position.Environment != environmentId || position.Actor != actor || position.Computer != id) return Results.BadRequest();
            if (position.Generation != sync.Generation) return Results.StatusCode(409);
        }
        var target = id.ToString();
        var query = db.Audit.Where(x => x.EnvironmentId == environmentId && x.TargetId == target &&
            (x.Action == "Device.AssetUpdated" || x.Action == "Device.PrimaryUserUpdated"));
        if (position is not null) query = query.Where(x => x.OccurredAt < position.At || (x.OccurredAt == position.At && x.Id.CompareTo(position.Id) < 0));
        var rows = await query.OrderByDescending(x => x.OccurredAt).ThenByDescending(x => x.Id)
            .Select(x => new { x.Id, x.Action, x.Result, x.OccurredAt }).Take(51).ToListAsync(ct);
        var more = rows.Count > 50; if (more) rows.RemoveAt(50);
        var next = more ? protector.Protect(JsonSerializer.Serialize(new Cursor(environmentId, actor, id, sync.Generation, rows[^1].OccurredAt, rows[^1].Id))) : null;
        return Results.Ok(new { items = rows, nextCursor = next });
    });
}
