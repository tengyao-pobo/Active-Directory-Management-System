using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;
using System.Text.Json;

namespace ItManagement.Api;

public static class DeviceUserLinkApi
{
    public sealed record UpdateLink([property: System.Text.Json.Serialization.JsonRequired] Guid? UserId);
    private sealed record Cursor(Guid Environment, Guid Actor, Guid User, Guid Generation, Guid After);
    public static void MapDeviceUserLinks(this WebApplication app)
    {
        app.MapGet("/api/v1/environments/{environmentId:guid}/devices/{id:guid}/user", async
            (Guid environmentId, Guid id, HttpContext http, ConsoleDbContext db, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            var (status, generation) = await Generation(db, environmentId, actor, ct);
            if (status != 200) return Results.StatusCode(status);
            if (!await Visible(db, environmentId, actor, id, "Computer", generation, ct)) return Results.NotFound();
            var row = await db.DeviceUserLinks.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == id, ct);
            if (row?.UserId is Guid user && !await Visible(db, environmentId, actor, user, "User", generation, ct)) return Results.NotFound();
            var target = row?.UserId is Guid userId ? await db.DirectoryObjects.SingleAsync(x => x.EnvironmentId == environmentId && x.Id == userId && x.Generation == generation, ct) : null;
            http.Response.Headers.ETag = $"\"{row?.Version ?? 0}\"";
            return Results.Ok(new { user = target is null ? null : new { target.Id, target.Name }, version = row?.Version ?? 0,
                row?.UpdatedAt, source = "Manual", canEdit = await Editable(db, environmentId, actor, id, generation, ct) });
        });
        app.MapPut("/api/v1/environments/{environmentId:guid}/devices/{id:guid}/user", async
            (Guid environmentId, Guid id, UpdateLink input, HttpContext http, ConsoleDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            var (status, generation) = await Generation(db, environmentId, actor, ct);
            if (status != 200) return Results.StatusCode(status);
            if (!await Visible(db, environmentId, actor, id, "Computer", generation, ct)) return Results.NotFound();
            if (!await Editable(db, environmentId, actor, id, generation, ct)) return Results.Forbid();
            var row = await db.DeviceUserLinks.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == id, ct);
            // Both the old and new user must be visible: replacing a hidden link is not an authorization bypass.
            if (row?.UserId is Guid old && !await Visible(db, environmentId, actor, old, "User", generation, ct)) return Results.NotFound();
            if (input.UserId is Guid next && !await Visible(db, environmentId, actor, next, "User", generation, ct)) return Results.NotFound();
            if (!http.Request.Headers.ContainsKey("If-Match")) return Results.StatusCode(428);
            if (http.Request.Headers.IfMatch.ToString() != $"\"{row?.Version ?? 0}\"") return Results.StatusCode(412);
            if (row is null) { row = new() { EnvironmentId = environmentId, Id = id }; db.DeviceUserLinks.Add(row); }
            row.UserId = input.UserId; row.Version++; row.UpdatedAt = time.GetUtcNow();
            db.Audit.Add(new() { EnvironmentId = environmentId, Id = Guid.NewGuid(), ActorId = actor, TargetId = id.ToString(),
                Action = "Device.PrimaryUserUpdated", Result = "Success", Reason = $"source:Manual;version:{row.Version}",
                OccurredAt = row.UpdatedAt, CorrelationId = http.TraceIdentifier });
            try { await db.SaveChangesAsync(ct); await tx.CommitAsync(ct); }
            catch (Exception error) when (Conflict(error)) { return Results.StatusCode(409); }
            http.Response.Headers.ETag = $"\"{row.Version}\"";
            return Results.NoContent();
        });
        app.MapGet("/api/v1/environments/{environmentId:guid}/users/{id:guid}/devices", async
            (Guid environmentId, Guid id, string? cursor, HttpContext http, ConsoleDbContext db, IDataProtectionProvider protection, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            var (status, generation) = await Generation(db, environmentId, actor, ct);
            if (status != 200) return Results.StatusCode(status);
            if (!await Visible(db, environmentId, actor, id, "User", generation, ct)) return Results.NotFound();
            var protector = protection.CreateProtector("DeviceUserLinkCursor.v1");
            Guid? after = null;
            if (cursor is not null)
            {
                if (cursor.Length > 4096) return Results.BadRequest();
                Cursor? position;
                try { position = JsonSerializer.Deserialize<Cursor>(protector.Unprotect(cursor)); }
                catch (Exception error) when (error is CryptographicException or JsonException or FormatException) { return Results.BadRequest(); }
                if (position is null || position.Environment != environmentId || position.Actor != actor || position.User != id) return Results.BadRequest();
                if (position.Generation != generation) return Results.StatusCode(409);
                after = position.After;
            }
            var computers = (await DirectoryApi.Scoped(db, environmentId, actor, PermissionCatalog.ComputerView, generation, ct)).Where(x => x.Kind == "Computer");
            var query = from link in db.DeviceUserLinks join computer in computers on new { link.EnvironmentId, link.Id } equals new { computer.EnvironmentId, computer.Id }
                where link.EnvironmentId == environmentId && link.UserId == id && (after == null || link.Id.CompareTo(after.Value) > 0)
                orderby link.Id select new { computer.Id, computer.Name, link.UpdatedAt };
            var rows = await query.Take(51).ToListAsync(ct); var more = rows.Count > 50;
            if (more) rows.RemoveAt(50);
            return Results.Ok(new { items = rows, nextCursor = more ? protector.Protect(JsonSerializer.Serialize(new Cursor(environmentId, actor, id, generation, rows[^1].Id))) : null, source = "Manual" });
        });
    }
    private static bool Conflict(Exception error)
    {
        if (error is DbUpdateConcurrencyException) return true;
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is Npgsql.PostgresException { SqlState: "40001" } or Npgsql.PostgresException { SqlState: "23505", ConstraintName: "PK_DeviceUserLinks" }) return true;
        return false;
    }
    private static async Task<(int, Guid)> Generation(ConsoleDbContext db, Guid env, Guid actor, CancellationToken ct)
    {
        if (!await db.Memberships.AnyAsync(x => x.EnvironmentId == env && x.PrincipalId == actor && x.Active, ct)) return (404, Guid.Empty);
        var sync = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == env, ct);
        return sync?.Status == "Ready" && sync.CompletedAt >= DateTimeOffset.UtcNow.AddMinutes(-15) ? (200, sync.Generation) : (503, Guid.Empty);
    }
    private static async Task<bool> Visible(ConsoleDbContext db, Guid env, Guid actor, Guid id, string kind, Guid generation, CancellationToken ct) =>
        await (await DirectoryApi.Scoped(db, env, actor, kind == "User" ? PermissionCatalog.UserView : PermissionCatalog.ComputerView, generation, ct))
            .AnyAsync(x => x.Id == id && x.Kind == kind, ct);
    // Inert manual association only. Never drives AD, remote actions, inventory or automation.
    private static async Task<bool> Editable(ConsoleDbContext db, Guid env, Guid actor, Guid id, Guid generation, CancellationToken ct) =>
        await (await DirectoryApi.Scoped(db, env, actor, PermissionCatalog.AssetEdit, generation, ct)).AnyAsync(x => x.Id == id && x.Kind == "Computer" && !x.IsProtected, ct);
}
