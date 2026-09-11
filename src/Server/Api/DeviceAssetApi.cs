using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

public static class DeviceAssetApi
{
    public sealed record UpdateAsset(string Lifecycle, string Notes);
    private static object? Dto(DeviceAsset? item) => item is null ? null : new { item.Lifecycle, item.Notes, item.Version, item.UpdatedAt };

    public static void MapDeviceAssets(this WebApplication app)
    {
        app.MapGet("/api/v1/environments/{environmentId:guid}/devices/{id:guid}/asset", async
            (Guid environmentId, Guid id, HttpContext http, ConsoleDbContext db, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            var access = await Access(db, environmentId, id, actor, ct);
            if (access.Status != 200) return Results.StatusCode(access.Status);
            var item = await db.DeviceAssets.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == id, ct);
            http.Response.Headers.ETag = $"\"{item?.Version ?? 0}\"";
            return Results.Ok(new { item = Dto(item), canEdit = access.Edit });
        });
        app.MapPut("/api/v1/environments/{environmentId:guid}/devices/{id:guid}/asset", async
            (Guid environmentId, Guid id, UpdateAsset input, HttpContext http, ConsoleDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            var access = await Access(db, environmentId, id, actor, ct);
            if (access.Status != 200) return Results.StatusCode(access.Status);
            if (!access.Edit) return Results.Forbid();
            if (!DeviceLifecycle.States.Contains(input.Lifecycle, StringComparer.Ordinal) || input.Notes is null || input.Notes.Length > 4000 || input.Notes.Any(c => char.IsControl(c) && c != '\n' && c != '\r' && c != '\t'))
                return Results.BadRequest();
            var item = await db.DeviceAssets.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == id, ct);
            if (!http.Request.Headers.ContainsKey("If-Match")) return Results.StatusCode(428);
            if (http.Request.Headers.IfMatch.ToString() != $"\"{item?.Version ?? 0}\"") return Results.StatusCode(412);
            if (item is null) { item = new DeviceAsset { EnvironmentId = environmentId, Id = id }; db.DeviceAssets.Add(item); }
            var previousLifecycle = item.Lifecycle;
            item.Lifecycle = input.Lifecycle; item.Notes = input.Notes; item.Version++;
            item.UpdatedBy = actor; item.UpdatedAt = time.GetUtcNow();
            db.Audit.Add(new AuditRecord { EnvironmentId = environmentId, Id = Guid.NewGuid(), ActorId = actor,
                Action = "Device.AssetUpdated", TargetId = id.ToString(), Result = "Success", OccurredAt = item.UpdatedAt,
                Reason = $"lifecycle:{previousLifecycle}->{item.Lifecycle};version:{item.Version}",
                CorrelationId = http.TraceIdentifier });
            try { await db.SaveChangesAsync(ct); await tx.CommitAsync(ct); }
            catch (DbUpdateException error) when (error.InnerException is Npgsql.PostgresException { SqlState: "23505", ConstraintName: "PK_DeviceAssets" })
            { return Results.StatusCode(409); }
            catch (Exception error) when (SerializationConflict(error))
            { return Results.StatusCode(409); }
            http.Response.Headers.ETag = $"\"{item.Version}\"";
            return Results.Ok(new { item = Dto(item), canEdit = true });
        });
    }

    private static bool SerializationConflict(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is Npgsql.PostgresException { SqlState: "40001" }) return true;
        return false;
    }
    private static async Task<(int Status, bool Edit)> Access(ConsoleDbContext db, Guid env, Guid id, Guid actor, CancellationToken ct)
    {
        if (!await db.Memberships.AnyAsync(x => x.EnvironmentId == env && x.PrincipalId == actor && x.Active, ct)) return (404, false);
        var sync = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == env, ct);
        if (sync?.Status != "Ready" || sync.CompletedAt is null || sync.CompletedAt < DateTimeOffset.UtcNow.AddMinutes(-15)) return (503, false);
        var visible = await DirectoryApi.Scoped(db, env, actor, PermissionCatalog.ComputerView, sync.Generation, ct);
        if (!await visible.AnyAsync(x => x.Id == id && x.Kind == "Computer", ct)) return (404, false);
        // Inert platform annotations only: never dispatch AD, remote, inventory or automation actions.
        // Unknown protection is permitted here; known protected computers remain read-only.
        var editable = await DirectoryApi.Scoped(db, env, actor, PermissionCatalog.AssetEdit, sync.Generation, ct);
        return (200, await editable.AnyAsync(x => x.Id == id && x.Kind == "Computer" && !x.IsProtected, ct));
    }
}
