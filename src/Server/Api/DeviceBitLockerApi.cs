using ItManagement.AgentProjection;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

public static class DeviceBitLockerApi
{
    public static readonly TimeSpan MaximumObservationAge = TimeSpan.FromHours(24);
    public static readonly TimeSpan MaximumFutureSkew = TimeSpan.FromMinutes(5);

    public static void MapDeviceBitLocker(this WebApplication app)
    {
        app.MapGet("/api/v1/environments/{environmentId:guid}/devices/{id:guid}/bitlocker", async (
            Guid environmentId, Guid id, HttpContext http, ConsoleDbContext db,
            IAgentBitLockerProjectionReader reader, TimeProvider time, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await db.Memberships.AnyAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor && x.Active, ct))
                return Results.NotFound();
            var directory = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId, ct);
            var now = time.GetUtcNow();
            if (directory?.Status != "Ready" || directory.CompletedAt is null || directory.CompletedAt < now.AddMinutes(-15))
                return Unavailable();
            foreach (var permission in new[] { PermissionCatalog.ComputerView, PermissionCatalog.ComputerInventory, PermissionCatalog.BitLockerStatusView })
            {
                var scoped = await DirectoryApi.Scoped(db, environmentId, actor, permission, directory.Generation, ct);
                if (!await scoped.AnyAsync(x => x.Id == id && x.Kind == "Computer", ct)) return Results.NotFound();
            }
            var projection = await reader.ReadAsync(environmentId, id, ct);
            if (projection.EnvironmentId != environmentId || projection.DirectoryObjectId != id || projection.State == ProjectionReadState.Unavailable)
                return Unavailable();
            if (projection.State == ProjectionReadState.Missing)
                return Results.Ok(new { state = "Missing", queriedAt = time.GetUtcNow(), volumes = Array.Empty<object>() });
            now = time.GetUtcNow();
            if (projection.State != ProjectionReadState.Observed || projection.CollectedAt is null || projection.SourceObservedAt is null || projection.ReceivedAt is null)
                return Unavailable();
            var times = new[] { projection.CollectedAt.Value, projection.SourceObservedAt.Value, projection.ReceivedAt.Value };
            if (times.Any(value => value > now + MaximumFutureSkew)) return Unavailable();
            var stale = times.Any(value => value < now - MaximumObservationAge);
            return Results.Ok(new { state = stale ? "Stale" : "Current", queriedAt = now,
                sourceObservedAt = projection.SourceObservedAt, collectedAt = projection.CollectedAt, receivedAt = projection.ReceivedAt,
                lastSeenAt = projection.LastSeenAt, source = projection.Source, isTruncated = projection.IsTruncated,
                volumes = projection.Volumes.Select(volume => new { volume.DriveLetter, volume.VolumeType, volume.ProtectionStatus,
                    volume.ConversionStatus, volume.EncryptionMethod, volume.IsVolumeInitializedForProtection }) });
        });
    }

    private static IResult Unavailable() => Results.Problem(statusCode: 503, title: "BitLockerUnavailable");
}
