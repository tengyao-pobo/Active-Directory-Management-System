using ItManagement.AgentEnrollmentTargets;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

public static class DeviceEnrollmentApi
{
    public static void MapDeviceEnrollment(this WebApplication app)
    {
        app.MapGet("/api/v1/environments/{environmentId:guid}/devices/{id:guid}/enrollment-target", async (
            Guid environmentId, Guid id, HttpContext http, ConsoleDbContext db,
            IEnrollmentTargetReader reader, TimeProvider time, CancellationToken ct) =>
        {
            http.Response.Headers.CacheControl = "no-store";
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await db.Memberships.AnyAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor && x.Active, ct))
                return Results.NotFound();
            var directory = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId, ct);
            var now = time.GetUtcNow();
            if (directory?.Status != "Ready" || directory.CompletedAt is null ||
                directory.CompletedAt < now.AddMinutes(-15) || directory.CompletedAt > now)
                return Unavailable();
            foreach (var permission in new[] { PermissionCatalog.ComputerView, PermissionCatalog.AgentEnrollmentGrantManage })
            {
                var scoped = await DirectoryApi.Scoped(db, environmentId, actor, permission, directory.Generation, ct);
                if (!await scoped.AnyAsync(x => x.Id == id && x.Kind == "Computer", ct)) return Results.NotFound();
            }

            // This read is an advisory prerequisite, never proof of approval or permission to mint.
            var target = await reader.ReadAsync(environmentId, id, ct);
            if (target.EnvironmentId != environmentId || target.DirectoryObjectId != id) return Unavailable();
            var queriedAt = time.GetUtcNow();
            if (target.State == EnrollmentTargetState.Resolved && target.Diagnostic == EnrollmentTargetDiagnostic.None &&
                target.DeviceId is { } deviceId && deviceId != Guid.Empty && target.MappingCreatedAt is { } mappedAt &&
                mappedAt.Offset == TimeSpan.Zero && mappedAt.Ticks % 10 == 0 && mappedAt <= queriedAt)
                return Results.Ok(new { status = "Eligible", queriedAt });
            if (target.State == EnrollmentTargetState.MappingRequired &&
                target.Diagnostic is EnrollmentTargetDiagnostic.MappingMissing or EnrollmentTargetDiagnostic.DeviceInactive &&
                target.DeviceId is null && target.MappingCreatedAt is null)
                return Results.Ok(new { status = "MappingRequired", queriedAt });
            return Unavailable();
        });
    }

    private static IResult Unavailable() => Results.Problem(statusCode: 503, title: "EnrollmentTargetUnavailable");
}
