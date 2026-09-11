using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

// Informational snapshot comparison only. This DTO is never a ChangePlan or an execution token.
public sealed record DepartmentProposalRequest(string Kind, string Department);

public static class DirectoryProposalsApi
{
    public static void MapDirectoryProposals(this WebApplication app)
    {
        app.MapPost("/api/v1/environments/{environmentId:guid}/directory/users/{id:guid}/proposal",
            async (Guid environmentId, Guid id, DepartmentProposalRequest input, HttpContext http,
                ConsoleDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            if (input.Kind != "SetUserDepartment" || string.IsNullOrWhiteSpace(input.Department) ||
                input.Department.Length > 128 || input.Department.Any(char.IsControl))
                return Results.Problem(statusCode: 400, title: "InvalidDirectoryTemplate");
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await db.Memberships.AnyAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor && x.Active, ct))
                return Results.NotFound();
            var sync = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId, ct);
            var now = time.GetUtcNow();
            if (sync?.Status != "Ready" || sync.CompletedAt is null || sync.CompletedAt < now.AddMinutes(-2) || sync.CompletedAt > now)
                return Results.Problem(statusCode: 503, title: "DirectoryUnavailable");
            var readable = await DirectoryApi.Scoped(db, environmentId, actor, PermissionCatalog.UserView, sync.Generation, ct);
            var editable = await DirectoryApi.Scoped(db, environmentId, actor, PermissionCatalog.UserEdit, sync.Generation, ct);
            var row = await readable.SingleOrDefaultAsync(x => x.Id == id && x.Kind == "User", ct);
            if (row is null || !await editable.AnyAsync(x => x.Id == id && x.Kind == "User", ct)) return Results.NotFound();
            return Results.Ok(new
            {
                environmentId, target = new { row.Id, row.Name, row.DistinguishedName, row.UsnChanged },
                kind = "SetUserDepartment", before = row.Department, after = input.Department.Trim(),
                asOf = sync.CompletedAt, generation = sync.Generation, snapshotValidUntil = sync.CompletedAt.Value.AddMinutes(2),
                row.IsProtected, row.ProtectionKnown, approvalAvailable = false, executionAvailable = false,
                blockers = new[] { "DirectoryWritesNotConfigured", "ApprovalWorkflowUnavailable",
                    !row.ProtectionKnown ? "ProtectionClassificationUnavailable" : row.IsProtected ? "ProtectedObject" : null }.Where(x => x is not null),
                status = "InformationalOnly"
            });
        });
    }
}
