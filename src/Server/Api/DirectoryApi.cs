using System.Security.Cryptography;
using System.Text.Json;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

public static class DirectoryApi
{
    private sealed record Cursor(Guid Environment, Guid Actor, Guid Generation, string Kind, string Search, Guid After);
    private static string? Permission(string kind) => kind switch
    {
        "User" => PermissionCatalog.UserView, "Group" => PermissionCatalog.GroupView,
        "Computer" => PermissionCatalog.ComputerView, "OrganizationalUnit" => PermissionCatalog.EnvironmentView, _ => null
    };

    public static void MapDirectoryApi(this WebApplication app)
    {
        var group = app.MapGroup("/api/v1/environments/{environmentId:guid}/directory");
        group.MapGet("/status", async (Guid environmentId, HttpContext http, ConsoleDbContext db, CancellationToken ct) =>
        {
            await using var tx = await db.BeginEnvironment(environmentId, AuthEndpoints.Actor(http), ct);
            if (!await Member(db, environmentId, AuthEndpoints.Actor(http), ct)) return Results.NotFound();
            var state = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId, ct);
            return Results.Ok(new { status = state?.Status ?? "Unconfigured", state?.CompletedAt, state?.AttemptedAt, state?.ErrorCode,
                stale = state?.Status != "Ready" || state.CompletedAt is null || state.CompletedAt < DateTimeOffset.UtcNow.AddMinutes(-15), mutationAvailable = false });
        });
        group.MapGet("/objects", async (Guid environmentId, string kind, string? search, string? cursor, int? limit,
            HttpContext http, ConsoleDbContext db, IDataProtectionProvider protection, CancellationToken ct) =>
        {
            var permission = Permission(kind);
            search = search?.Trim() ?? "";
            if (permission is null || search.Length > 128 || search.Any(char.IsControl) || limit is < 1 or > 200 || cursor?.Length > 4096) return Results.BadRequest();
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await Member(db, environmentId, actor, ct)) return Results.NotFound();
            var state = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId, ct);
            if (state?.CompletedAt is null || state.Status != "Ready" || state.CompletedAt < DateTimeOffset.UtcNow.AddMinutes(-15))
                return Results.Problem(statusCode: 503, title: "DirectoryUnavailable");
            var protector = protection.CreateProtector("DirectoryCursor.v1");
            Cursor? position = null;
            if (cursor is not null)
            {
                try { position = JsonSerializer.Deserialize<Cursor>(protector.Unprotect(cursor)); }
                catch (Exception error) when (error is CryptographicException or JsonException or FormatException) { return Results.BadRequest(); }
                if (position is null || position.Environment != environmentId || position.Actor != actor || position.Kind != kind || position.Search != search)
                    return Results.BadRequest();
                if (position.Generation != state.Generation) return Results.Problem(statusCode: 409, title: "DirectorySnapshotChanged");
            }
            var query = await Scoped(db, environmentId, actor, permission, state.Generation, ct);
            query = query.Where(x => x.Kind == kind);
            if (search.Length > 0) query = query.Where(x => x.Name.Contains(search) || (x.SamAccountName != null && x.SamAccountName.Contains(search)));
            if (position is not null) query = query.Where(x => x.Id.CompareTo(position.After) > 0);
            var take = limit ?? 50;
            var rows = await query.OrderBy(x => x.Id).Take(take + 1).ToListAsync(ct);
            var more = rows.Count > take;
            if (more) rows.RemoveAt(take);
            var next = more ? protector.Protect(JsonSerializer.Serialize(new Cursor(environmentId, actor, state.Generation, kind, search, rows[^1].Id))) : null;
            return Results.Ok(new { items = rows.Select(Dto), nextCursor = next, asOf = state.CompletedAt, generation = state.Generation });
        });
        group.MapGet("/objects/{objectId:guid}", async (Guid environmentId, Guid objectId, HttpContext http, ConsoleDbContext db, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await Member(db, environmentId, actor, ct)) return Results.NotFound();
            var state = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId, ct);
            if (state?.CompletedAt is null || state.Status != "Ready" || state.CompletedAt < DateTimeOffset.UtcNow.AddMinutes(-15))
                return Results.Problem(statusCode: 503, title: "DirectoryUnavailable");
            // Kind is read internally only; unauthorized objects always return the same 404.
            var kind = await db.DirectoryObjects.Where(x => x.EnvironmentId == environmentId && x.Id == objectId && x.Generation == state.Generation).Select(x => x.Kind).SingleOrDefaultAsync(ct);
            var permission = kind is null ? null : Permission(kind);
            if (permission is null) return Results.NotFound();
            var query = await Scoped(db, environmentId, actor, permission, state.Generation, ct);
            var row = await query.SingleOrDefaultAsync(x => x.Id == objectId, ct);
            return row is null ? Results.NotFound() : Results.Ok(new { item = Dto(row), asOf = state.CompletedAt });
        });
    }

    private static Task<bool> Member(ConsoleDbContext db, Guid env, Guid actor, CancellationToken ct) =>
        db.Memberships.AnyAsync(x => x.EnvironmentId == env && x.PrincipalId == actor && x.Active, ct);

    internal static async Task<IQueryable<DirectoryObjectRecord>> Scoped(ConsoleDbContext db, Guid env, Guid actor, string permission, Guid generation, CancellationToken ct)
    {
        var grants = await (from assignment in db.Assignments
            join role in db.Roles on new { assignment.EnvironmentId, Id = assignment.RoleId } equals new { role.EnvironmentId, role.Id }
            join p in db.RolePermissions on new { role.EnvironmentId, RoleId = role.Id } equals new { p.EnvironmentId, p.RoleId }
            join scope in db.Scopes on new { assignment.EnvironmentId, Id = assignment.ScopeId } equals new { scope.EnvironmentId, scope.Id }
            where assignment.EnvironmentId == env && assignment.PrincipalId == actor && p.Permission == permission
            select scope).ToListAsync(ct);
        var all = grants.Any(s => s.Kind == ScopeKind.All && s.Value is null);
        var departments = grants.Where(s => s.Kind == ScopeKind.Department && !string.IsNullOrEmpty(s.Value)).Select(s => s.Value!).ToArray();
        var exact = grants.Where(s => s.Kind == ScopeKind.OrganizationalUnit && !s.IncludeDescendants && Guid.TryParse(s.Value, out _)).Select(s => Guid.Parse(s.Value!)).ToArray();
        var subtree = grants.Where(s => s.Kind == ScopeKind.OrganizationalUnit && s.IncludeDescendants && Guid.TryParse(s.Value, out _)).Select(s => Guid.Parse(s.Value!)).ToArray();
        return db.DirectoryObjects.AsNoTracking().Where(x => x.EnvironmentId == env && x.Generation == generation &&
            (all || (x.Department != null && departments.Contains(x.Department)) || (x.ParentOuId != null && exact.Contains(x.ParentOuId.Value)) || x.OuAncestry.Any(id => subtree.Contains(id))));
    }
    private static object Dto(DirectoryObjectRecord x) => new { x.Id, x.Kind, x.Name, x.DistinguishedName, x.SamAccountName, x.Department,
        x.ObjectSid, x.UsnChanged, x.IsProtected, x.ProtectionKnown, x.ParentOuId };
}
