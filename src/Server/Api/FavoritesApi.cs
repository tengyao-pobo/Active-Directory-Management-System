using System.Security.Cryptography;
using System.Text.Json;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

public static class FavoritesApi
{
    private const int MaximumFavorites = 500;
    private sealed record Cursor(Guid Environment, Guid Principal, Guid Generation, long Version, Guid After);
    private static readonly (string Kind, string Permission)[] Kinds =
    [
        ("Computer", PermissionCatalog.ComputerView), ("User", PermissionCatalog.UserView),
        ("Group", PermissionCatalog.GroupView), ("OrganizationalUnit", PermissionCatalog.EnvironmentView)
    ];

    public static void MapFavorites(this WebApplication app)
    {
        var group = app.MapGroup("/api/v1/environments/{environmentId:guid}/favorites");
        group.MapGet("", async (Guid environmentId, string? cursor, int? limit, HttpContext http,
            ConsoleDbContext db, IDataProtectionProvider protection, CancellationToken ct) =>
        {
            if (limit is < 1 or > 100 || cursor?.Length > 4096) return Results.BadRequest();
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await Member(db, environmentId, actor, ct)) return Results.NotFound();
            var state = await FreshState(db, environmentId, ct);
            if (state is null) return Unavailable();
            var version = await db.Environments.Where(e => e.Id == environmentId).Select(e => e.Version).SingleAsync(ct);
            var protector = protection.CreateProtector("FavoritesCursor.v2");
            Cursor? position = null;
            if (cursor is not null)
            {
                try { position = JsonSerializer.Deserialize<Cursor>(protector.Unprotect(cursor)); }
                catch (Exception error) when (error is CryptographicException or JsonException or FormatException)
                { return Results.BadRequest(); }
                if (position is null || position.Environment != environmentId || position.Principal != actor)
                    return Results.BadRequest();
                if (position.Generation != state.Generation)
                    return Results.Problem(statusCode: 409, title: "DirectorySnapshotChanged");
                if (position.Version != version) return Results.Problem(statusCode: 409, title: "AuthorizationSnapshotChanged");
            }
            var visible = await Visible(db, environmentId, actor, state.Generation, ct);
            var query = from row in visible
                        join favorite in db.Favorites.Where(x => x.EnvironmentId == environmentId && x.PrincipalId == actor)
                            on new { ObjectId = row.Id, row.Kind } equals new { favorite.ObjectId, favorite.Kind }
                        select row;
            if (position is not null) query = query.Where(x => x.Id.CompareTo(position.After) > 0);
            var take = limit ?? 50;
            var rows = await query.OrderBy(x => x.Id).Take(take + 1).ToListAsync(ct);
            var more = rows.Count > take;
            if (more) rows.RemoveAt(take);
            var next = more ? protector.Protect(JsonSerializer.Serialize(new Cursor(environmentId, actor, state.Generation, version, rows[^1].Id))) : null;
            return Results.Ok(new { items = rows.Select(x => new { x.Id, x.Kind, x.Name, x.DistinguishedName, x.SamAccountName, x.Department }),
                nextCursor = next, generation = state.Generation, asOf = state.CompletedAt });
        });

        group.MapGet("/{objectId:guid}", async (Guid environmentId, Guid objectId, HttpContext http, ConsoleDbContext db, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await Member(db, environmentId, actor, ct)) return Results.NotFound();
            var state = await FreshState(db, environmentId, ct);
            if (state is null) return Unavailable();
            var visible = await Visible(db, environmentId, actor, state.Generation, ct);
            var kind = await visible.Where(x => x.Id == objectId).Select(x => x.Kind).SingleOrDefaultAsync(ct);
            if (kind is null) return Results.NotFound();
            return Results.Ok(new { saved = await db.Favorites.AnyAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor && x.ObjectId == objectId && x.Kind == kind, ct) });
        });

        group.MapPut("/{objectId:guid}", async (Guid environmentId, Guid objectId, HttpContext http, ConsoleDbContext db, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await Member(db, environmentId, actor, ct)) return Results.NotFound();
            // Serialize each user's capacity check and insert. Serializable conflicts return 409 via middleware.
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM public.\"Memberships\" WHERE \"EnvironmentId\"={environmentId} AND \"PrincipalId\"={actor} FOR UPDATE", ct);
            var state = await FreshState(db, environmentId, ct);
            if (state is null) return Unavailable();
            var visible = await Visible(db, environmentId, actor, state.Generation, ct);
            var kind = await visible.Where(x => x.Id == objectId).Select(x => x.Kind).SingleOrDefaultAsync(ct);
            if (kind is null) return Results.NotFound();
            var existing = await db.Favorites.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor && x.ObjectId == objectId, ct);
            if (existing is not null && existing.Kind != kind) return Results.NotFound();
            if (existing is null)
            {
                if (await db.Favorites.CountAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor, ct) >= MaximumFavorites)
                    return Results.Problem(statusCode: 409, title: "FavoritesLimitReached");
                await db.Database.ExecuteSqlInterpolatedAsync($"INSERT INTO public.\"Favorites\" (\"EnvironmentId\",\"PrincipalId\",\"ObjectId\",\"Kind\") VALUES ({environmentId},{actor},{objectId},{kind}) ON CONFLICT DO NOTHING", ct);
            }
            await tx.CommitAsync(ct);
            return Results.NoContent();
        });

        group.MapDelete("/{objectId:guid}", async (Guid environmentId, Guid objectId, HttpContext http, ConsoleDbContext db, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await Member(db, environmentId, actor, ct)) return Results.NotFound();
            // Ownership alone permits cleanup when an object is removed, stale or no longer visible.
            await db.Favorites.Where(x => x.EnvironmentId == environmentId && x.PrincipalId == actor && x.ObjectId == objectId).ExecuteDeleteAsync(ct);
            await tx.CommitAsync(ct);
            return Results.NoContent();
        });
    }

    private static Task<bool> Member(ConsoleDbContext db, Guid env, Guid actor, CancellationToken ct) =>
        db.Memberships.AnyAsync(x => x.EnvironmentId == env && x.PrincipalId == actor && x.Active, ct);

    private static async Task<DirectorySyncState?> FreshState(ConsoleDbContext db, Guid env, CancellationToken ct)
    {
        var state = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == env, ct);
        return state?.Status == "Ready" && state.CompletedAt >= DateTimeOffset.UtcNow.AddMinutes(-15) ? state : null;
    }

    private static IResult Unavailable() => Results.Problem(statusCode: 503, title: "DirectoryUnavailable");

    private static async Task<IQueryable<DirectoryObjectRecord>> Visible(ConsoleDbContext db, Guid env, Guid actor, Guid generation, CancellationToken ct)
    {
        IQueryable<DirectoryObjectRecord>? query = null;
        foreach (var (kind, permission) in Kinds)
        {
            var scoped = (await DirectoryApi.Scoped(db, env, actor, permission, generation, ct)).Where(x => x.Kind == kind);
            query = query is null ? scoped : query.Concat(scoped);
        }
        return query!;
    }
}
