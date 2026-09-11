using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

public static class SavedFilterApi
{
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    public sealed record SavedFilterInput(int SchemaVersion, string? Name, string? Kind, string? Search, Guid? TagId);

    private sealed record Cursor(Guid Environment, Guid Principal, Guid FilterId, long FilterVersion, long EnvironmentVersion,
        Guid Generation, string Kind, string Search, Guid? TagId, Guid After);

    public static void MapSavedFilters(this WebApplication app)
    {
        var group = app.MapGroup("/api/v1/environments/{environmentId:guid}/saved-filters");
        group.MapGet("", List);
        group.MapPost("", Create).AddEndpointFilter<WriteConflictFilter>();
        group.MapGet("/{id:guid}", Get);
        group.MapPut("/{id:guid}", Update).AddEndpointFilter<WriteConflictFilter>();
        group.MapDelete("/{id:guid}", Delete).AddEndpointFilter<WriteConflictFilter>();
        group.MapGet("/{id:guid}/results", ResultsFor);
    }

    public sealed class WriteConflictFilter : IEndpointFilter
    {
        public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            try { return await next(context); }
            catch (Exception error) when (SerializationConflict(error))
            {
                return Results.Problem(statusCode: 409, title: "SavedFilterWriteConflict");
            }
        }
    }

    private static async Task<IResult> List(Guid environmentId, HttpContext http, ConsoleDbContext db, CancellationToken ct)
    {
        var actor = AuthEndpoints.Actor(http); await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        if (!await DirectoryApi.Member(db, environmentId, actor, ct)) return Results.NotFound();
        var rows = await db.SavedFilters.Where(x => x.EnvironmentId == environmentId && x.PrincipalId == actor)
            .OrderBy(x => x.Name).ThenBy(x => x.Id).Take(SavedFilterCatalog.MaximumPerPrincipal).ToListAsync(ct);
        return Results.Ok(new { items = rows.Select(Dto) });
    }

    private static async Task<IResult> Create(Guid environmentId, SavedFilterInput input, HttpContext http, ConsoleDbContext db, TimeProvider time, CancellationToken ct)
    {
        var normalized = Normalize(input); if (normalized is null) return Results.BadRequest();
        var actor = AuthEndpoints.Actor(http); await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        var membership = await db.Memberships.FromSqlInterpolated($"SELECT * FROM public.\"Memberships\" WHERE \"EnvironmentId\"={environmentId} AND \"PrincipalId\"={actor} FOR UPDATE").SingleOrDefaultAsync(ct);
        if (membership?.Active != true) return Results.NotFound();
        if (!await ValidTag(db, environmentId, normalized, ct)) return Results.BadRequest();
        if (await db.SavedFilters.CountAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor, ct) >= SavedFilterCatalog.MaximumPerPrincipal)
            return Results.Problem(statusCode: 409, title: "SavedFilterLimitReached");
        var now = DatabaseTime(time); var row = new SavedFilter { EnvironmentId = environmentId, PrincipalId = actor, Id = Guid.NewGuid(),
            SchemaVersion = 1, Name = normalized.Name!, Kind = normalized.Kind!, Search = normalized.Search!, TagId = normalized.TagId,
            Version = 1, CreatedAt = now, UpdatedAt = now };
        db.SavedFilters.Add(row); await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
        http.Response.Headers.ETag = ETag(row.Version);
        return Results.Created($"/api/v1/environments/{environmentId}/saved-filters/{row.Id}", Dto(row));
    }

    private static async Task<IResult> Get(Guid environmentId, Guid id, HttpContext http, ConsoleDbContext db, CancellationToken ct)
    {
        var actor = AuthEndpoints.Actor(http); await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        if (!await DirectoryApi.Member(db, environmentId, actor, ct)) return Results.NotFound();
        var row = await Find(db, environmentId, actor, id, ct); if (row is null) return Results.NotFound();
        http.Response.Headers.ETag = ETag(row.Version); return Results.Ok(Dto(row));
    }

    private static async Task<IResult> Update(Guid environmentId, Guid id, SavedFilterInput input, HttpContext http, ConsoleDbContext db, TimeProvider time, CancellationToken ct)
    {
        var normalized = Normalize(input); if (normalized is null) return Results.BadRequest();
        if (!TryExpectedVersion(http, out var expected, out var missing)) return missing ? Results.StatusCode(428) : Results.BadRequest();
        var actor = AuthEndpoints.Actor(http); await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        if (!await DirectoryApi.Member(db, environmentId, actor, ct)) return Results.NotFound();
        var row = await FindForUpdate(db, environmentId, actor, id, ct); if (row is null) return Results.NotFound();
        if (row.Version != expected) return Results.StatusCode(412);
        if (!await ValidTag(db, environmentId, normalized, ct)) return Results.BadRequest();
        row.SchemaVersion = 1; row.Name = normalized.Name!; row.Kind = normalized.Kind!; row.Search = normalized.Search!; row.TagId = normalized.TagId;
        row.Version++; row.UpdatedAt = DatabaseTime(time); await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
        http.Response.Headers.ETag = ETag(row.Version); return Results.Ok(Dto(row));
    }

    private static async Task<IResult> Delete(Guid environmentId, Guid id, HttpContext http, ConsoleDbContext db, CancellationToken ct)
    {
        if (!TryExpectedVersion(http, out var expected, out var missing)) return missing ? Results.StatusCode(428) : Results.BadRequest();
        var actor = AuthEndpoints.Actor(http); await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        if (!await DirectoryApi.Member(db, environmentId, actor, ct)) return Results.NotFound();
        var row = await FindForUpdate(db, environmentId, actor, id, ct); if (row is null) return Results.NotFound();
        if (row.Version != expected) return Results.StatusCode(412);
        db.SavedFilters.Remove(row); await db.SaveChangesAsync(ct); await tx.CommitAsync(ct); return Results.NoContent();
    }

    private static async Task<IResult> ResultsFor(Guid environmentId, Guid id, long? filterVersion, string? cursor, int? limit, HttpContext http,
        ConsoleDbContext db, IDataProtectionProvider protection, CancellationToken ct)
    {
        if (filterVersion is null or <= 0 || limit is < 1 or > 200 || cursor?.Length > 4096) return Results.BadRequest();
        var actor = AuthEndpoints.Actor(http); await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        if (!await DirectoryApi.Member(db, environmentId, actor, ct)) return Results.NotFound();
        var filter = await Find(db, environmentId, actor, id, ct); if (filter is null) return Results.NotFound();
        if (filter.Version != filterVersion) return Results.Problem(statusCode: 409, title: "SavedFilterChanged");
        var state = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId, ct);
        if (state?.CompletedAt is null || state.Status != "Ready" || state.CompletedAt < DateTimeOffset.UtcNow.AddMinutes(-15))
            return Results.Problem(statusCode: 503, title: "DirectoryUnavailable");
        var environmentVersion = await db.Environments.Where(x => x.Id == environmentId).Select(x => x.Version).SingleAsync(ct);
        var protector = protection.CreateProtector("SavedFilterResultsCursor.v1"); Cursor? position = null;
        if (cursor is not null)
        {
            try { position = JsonSerializer.Deserialize<Cursor>(protector.Unprotect(cursor)); }
            catch (Exception error) when (error is CryptographicException or JsonException or FormatException) { return Results.BadRequest(); }
            if (position is null || position.Environment != environmentId || position.Principal != actor || position.FilterId != filter.Id) return Results.BadRequest();
            if (position.Generation != state.Generation) return Results.Problem(statusCode: 409, title: "DirectorySnapshotChanged");
            if (position.EnvironmentVersion != environmentVersion) return Results.Problem(statusCode: 409, title: "AuthorizationSnapshotChanged");
            if (position.FilterVersion != filter.Version || position.Kind != filter.Kind || position.Search != filter.Search || position.TagId != filter.TagId)
                return Results.Problem(statusCode: 409, title: "SavedFilterChanged");
        }
        var permission = DirectoryApi.Permission(filter.Kind)!;
        var query = await DirectoryApi.Scoped(db, environmentId, actor, permission, state.Generation, ct);
        query = query.Where(x => x.Kind == filter.Kind);
        if (filter.TagId is { } tag) query = query.Where(x => db.DeviceTagAssignments.Any(a => a.EnvironmentId == environmentId && a.ObjectId == x.Id && a.TagId == tag));
        if (filter.Search.Length > 0) query = query.Where(x => x.Name.Contains(filter.Search) || (x.SamAccountName != null && x.SamAccountName.Contains(filter.Search)));
        if (position is not null) query = query.Where(x => x.Id.CompareTo(position.After) > 0);
        var take = limit ?? 50; var rows = await query.OrderBy(x => x.Id).Take(take + 1).ToListAsync(ct); var more = rows.Count > take;
        if (more) rows.RemoveAt(take);
        var next = more ? protector.Protect(JsonSerializer.Serialize(new Cursor(environmentId, actor, filter.Id, filter.Version, environmentVersion,
            state.Generation, filter.Kind, filter.Search, filter.TagId, rows[^1].Id))) : null;
        return Results.Ok(new { items = rows.Select(DirectoryApi.Dto), nextCursor = next, asOf = state.CompletedAt, generation = state.Generation });
    }

    private static SavedFilterInput? Normalize(SavedFilterInput input)
    {
        if (input.SchemaVersion != 1 || input.Name is null || input.Kind is null || input.Search is null) return null;
        var name = input.Name.Trim(); var search = input.Search.Trim();
        if (name.Length is < 1 or > 128 || name.Any(char.IsControl) || search.Length > 128 || search.Any(char.IsControl) ||
            !SavedFilterCatalog.Kinds.Contains(input.Kind, StringComparer.Ordinal) || input.TagId == Guid.Empty ||
            (input.TagId is not null && input.Kind != "Computer")) return null;
        return input with { Name = name, Search = search };
    }

    private static Task<bool> ValidTag(ConsoleDbContext db, Guid environmentId, SavedFilterInput input, CancellationToken ct) => input.TagId is null
        ? Task.FromResult(true)
        : db.DeviceTags.AnyAsync(x => x.EnvironmentId == environmentId && x.Id == input.TagId, ct);
    private static Task<SavedFilter?> Find(ConsoleDbContext db, Guid environmentId, Guid actor, Guid id, CancellationToken ct) =>
        db.SavedFilters.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor && x.Id == id, ct);
    private static Task<SavedFilter?> FindForUpdate(ConsoleDbContext db, Guid environmentId, Guid actor, Guid id, CancellationToken ct) =>
        db.SavedFilters.FromSqlInterpolated($"SELECT * FROM public.\"SavedFilters\" WHERE \"EnvironmentId\"={environmentId} AND \"PrincipalId\"={actor} AND \"Id\"={id} FOR UPDATE").SingleOrDefaultAsync(ct);
    private static object Dto(SavedFilter row) => new { row.Id, row.SchemaVersion, row.Name, row.Kind, row.Search, row.TagId, row.Version, row.CreatedAt, row.UpdatedAt };
    private static string ETag(long version) => $"\"{version}\"";
    private static bool SerializationConflict(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is Npgsql.PostgresException { SqlState: "40001" }) return true;
        return false;
    }
    private static DateTimeOffset DatabaseTime(TimeProvider time)
    {
        var ticks = time.GetUtcNow().UtcTicks;
        return new DateTimeOffset(ticks - ticks % 10, TimeSpan.Zero);
    }
    private static bool TryExpectedVersion(HttpContext http, out long version, out bool missing)
    {
        missing = !http.Request.Headers.ContainsKey("If-Match"); version = 0; if (missing) return false;
        var value = http.Request.Headers.IfMatch.ToString(); return value.Length >= 3 && value[0] == '"' && value[^1] == '"' &&
            long.TryParse(value.AsSpan(1, value.Length - 2), out version) && version > 0;
    }
}
