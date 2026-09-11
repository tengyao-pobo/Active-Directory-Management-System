using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

internal static class DeviceTagChanges
{
    internal static bool IsTagChange(ManagementChange c) => c.Kind is
        "device-tag.create" or "device-tag.archive" or "device-tag.reactivate" or "device-tag.assign" or "device-tag.unassign";

    internal static bool Valid(ManagementChange c) => c.Kind switch
    {
        "device-tag.create" => c.TagKey is not null && DeviceTagCatalog.Keys.Contains(c.TagKey) &&
            c.ExpectedTagVersion is null && c.ObjectId is null,
        "device-tag.archive" or "device-tag.reactivate" => c.TagId is { } id && id != Guid.Empty &&
            c.ExpectedTagVersion > 0 && c.ObjectId is null,
        "device-tag.assign" or "device-tag.unassign" => c.TagId is { } id && id != Guid.Empty &&
            c.ExpectedTagVersion > 0 && c.ObjectId is { } objectId && objectId != Guid.Empty,
        _ => false
    };

    internal static async Task<bool> Allows(ConsoleDbContext db, EnvironmentAccess access, Guid env, Guid actor, CancellationToken ct) =>
        await access.Allows(env, actor, PermissionCatalog.DeviceTagManage, ct) &&
        await (from a in db.Assignments
               join r in db.Roles on new { a.EnvironmentId, Id = a.RoleId } equals new { r.EnvironmentId, r.Id }
               join p in db.RolePermissions on new { r.EnvironmentId, RoleId = r.Id } equals new { p.EnvironmentId, p.RoleId }
               join s in db.Scopes on new { a.EnvironmentId, Id = a.ScopeId } equals new { s.EnvironmentId, s.Id }
               where a.EnvironmentId == env && a.PrincipalId == actor && r.BuiltInKind == BuiltInRoleKinds.Owner &&
                   p.Permission == PermissionCatalog.DeviceTagManage && s.Kind == ScopeKind.All && s.Value == null
               select a.Id).AnyAsync(ct);

    internal static async Task<string?> Check(ConsoleDbContext db, Guid env, ManagementChange c, DateTimeOffset now, CancellationToken ct)
    {
        if (c.Kind is "assignment.add" or "group-mapping.add")
        {
            var scope = await db.Scopes.SingleOrDefaultAsync(s => s.EnvironmentId == env && s.Id == c.ScopeId, ct);
            if (scope?.Kind == ScopeKind.DeviceTag && (!DeviceTagCatalog.IsCanonicalId(scope.Value) || scope.IncludeDescendants ||
                !await db.DeviceTags.AnyAsync(t => t.EnvironmentId == env && t.Id == Guid.Parse(scope.Value!) && t.ArchivedAt == null, ct)))
                return "TagUnavailable";
        }
        if (c.Kind == "scope.create" && c.ScopeKind == ScopeKind.DeviceTag)
            return DeviceTagCatalog.IsCanonicalId(c.ScopeValue) && !c.IncludeDescendants &&
                await db.DeviceTags.AnyAsync(t => t.EnvironmentId == env && t.Id == Guid.Parse(c.ScopeValue!) && t.ArchivedAt == null, ct)
                ? null : "TagUnavailable";
        if (!IsTagChange(c)) return null;
        if (c.Kind == "device-tag.create")
            return await db.DeviceTags.AnyAsync(t => t.EnvironmentId == env && (t.Key == c.TagKey || t.Id == c.TagId), ct)
                ? "TagExists" : null;
        var tag = await db.DeviceTags.SingleOrDefaultAsync(t => t.EnvironmentId == env && t.Id == c.TagId, ct);
        if (tag is null) return "TagUnavailable";
        if (tag.Version != c.ExpectedTagVersion) return "TagChanged";
        if (c.Kind == "device-tag.archive") return tag.ArchivedAt is null ? null : "TagAlreadyArchived";
        if (c.Kind == "device-tag.reactivate") return tag.ArchivedAt is not null ? null : "TagAlreadyActive";
        var assigned = await db.DeviceTagAssignments.AnyAsync(a => a.EnvironmentId == env && a.TagId == c.TagId && a.ObjectId == c.ObjectId, ct);
        if (c.Kind == "device-tag.unassign") return assigned ? null : "TagAssignmentUnavailable";
        if (tag.ArchivedAt is not null) return "TagArchived";
        if (assigned) return "TagAlreadyAssigned";
        var state = await db.DirectorySync.SingleOrDefaultAsync(s => s.EnvironmentId == env, ct);
        if (state?.Status != "Ready" || state.CompletedAt is null || state.CompletedAt < now.AddMinutes(-15)) return "DirectoryUnavailable";
        if (!await db.DirectoryObjects.AnyAsync(d => d.EnvironmentId == env && d.Generation == state.Generation &&
            d.Id == c.ObjectId && d.Kind == "Computer", ct)) return "DeviceUnavailable";
        if (await db.DeviceTagAssignments.CountAsync(a => a.EnvironmentId == env, ct) >= DeviceTagCatalog.AssignmentLimit) return "TagAssignmentLimitReached";
        return null;
    }

    internal static async Task Apply(ConsoleDbContext db, Guid env, ManagementChange c, Guid actor, DateTimeOffset now, CancellationToken ct)
    {
        if (c.Kind == "device-tag.create")
        {
            db.DeviceTags.Add(new DeviceTag { EnvironmentId = env, Id = c.TagId!.Value, Key = c.TagKey!,
                CreatedAt = now, UpdatedAt = now, CreatedBy = actor, UpdatedBy = actor });
            return;
        }
        var tag = await db.DeviceTags.SingleAsync(t => t.EnvironmentId == env && t.Id == c.TagId, ct);
        switch (c.Kind)
        {
            case "device-tag.archive": tag.ArchivedAt = now; break;
            case "device-tag.reactivate": tag.ArchivedAt = null; break;
            case "device-tag.assign":
                db.DeviceTagAssignments.Add(new DeviceTagAssignment { EnvironmentId = env, TagId = tag.Id,
                    ObjectId = c.ObjectId!.Value, CreatedAt = now, CreatedBy = actor }); break;
            case "device-tag.unassign":
                db.DeviceTagAssignments.Remove(await db.DeviceTagAssignments.SingleAsync(a => a.EnvironmentId == env &&
                    a.TagId == tag.Id && a.ObjectId == c.ObjectId, ct)); break;
        }
        tag.Version++;
        tag.UpdatedAt = now;
        tag.UpdatedBy = actor;
    }
}
