namespace ItManagement.Core;

public sealed class AuthorizationEvaluator
{
    public bool IsAllowed(
        Guid environmentId,
        Guid principalId,
        string permission,
        ResourceScope resource,
        IEnumerable<Principal> principals,
        IEnumerable<EnvironmentMembership> memberships,
        IEnumerable<Role> roles,
        IEnumerable<RolePermission> rolePermissions,
        IEnumerable<Scope> scopes,
        IEnumerable<RoleAssignment> assignments)
    {
        ArgumentNullException.ThrowIfNull(permission);
        ArgumentNullException.ThrowIfNull(resource);
        ArgumentNullException.ThrowIfNull(principals);
        ArgumentNullException.ThrowIfNull(memberships);
        ArgumentNullException.ThrowIfNull(roles);
        ArgumentNullException.ThrowIfNull(rolePermissions);
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(assignments);

        if (!PermissionCatalog.IsKnown(permission) || resource.EnvironmentId != environmentId)
        {
            return false;
        }

        if (!principals.Any(principal => principal.Id == principalId && principal.Enabled) ||
            !memberships.Any(membership =>
                membership.EnvironmentId == environmentId &&
                membership.PrincipalId == principalId &&
                membership.Active))
        {
            return false;
        }

        if ((resource.IsProtected || !resource.ProtectionKnown) && !PermissionCatalog.IsReadOnly(permission))
        {
            return false;
        }

        var environmentRoles = roles
            .Where(role => role.EnvironmentId == environmentId)
            .GroupBy(role => role.Id)
            .Where(group => group.Count() == 1)
            .ToDictionary(group => group.Key, group => group.Single());
        var environmentScopes = scopes
            .Where(scope => scope.EnvironmentId == environmentId)
            .GroupBy(scope => scope.Id)
            .Where(group => group.Count() == 1)
            .ToDictionary(group => group.Key, group => group.Single());
        var permissionsByRole = rolePermissions
            .Where(rolePermission =>
                rolePermission.EnvironmentId == environmentId &&
                string.Equals(rolePermission.Permission, permission, StringComparison.Ordinal))
            .Select(rolePermission => rolePermission.RoleId)
            .ToHashSet();

        foreach (var assignment in assignments.Where(assignment =>
                     assignment.EnvironmentId == environmentId &&
                     assignment.PrincipalId == principalId))
        {
            if (!environmentRoles.TryGetValue(assignment.RoleId, out var role) ||
                !permissionsByRole.Contains(role.Id) ||
                !environmentScopes.TryGetValue(assignment.ScopeId, out var scope))
            {
                continue;
            }

            if (PermissionCatalog.IsOwnerOnly(permission) &&
                !string.Equals(role.BuiltInKind, BuiltInRoleKinds.Owner, StringComparison.Ordinal))
            {
                continue;
            }

            if (MatchesScope(scope, resource))
            {
                return true;
            }
        }

        return false;
    }

    public bool MatchesScope(Scope scope, ResourceScope resource)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(resource);

        if (scope.EnvironmentId != resource.EnvironmentId)
        {
            return false;
        }

        return scope.Kind switch
        {
            ScopeKind.All => scope.Value is null,
            ScopeKind.Department => HasValue(scope) &&
                                    string.Equals(scope.Value, resource.DepartmentId, StringComparison.Ordinal),
            ScopeKind.Group => HasValue(scope) && resource.GroupIds.Contains(scope.Value!),
            ScopeKind.DeviceTag => !scope.IncludeDescendants && DeviceTagCatalog.IsCanonicalId(scope.Value) && resource.TagIds.Contains(scope.Value!),
            ScopeKind.OrganizationalUnit => MatchesOrganizationalUnit(scope, resource),
            _ => false,
        };
    }

    private static bool HasValue(Scope scope) => !string.IsNullOrWhiteSpace(scope.Value);

    private static bool MatchesOrganizationalUnit(Scope scope, ResourceScope resource)
    {
        if (!HasValue(scope))
        {
            return false;
        }

        return scope.IncludeDescendants
            ? resource.OrganizationalUnitAncestry.Contains(scope.Value!)
            : string.Equals(scope.Value, resource.OrganizationalUnitId, StringComparison.Ordinal);
    }
}
