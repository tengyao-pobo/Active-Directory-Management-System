using ItManagement.Core;

namespace ItManagement.UnitTests;

public sealed class AuthorizationEvaluatorTests
{
    [Fact]
    public void PermissionAndScopeFromDifferentAssignmentsCannotBeCombined()
    {
        var fixture = AuthorizationFixture.Create();
        var narrowRole = fixture.AddRole();
        var broadRole = fixture.AddRole();
        var wrongDepartment = fixture.AddScope(ScopeKind.Department, "finance");
        var all = fixture.AddScope(ScopeKind.All);

        fixture.Grant(narrowRole, PermissionCatalog.UserManage);
        fixture.Assign(narrowRole, wrongDepartment);
        fixture.Assign(broadRole, all);

        Assert.False(fixture.IsAllowed(
            PermissionCatalog.UserManage,
            fixture.Resource(departmentId: "engineering")));
    }

    [Fact]
    public void CrossEnvironmentRoleDataCannotAuthorize()
    {
        var fixture = AuthorizationFixture.Create();
        var otherEnvironment = Guid.NewGuid();
        var role = fixture.AddRole(environmentId: otherEnvironment);
        var scope = fixture.AddScope(ScopeKind.All, environmentId: otherEnvironment);
        fixture.Grant(role, PermissionCatalog.UserView, otherEnvironment);
        fixture.Assign(role, scope, otherEnvironment);

        Assert.False(fixture.IsAllowed(PermissionCatalog.UserView, fixture.Resource()));
    }

    [Fact]
    public void CustomRoleCannotReceiveOwnerOnlyPermission()
    {
        var fixture = AuthorizationFixture.Create();
        var customRole = fixture.AddRole(name: "Owner", builtInKind: null);
        var all = fixture.AddScope(ScopeKind.All);
        fixture.Grant(customRole, PermissionCatalog.OwnerTransfer);
        fixture.Assign(customRole, all);

        Assert.False(fixture.IsAllowed(PermissionCatalog.OwnerTransfer, fixture.Resource()));
    }

    [Fact]
    public void OwnerBuiltInRoleCanReceiveOwnerOnlyPermission()
    {
        var fixture = AuthorizationFixture.Create();
        var owner = fixture.AddRole(builtInKind: BuiltInRoleKinds.Owner);
        var all = fixture.AddScope(ScopeKind.All);
        fixture.Grant(owner, PermissionCatalog.OwnerTransfer);
        fixture.Assign(owner, all);

        Assert.True(fixture.IsAllowed(PermissionCatalog.OwnerTransfer, fixture.Resource()));
    }

    [Fact]
    public void UnknownScopeKindFailsClosed()
    {
        var fixture = AuthorizationFixture.Create();
        var role = fixture.AddRole();
        var unknown = fixture.AddScope((ScopeKind)999, "anything");
        fixture.Grant(role, PermissionCatalog.UserView);
        fixture.Assign(role, unknown);

        Assert.False(fixture.IsAllowed(PermissionCatalog.UserView, fixture.Resource()));
    }

    [Fact]
    public void UnknownPermissionFailsClosed()
    {
        var fixture = AuthorizationFixture.Create();
        var role = fixture.AddRole();
        var all = fixture.AddScope(ScopeKind.All);
        fixture.Grant(role, "Unknown.Field");
        fixture.Assign(role, all);

        Assert.False(fixture.IsAllowed("Unknown.Field", fixture.Resource()));
    }

    [Fact]
    public void ExactOrganizationalUnitMatchesCurrentOu()
    {
        var fixture = AuthorizationFixture.Create();
        var role = fixture.AddRole();
        var scope = fixture.AddScope(ScopeKind.OrganizationalUnit, "ou-engineering");
        fixture.Grant(role, PermissionCatalog.UserView);
        fixture.Assign(role, scope);

        Assert.True(fixture.IsAllowed(
            PermissionCatalog.UserView,
            fixture.Resource(
                organizationalUnitId: "ou-engineering",
                organizationalUnitAncestry: new HashSet<string> { "ou-engineering", "ou-company" })));
    }

    [Fact]
    public void ExactOrganizationalUnitDoesNotMatchDirectChild()
    {
        var fixture = AuthorizationFixture.Create();
        var role = fixture.AddRole();
        var scope = fixture.AddScope(ScopeKind.OrganizationalUnit, "ou-engineering");
        fixture.Grant(role, PermissionCatalog.UserView);
        fixture.Assign(role, scope);

        Assert.False(fixture.IsAllowed(
            PermissionCatalog.UserView,
            fixture.Resource(
                organizationalUnitId: "ou-platform",
                organizationalUnitAncestry: new HashSet<string> { "ou-platform", "ou-engineering", "ou-company" })));
    }

    [Fact]
    public void OrganizationalUnitSubtreeMatchesDirectChildButNotDifferentTree()
    {
        var fixture = AuthorizationFixture.Create();
        var role = fixture.AddRole();
        var scope = fixture.AddScope(ScopeKind.OrganizationalUnit, "ou-engineering");
        scope.IncludeDescendants = true;
        fixture.Grant(role, PermissionCatalog.UserView);
        fixture.Assign(role, scope);

        Assert.True(fixture.IsAllowed(
            PermissionCatalog.UserView,
            fixture.Resource(
                organizationalUnitId: "ou-platform",
                organizationalUnitAncestry: new HashSet<string> { "ou-platform", "ou-engineering", "ou-company" })));
        Assert.False(fixture.IsAllowed(
            PermissionCatalog.UserView,
            fixture.Resource(
                organizationalUnitId: "ou-payroll",
                organizationalUnitAncestry: new HashSet<string> { "ou-payroll", "ou-finance", "ou-company" })));
    }

    [Fact]
    public void ProtectedResourceRejectsMutatingPermission()
    {
        var fixture = AuthorizationFixture.Create();
        var role = fixture.AddRole();
        var all = fixture.AddScope(ScopeKind.All);
        fixture.Grant(role, PermissionCatalog.UserManage);
        fixture.Assign(role, all);

        Assert.False(fixture.IsAllowed(PermissionCatalog.UserManage, fixture.Resource(isProtected: true)));
    }

    [Fact]
    public void UnknownProtectionStateDeniesMutationButAllowsReadOnlyPermission()
    {
        var fixture = AuthorizationFixture.Create();
        var role = fixture.AddRole();
        var all = fixture.AddScope(ScopeKind.All);
        fixture.Grant(role, PermissionCatalog.UserManage);
        fixture.Grant(role, PermissionCatalog.UserView);
        fixture.Assign(role, all);
        var resource = fixture.Resource(protectionKnown: false);

        Assert.False(fixture.IsAllowed(PermissionCatalog.UserManage, resource));
        Assert.True(fixture.IsAllowed(PermissionCatalog.UserView, resource));
    }

    [Fact]
    public void ViewerPresetDoesNotImplicitlyIncludeExport()
    {
        Assert.DoesNotContain(PermissionCatalog.ReportExport, RolePresets.GetPermissions(BuiltInRoleKinds.Viewer));
    }

    [Fact]
    public void MissingOrInactiveMembershipAndPrincipalFailClosed()
    {
        var fixture = AuthorizationFixture.Create();
        var role = fixture.AddRole();
        var all = fixture.AddScope(ScopeKind.All);
        fixture.Grant(role, PermissionCatalog.UserView);
        fixture.Assign(role, all);

        fixture.Memberships.Clear();
        Assert.False(fixture.IsAllowed(PermissionCatalog.UserView, fixture.Resource()));

        fixture.Memberships.Add(new EnvironmentMembership
        {
            EnvironmentId = fixture.EnvironmentId,
            PrincipalId = fixture.PrincipalId,
            Active = true,
        });
        fixture.Principals[0].Enabled = false;
        Assert.False(fixture.IsAllowed(PermissionCatalog.UserView, fixture.Resource()));
    }

    [Fact]
    public void DirectoryGroupMappingCannotTargetOwnerRole()
    {
        Assert.False(RolePolicy.CanUseForDirectoryGroupMapping(new Role
        {
            BuiltInKind = BuiltInRoleKinds.Owner,
        }));
    }

    private sealed class AuthorizationFixture
    {
        private readonly AuthorizationEvaluator _evaluator = new();

        public Guid EnvironmentId { get; } = Guid.NewGuid();
        public Guid PrincipalId { get; } = Guid.NewGuid();
        public List<Principal> Principals { get; } = [];
        public List<EnvironmentMembership> Memberships { get; } = [];
        public List<Role> Roles { get; } = [];
        public List<RolePermission> RolePermissions { get; } = [];
        public List<Scope> Scopes { get; } = [];
        public List<RoleAssignment> Assignments { get; } = [];

        public static AuthorizationFixture Create()
        {
            var fixture = new AuthorizationFixture();
            fixture.Principals.Add(new Principal { Id = fixture.PrincipalId, Enabled = true });
            fixture.Memberships.Add(new EnvironmentMembership
            {
                EnvironmentId = fixture.EnvironmentId,
                PrincipalId = fixture.PrincipalId,
                Active = true,
            });
            return fixture;
        }

        public Role AddRole(
            string name = "custom",
            string? builtInKind = null,
            Guid? environmentId = null)
        {
            var role = new Role
            {
                EnvironmentId = environmentId ?? EnvironmentId,
                Id = Guid.NewGuid(),
                Name = name,
                BuiltInKind = builtInKind,
            };
            Roles.Add(role);
            return role;
        }

        public Scope AddScope(ScopeKind kind, string? value = null, Guid? environmentId = null)
        {
            var scope = new Scope
            {
                EnvironmentId = environmentId ?? EnvironmentId,
                Id = Guid.NewGuid(),
                Kind = kind,
                Value = value,
            };
            Scopes.Add(scope);
            return scope;
        }

        public void Grant(Role role, string permission, Guid? environmentId = null) =>
            RolePermissions.Add(new RolePermission
            {
                EnvironmentId = environmentId ?? EnvironmentId,
                RoleId = role.Id,
                Permission = permission,
            });

        public void Assign(Role role, Scope scope, Guid? environmentId = null) =>
            Assignments.Add(new RoleAssignment
            {
                EnvironmentId = environmentId ?? EnvironmentId,
                Id = Guid.NewGuid(),
                PrincipalId = PrincipalId,
                RoleId = role.Id,
                ScopeId = scope.Id,
            });

        public ResourceScope Resource(
            string? departmentId = null,
            bool isProtected = false,
            string? organizationalUnitId = null,
            IReadOnlySet<string>? organizationalUnitAncestry = null,
            bool protectionKnown = true) => new(
            EnvironmentId,
            "resource-1",
            departmentId,
            new HashSet<string>(StringComparer.Ordinal),
            new HashSet<string>(StringComparer.Ordinal),
            organizationalUnitAncestry ?? new HashSet<string>(StringComparer.Ordinal),
            isProtected,
            organizationalUnitId,
            protectionKnown);

        public bool IsAllowed(string permission, ResourceScope resource) => _evaluator.IsAllowed(
            EnvironmentId,
            PrincipalId,
            permission,
            resource,
            Principals,
            Memberships,
            Roles,
            RolePermissions,
            Scopes,
            Assignments);
    }
}
