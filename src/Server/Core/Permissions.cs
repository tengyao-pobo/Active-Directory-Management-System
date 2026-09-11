using System.Collections.Frozen;

namespace ItManagement.Core;

public static class PermissionCatalog
{
    public const string EnvironmentView = "Environment.View";
    public const string EnvironmentManage = "Environment.Manage";
    public const string ConnectorManage = "Connector.Manage";
    public const string UserView = "User.View";
    public const string UserCreate = "User.Create";
    public const string UserEdit = "User.Edit";
    public const string UserDisable = "User.Disable";
    public const string UserEnable = "User.Enable";
    public const string UserMove = "User.Move";
    public const string UserManage = "User.Manage";
    public const string UserUnlock = "User.Unlock";
    public const string UserResetPassword = "User.ResetPassword";
    public const string GroupView = "Group.View";
    public const string GroupEditMembership = "Group.EditMembership";
    public const string GroupManage = "Group.Manage";
    public const string ComputerView = "Computer.View";
    public const string ComputerRemote = "Computer.Remote";
    public const string ComputerInventory = "Computer.Inventory";
    public const string ComputerManage = "Computer.Manage";
    public const string ComputerOpenShare = "Computer.OpenShare";
    public const string AssetEdit = "Asset.Edit";
    public const string DeviceTagManage = "DeviceTag.Manage";
    public const string AgentEnrollmentGrantManage = "AgentEnrollmentGrant.Manage";
    public const string InventoryRequest = "Inventory.Request";
    public const string BitLockerStatusView = "BitLocker.ViewStatus";
    public const string BitLockerRecoveryKeyRead = "BitLocker.ViewRecoveryKey";
    public const string GpoView = "GPO.View";
    public const string GpoManage = "GPO.Edit";
    public const string ExchangeView = "Exchange.View";
    public const string ExchangeManage = "Exchange.Manage";
    public const string EntraView = "Entra.View";
    public const string EntraManage = "Entra.Manage";
    public const string ReportView = "Report.View";
    public const string ReportExport = "Report.Export";
    public const string AuditView = "Audit.View";
    public const string SystemView = "System.View";
    public const string SystemManage = "System.Manage";
    public const string RbacManage = "RBAC.Manage";
    public const string OwnerTransfer = "Owner.Transfer";
    public const string OwnerRemove = "Owner.Remove";
    public const string SecurityManage = "Security.Manage";
    public const string ChangeApprove = "Change.Approve";

    private static readonly FrozenSet<string> Known = new HashSet<string>(StringComparer.Ordinal)
    {
        EnvironmentView, EnvironmentManage, ConnectorManage,
        UserView, UserCreate, UserEdit, UserDisable, UserEnable, UserMove,
        UserManage, UserUnlock, UserResetPassword,
        GroupView, GroupEditMembership, GroupManage,
        ComputerView, ComputerRemote, ComputerInventory, ComputerManage, ComputerOpenShare,
        AssetEdit, InventoryRequest, DeviceTagManage, AgentEnrollmentGrantManage,
        BitLockerStatusView, BitLockerRecoveryKeyRead,
        GpoView, GpoManage, ExchangeView, ExchangeManage, EntraView, EntraManage,
        ReportView, ReportExport, AuditView, SystemView, SystemManage, RbacManage,
        OwnerTransfer, OwnerRemove, SecurityManage, ChangeApprove,
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> OwnerOnlyCodes = new HashSet<string>(StringComparer.Ordinal)
    {
        EnvironmentManage,
        ConnectorManage,
        RbacManage,
        OwnerTransfer,
        OwnerRemove,
        SecurityManage,
        SystemManage,
        DeviceTagManage,
        AgentEnrollmentGrantManage,
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> ReadOnlyCodes = new HashSet<string>(StringComparer.Ordinal)
    {
        EnvironmentView,
        UserView,
        GroupView,
        ComputerView,
        ComputerInventory,
        BitLockerStatusView,
        GpoView,
        ExchangeView,
        EntraView,
        ReportView,
        AuditView,
        SystemView,
    }.ToFrozenSet(StringComparer.Ordinal);

    public static IReadOnlySet<string> All { get; } = Known;
    public static IReadOnlySet<string> OwnerOnly { get; } = OwnerOnlyCodes;

    public static bool IsKnown(string permission) => Known.Contains(permission);
    public static bool IsOwnerOnly(string permission) => OwnerOnlyCodes.Contains(permission);
    public static bool IsReadOnly(string permission) => ReadOnlyCodes.Contains(permission);
}

public static class BuiltInRoleKinds
{
    public const string Owner = "Owner";
    public const string Admin = "Admin";
    public const string Manager = "Manager";
    public const string Member = "Member";
    public const string Viewer = "Viewer";
    public const string Hr = "HR";
}

public static class RolePresets
{
    private static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> Presets =
        new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal)
        {
            [BuiltInRoleKinds.Owner] = PermissionCatalog.All.ToFrozenSet(StringComparer.Ordinal),
            [BuiltInRoleKinds.Admin] = Set(
                PermissionCatalog.EnvironmentView, PermissionCatalog.UserView, PermissionCatalog.UserCreate,
                PermissionCatalog.UserEdit, PermissionCatalog.UserDisable, PermissionCatalog.UserEnable,
                PermissionCatalog.UserMove, PermissionCatalog.UserUnlock, PermissionCatalog.UserResetPassword,
                PermissionCatalog.GroupView, PermissionCatalog.GroupEditMembership, PermissionCatalog.ComputerView,
                PermissionCatalog.ComputerRemote, PermissionCatalog.ComputerInventory,
                PermissionCatalog.ComputerOpenShare, PermissionCatalog.AssetEdit, PermissionCatalog.InventoryRequest,
                PermissionCatalog.BitLockerStatusView, PermissionCatalog.GpoView, PermissionCatalog.ReportView,
                PermissionCatalog.ReportExport, PermissionCatalog.AuditView, PermissionCatalog.SystemView,
                PermissionCatalog.ChangeApprove),
            [BuiltInRoleKinds.Manager] = Set(
                PermissionCatalog.EnvironmentView, PermissionCatalog.UserView, PermissionCatalog.GroupView,
                PermissionCatalog.ComputerView, PermissionCatalog.ComputerInventory,
                PermissionCatalog.BitLockerStatusView, PermissionCatalog.ReportView),
            [BuiltInRoleKinds.Member] = Set(
                PermissionCatalog.UserView, PermissionCatalog.UserUnlock, PermissionCatalog.UserResetPassword,
                PermissionCatalog.GroupView, PermissionCatalog.ComputerView, PermissionCatalog.ComputerInventory,
                PermissionCatalog.ComputerRemote, PermissionCatalog.AssetEdit,
                PermissionCatalog.InventoryRequest, PermissionCatalog.BitLockerStatusView),
            [BuiltInRoleKinds.Viewer] = Set(
                PermissionCatalog.EnvironmentView, PermissionCatalog.UserView, PermissionCatalog.GroupView,
                PermissionCatalog.ComputerView, PermissionCatalog.ComputerInventory,
                PermissionCatalog.BitLockerStatusView, PermissionCatalog.ReportView,
                PermissionCatalog.SystemView),
            [BuiltInRoleKinds.Hr] = Set(
                PermissionCatalog.UserView, PermissionCatalog.GroupView, PermissionCatalog.ComputerView,
                PermissionCatalog.ReportView),
        };

    public static IReadOnlySet<string> GetPermissions(string builtInKind) =>
        Presets.TryGetValue(builtInKind, out var permissions)
            ? permissions
            : throw new ArgumentOutOfRangeException(nameof(builtInKind), builtInKind, "Unknown built-in role kind.");

    private static IReadOnlySet<string> Set(params string[] permissions) =>
        permissions.ToFrozenSet(StringComparer.Ordinal);
}

public static class RolePolicy
{
    public static bool CanUseForDirectoryGroupMapping(Role? role) =>
        role is not null && !string.Equals(role.BuiltInKind, BuiltInRoleKinds.Owner, StringComparison.Ordinal);
}
