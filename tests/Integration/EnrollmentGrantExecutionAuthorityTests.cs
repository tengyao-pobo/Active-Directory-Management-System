using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Fact]
    public async Task CurrentAuthorityMatchesLockedQueuedOperationBaselineAndRejectsDeadline()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        Assert.True(await CurrentAuthority(db, operation, operation.QueuedAt));
        Assert.False(await CurrentAuthority(db, operation, operation.AuthorizationNotAfter));
    }

    [Theory]
    [InlineData("requester-disabled")]
    [InlineData("approver-disabled")]
    [InlineData("requester-membership")]
    [InlineData("approver-membership")]
    [InlineData("requester-operator")]
    [InlineData("approver-operator")]
    [InlineData("environment-version")]
    [InlineData("sync-generation")]
    [InlineData("sync-status")]
    [InlineData("sync-stale")]
    [InlineData("sync-future")]
    [InlineData("target-missing")]
    [InlineData("target-kind")]
    [InlineData("requester-view")]
    [InlineData("requester-manage")]
    [InlineData("approver-view")]
    [InlineData("approver-approve")]
    [InlineData("manage-non-owner")]
    public async Task CurrentAuthorityFailsClosedForEveryCurrentStateDrift(string fault)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        var checkedAt = operation.QueuedAt;

        switch (fault)
        {
            case "requester-disabled":
                await db.Principals.Where(x => x.Id == operation.RequesterId)
                    .ExecuteUpdateAsync(x => x.SetProperty(p => p.Enabled, false)); break;
            case "approver-disabled":
                await db.Principals.Where(x => x.Id == operation.ApproverId)
                    .ExecuteUpdateAsync(x => x.SetProperty(p => p.Enabled, false)); break;
            case "requester-membership":
                await db.Memberships.Where(x => x.EnvironmentId == operation.EnvironmentId && x.PrincipalId == operation.RequesterId)
                    .ExecuteUpdateAsync(x => x.SetProperty(m => m.Active, false)); break;
            case "approver-membership":
                await db.Memberships.Where(x => x.EnvironmentId == operation.EnvironmentId && x.PrincipalId == operation.ApproverId)
                    .ExecuteUpdateAsync(x => x.SetProperty(m => m.Active, false)); break;
            case "requester-operator":
                Assert.False(await CurrentAuthorityWithOperator(db, operation, checkedAt, requester: true)); return;
            case "approver-operator":
                Assert.False(await CurrentAuthorityWithOperator(db, operation, checkedAt, requester: false)); return;
            case "environment-version":
                await db.Environments.Where(x => x.Id == operation.EnvironmentId)
                    .ExecuteUpdateAsync(x => x.SetProperty(e => e.Version, e => e.Version + 1)); break;
            case "sync-generation":
                await db.DirectorySync.Where(x => x.EnvironmentId == operation.EnvironmentId)
                    .ExecuteUpdateAsync(x => x.SetProperty(s => s.Generation, Guid.NewGuid())); break;
            case "sync-status":
                await db.DirectorySync.Where(x => x.EnvironmentId == operation.EnvironmentId)
                    .ExecuteUpdateAsync(x => x.SetProperty(s => s.Status, "Failed")); break;
            case "sync-stale":
                await db.DirectorySync.Where(x => x.EnvironmentId == operation.EnvironmentId)
                    .ExecuteUpdateAsync(x => x.SetProperty(s => s.CompletedAt, checkedAt.AddMinutes(-15).AddTicks(-10))); break;
            case "sync-future":
                await db.DirectorySync.Where(x => x.EnvironmentId == operation.EnvironmentId)
                    .ExecuteUpdateAsync(x => x.SetProperty(s => s.CompletedAt, checkedAt.AddTicks(10))); break;
            case "target-missing":
                await db.DirectoryObjects.Where(x => x.EnvironmentId == operation.EnvironmentId && x.Id == operation.DirectoryObjectId)
                    .ExecuteDeleteAsync(); break;
            case "target-kind":
                await db.DirectoryObjects.Where(x => x.EnvironmentId == operation.EnvironmentId && x.Id == operation.DirectoryObjectId)
                    .ExecuteUpdateAsync(x => x.SetProperty(o => o.Kind, "User")); break;
            case "requester-view":
                await RemovePermission(db, operation.EnvironmentId, operation.RequesterId, PermissionCatalog.ComputerView); break;
            case "requester-manage":
                await RemovePermission(db, operation.EnvironmentId, operation.RequesterId, PermissionCatalog.AgentEnrollmentGrantManage); break;
            case "approver-view":
                await RemovePermission(db, operation.EnvironmentId, operation.ApproverId, PermissionCatalog.ComputerView); break;
            case "approver-approve":
                await RemovePermission(db, operation.EnvironmentId, operation.ApproverId, PermissionCatalog.ChangeApprove); break;
            case "manage-non-owner":
                await AddOrdinaryManageRole(db, operation); break;
            default: throw new ArgumentOutOfRangeException(nameof(fault));
        }

        Assert.False(await CurrentAuthority(db, operation, checkedAt));
    }

    [Fact]
    public async Task ComputerPermissionScopeParityIsClosedAndDeterministic()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        var assignment = await db.Assignments.SingleAsync(x => x.EnvironmentId == operation.EnvironmentId &&
            x.PrincipalId == operation.ApproverId);
        var scope = await db.Scopes.SingleAsync(x => x.EnvironmentId == operation.EnvironmentId && x.Id == assignment.ScopeId);
        var target = await db.DirectoryObjects.SingleAsync(x => x.EnvironmentId == operation.EnvironmentId &&
            x.Id == operation.DirectoryObjectId);
        var directOu = Guid.NewGuid(); var ancestorOu = Guid.NewGuid();
        target.Department = "Finance"; target.ParentOuId = directOu; target.OuAncestry = [directOu, ancestorOu];
        await db.SaveChangesAsync();

        async Task<bool> Check(ScopeKind kind, string? value, bool descendants = false)
        {
            scope.Kind = kind; scope.Value = value; scope.IncludeDescendants = descendants;
            await db.SaveChangesAsync();
            return await HasComputerPermission(db, operation, operation.ApproverId, PermissionCatalog.ComputerView);
        }

        Assert.True(await Check(ScopeKind.All, null));
        Assert.True(await Check(ScopeKind.Department, "Finance"));
        Assert.False(await Check(ScopeKind.Department, "finance"));
        Assert.False(await Check(ScopeKind.Department, string.Empty));
        Assert.False(await Check(ScopeKind.Group, null));

        foreach (var value in new[]
        {
            directOu.ToString("D"), directOu.ToString("N"), directOu.ToString("B"), directOu.ToString("P"),
            directOu.ToString("D").ToUpperInvariant()
        }) Assert.True(await Check(ScopeKind.OrganizationalUnit, value));
        Assert.True(await Check(ScopeKind.OrganizationalUnit, ancestorOu.ToString("D"), descendants: true));
        Assert.False(await Check(ScopeKind.OrganizationalUnit, ancestorOu.ToString("D"), descendants: false));
        Assert.False(await Check(ScopeKind.OrganizationalUnit, "{0x00000000,0,0,{0,0,0,0,0,0,0,1}}"));
        Assert.False(await Check(ScopeKind.OrganizationalUnit, $"\u00a0{directOu:D}\u00a0"));

        var tagId = Guid.NewGuid(); var now = operation.QueuedAt;
        db.DeviceTags.Add(new DeviceTag { EnvironmentId = operation.EnvironmentId, Id = tagId, Key = "Test",
            CreatedAt = now, UpdatedAt = now, CreatedBy = operation.RequesterId, UpdatedBy = operation.RequesterId });
        db.DeviceTagAssignments.Add(new DeviceTagAssignment { EnvironmentId = operation.EnvironmentId, TagId = tagId,
            ObjectId = operation.DirectoryObjectId, CreatedAt = now, CreatedBy = operation.RequesterId });
        await db.SaveChangesAsync();
        Assert.True(await Check(ScopeKind.DeviceTag, tagId.ToString("D")));
        Assert.False(await Check(ScopeKind.DeviceTag, tagId.ToString("D"), descendants: true));
        Assert.False(await Check(ScopeKind.DeviceTag, tagId.ToString("D").ToUpperInvariant()));
        await db.DeviceTags.Where(x => x.EnvironmentId == operation.EnvironmentId && x.Id == tagId)
            .ExecuteUpdateAsync(x => x.SetProperty(tag => tag.ArchivedAt, now));
        Assert.True(await Check(ScopeKind.DeviceTag, tagId.ToString("D")));
    }

    [Fact]
    public async Task ComputerPermissionRejectsUnknownPermissionAndManageOnOrdinaryRole()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        Assert.False(await HasComputerPermission(db, operation, operation.RequesterId, "Computer.Unknown"));
        await AddOrdinaryManageRole(db, operation);
        Assert.False(await HasComputerPermission(db, operation, operation.RequesterId,
            PermissionCatalog.AgentEnrollmentGrantManage));
    }

    private static Task<bool> CurrentAuthority(ConsoleDbContext db, EnrollmentGrantOperation operation,
        DateTimeOffset checkedAt) => db.Database.SqlQuery<bool>($"""
            SELECT enrollment_execution.current_authority_matches(stored,{checkedAt}) AS "Value"
            FROM public."EnrollmentGrantOperations" stored
            WHERE stored."EnvironmentId"={operation.EnvironmentId} AND stored."Id"={operation.Id}
            """).SingleAsync();

    private static Task<bool> HasComputerPermission(ConsoleDbContext db, EnrollmentGrantOperation operation,
        Guid principal, string permission) => db.Database.SqlQuery<bool>($"""
            SELECT enrollment_execution.has_computer_permission({operation.EnvironmentId},{principal},
                {operation.DirectoryObjectId},{operation.DirectoryGeneration},{permission}) AS "Value"
            """).SingleAsync();

    private static Task<bool> CurrentAuthorityWithOperator(ConsoleDbContext db, EnrollmentGrantOperation operation,
        DateTimeOffset checkedAt, bool requester)
    {
        var property = requester ? "RequesterOperatorId" : "ApproverOperatorId";
        var changedOperator = Guid.NewGuid();
        return db.Database.SqlQuery<bool>($"""
            SELECT enrollment_execution.current_authority_matches(
                pg_catalog.jsonb_populate_record(NULL::public."EnrollmentGrantOperations",
                    pg_catalog.to_jsonb(stored)||pg_catalog.jsonb_build_object({property},{changedOperator})),{checkedAt}) AS "Value"
            FROM public."EnrollmentGrantOperations" stored
            WHERE stored."EnvironmentId"={operation.EnvironmentId} AND stored."Id"={operation.Id}
            """).SingleAsync();
    }

    private static async Task AddOrdinaryManageRole(ConsoleDbContext db, EnrollmentGrantOperation operation)
    {
        await RemovePermission(db, operation.EnvironmentId, operation.RequesterId,
            PermissionCatalog.AgentEnrollmentGrantManage);
        var scope = await db.Assignments.Where(x => x.EnvironmentId == operation.EnvironmentId &&
            x.PrincipalId == operation.RequesterId).Select(x => x.ScopeId).FirstAsync();
        var roleId = Guid.NewGuid();
        db.Roles.Add(new Role { EnvironmentId = operation.EnvironmentId, Id = roleId,
            Name = $"ordinary-{roleId:N}", BuiltInKind = null });
        db.RolePermissions.Add(new RolePermission { EnvironmentId = operation.EnvironmentId, RoleId = roleId,
            Permission = PermissionCatalog.AgentEnrollmentGrantManage });
        db.Assignments.Add(new RoleAssignment { EnvironmentId = operation.EnvironmentId, Id = Guid.NewGuid(),
            PrincipalId = operation.RequesterId, RoleId = roleId, ScopeId = scope });
        await db.SaveChangesAsync();
    }

    private static async Task RemovePermission(ConsoleDbContext db, Guid environment, Guid principal, string permission)
    {
        await db.RolePermissions.Where(value => value.EnvironmentId == environment && value.Permission == permission &&
                db.Assignments.Any(assignment => assignment.EnvironmentId == environment && assignment.PrincipalId == principal &&
                    assignment.RoleId == value.RoleId))
            .ExecuteDeleteAsync();
    }
}
