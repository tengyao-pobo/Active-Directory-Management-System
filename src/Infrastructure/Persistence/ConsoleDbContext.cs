using ItManagement.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore.Storage;

namespace ItManagement.Persistence;

public sealed class ConsoleDbContext(DbContextOptions<ConsoleDbContext> options) : DbContext(options)
{
    public DbSet<ManagedEnvironment> Environments => Set<ManagedEnvironment>();
    public DbSet<Principal> Principals => Set<Principal>();
    public DbSet<EnvironmentMembership> Memberships => Set<EnvironmentMembership>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<Scope> Scopes => Set<Scope>();
    public DbSet<RoleAssignment> Assignments => Set<RoleAssignment>();
    public DbSet<DirectoryGroupMapping> GroupMappings => Set<DirectoryGroupMapping>();
    public DbSet<AuditRecord> Audit => Set<AuditRecord>();
    public DbSet<OutboxMessage> Outbox => Set<OutboxMessage>();
    public DbSet<ChangePlan> Plans => Set<ChangePlan>();
    public DbSet<ChangePlanItem> PlanItems => Set<ChangePlanItem>();
    public DbSet<ChangeApproval> Approvals => Set<ChangeApproval>();
    public DbSet<LocalCredential> LocalCredentials => Set<LocalCredential>();
    public DbSet<PlatformSession> Sessions => Set<PlatformSession>();
    public DbSet<Passkey> Passkeys => Set<Passkey>();
    public DbSet<AuthCeremony> Ceremonies => Set<AuthCeremony>();
    public DbSet<PasskeyEnrollmentGrant> EnrollmentGrants => Set<PasskeyEnrollmentGrant>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
    public DbSet<PrincipalPreference> Preferences => Set<PrincipalPreference>();
    public DbSet<DirectoryObjectRecord> DirectoryObjects => Set<DirectoryObjectRecord>();
    public DbSet<DirectorySyncState> DirectorySync => Set<DirectorySyncState>();

    public async Task<IDbContextTransaction> BeginEnvironment(Guid environmentId, Guid principalId, CancellationToken ct)
    {
        var tx = await Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
        await Database.ExecuteSqlInterpolatedAsync($"SELECT set_config('app.environment_id', {environmentId.ToString()}, true), set_config('app.principal_id', {principalId.ToString()}, true)", ct);
        return tx;
    }

    protected override void OnModelCreating(ModelBuilder b)
    {
        ConfigureTenant<DirectoryObjectRecord>(b, "DirectoryObjects");
        b.Entity<DirectoryObjectRecord>().HasIndex(x => new { x.EnvironmentId, x.Generation, x.Kind, x.Id });
        b.Entity<DirectoryObjectRecord>().Property(x => x.Kind).HasMaxLength(32);
        b.Entity<DirectoryObjectRecord>().Property(x => x.DistinguishedName).HasMaxLength(4096);
        b.Entity<DirectoryObjectRecord>().Property(x => x.Name).HasMaxLength(256);
        b.Entity<DirectoryObjectRecord>().Property(x => x.SamAccountName).HasMaxLength(256);
        b.Entity<DirectoryObjectRecord>().Property(x => x.Department).HasMaxLength(256);
        b.Entity<DirectoryObjectRecord>().Property(x => x.ObjectSid).HasMaxLength(256);
        ConfigureTenant<DirectorySyncState>(b, "DirectorySync");
        b.Entity<DirectorySyncState>().HasIndex(x => x.EnvironmentId).IsUnique();
        b.Entity<DirectorySyncState>().Property(x => x.Status).HasMaxLength(32);
        b.Entity<DirectorySyncState>().Property(x => x.ErrorCode).HasMaxLength(64);
        b.Entity<ManagedEnvironment>().ToTable("Environments").HasKey(x => x.Id);
        b.Entity<ManagedEnvironment>().Property(x => x.Version).IsConcurrencyToken();
        b.Entity<ManagedEnvironment>().Property(x => x.Name).HasMaxLength(160);
        b.Entity<ManagedEnvironment>().Property(x => x.CanonicalDns).HasMaxLength(253);
        b.Entity<ManagedEnvironment>().Property(x => x.DefaultLocale).HasMaxLength(16);
        b.Entity<Principal>().ToTable("Principals").HasKey(x => x.Id);
        b.Entity<Principal>().HasIndex(x => new { x.Issuer, x.Subject }).IsUnique();
        b.Entity<Principal>().Property(x => x.Subject).HasMaxLength(256);
        b.Entity<Principal>().Property(x => x.Issuer).HasMaxLength(128);
        b.Entity<Principal>().Property(x => x.DisplayName).HasMaxLength(256);
        b.Entity<EnvironmentMembership>().ToTable("Memberships").HasKey(x => new { x.EnvironmentId, x.PrincipalId });
        b.Entity<EnvironmentMembership>().HasOne<ManagedEnvironment>().WithMany().HasForeignKey(x => x.EnvironmentId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<EnvironmentMembership>().HasOne<Principal>().WithMany().HasForeignKey(x => x.PrincipalId).OnDelete(DeleteBehavior.Restrict);

        ConfigureTenant<Role>(b, "Roles");
        b.Entity<Role>().HasIndex(x => new { x.EnvironmentId, x.Name }).IsUnique();
        b.Entity<Role>().Property(x => x.Name).HasMaxLength(128);
        b.Entity<Role>().Property(x => x.BuiltInKind).HasMaxLength(32);
        ConfigureTenant<Scope>(b, "Scopes");
        b.Entity<Scope>().Property(x => x.Value).HasMaxLength(256);
        b.Entity<RolePermission>().ToTable("RolePermissions").HasKey(x => new { x.EnvironmentId, x.RoleId, x.Permission });
        b.Entity<RolePermission>().Property(x => x.Permission).HasMaxLength(128);
        b.Entity<RolePermission>().HasOne<Role>().WithMany().HasForeignKey(x => new { x.EnvironmentId, x.RoleId }).OnDelete(DeleteBehavior.Restrict);
        ConfigureTenant<RoleAssignment>(b, "Assignments");
        b.Entity<RoleAssignment>().HasOne<Role>().WithMany().HasForeignKey(x => new { x.EnvironmentId, x.RoleId }).OnDelete(DeleteBehavior.Restrict);
        b.Entity<RoleAssignment>().HasOne<Scope>().WithMany().HasForeignKey(x => new { x.EnvironmentId, x.ScopeId }).OnDelete(DeleteBehavior.Restrict);
        b.Entity<RoleAssignment>().HasOne<EnvironmentMembership>().WithMany().HasForeignKey(x => new { x.EnvironmentId, x.PrincipalId }).OnDelete(DeleteBehavior.Restrict);
        ConfigureTenant<DirectoryGroupMapping>(b, "GroupMappings");
        b.Entity<DirectoryGroupMapping>().Property(x => x.GroupSid).HasMaxLength(256);
        b.Entity<DirectoryGroupMapping>().HasOne<Role>().WithMany().HasForeignKey(x => new { x.EnvironmentId, x.RoleId }).OnDelete(DeleteBehavior.Restrict);
        b.Entity<DirectoryGroupMapping>().HasOne<Scope>().WithMany().HasForeignKey(x => new { x.EnvironmentId, x.ScopeId }).OnDelete(DeleteBehavior.Restrict);
        ConfigureTenant<AuditRecord>(b, "Audit");
        b.Entity<AuditRecord>().Property(x => x.Action).HasMaxLength(128);
        b.Entity<AuditRecord>().Property(x => x.Result).HasMaxLength(64);
        b.Entity<AuditRecord>().Property(x => x.Reason).HasMaxLength(1024);
        b.Entity<AuditRecord>().HasIndex(x => new { x.EnvironmentId, x.OccurredAt, x.Id });
        ConfigureTenant<OutboxMessage>(b, "Outbox");
        b.Entity<OutboxMessage>().Property(x => x.Payload).HasColumnType("jsonb");
        ConfigureTenant<ChangePlan>(b, "Plans");
        b.Entity<ChangePlan>().Property(x => x.ImmutablePlanJson).HasColumnType("jsonb");
        b.Entity<ChangePlan>().Property(x => x.State).IsConcurrencyToken();
        ConfigureTenant<ChangePlanItem>(b, "PlanItems");
        b.Entity<ChangePlanItem>().HasOne<ChangePlan>().WithMany(x => x.Items).HasForeignKey(x => new { x.EnvironmentId, x.PlanId }).OnDelete(DeleteBehavior.Restrict);
        ConfigureTenant<ChangeApproval>(b, "Approvals");
        b.Entity<ChangeApproval>().HasOne<ChangePlan>().WithMany().HasForeignKey(x => new { x.EnvironmentId, x.PlanId }).OnDelete(DeleteBehavior.Restrict);
        b.Entity<ChangeApproval>().HasIndex(x => new { x.EnvironmentId, x.PlanId }).IsUnique();

        b.Entity<LocalCredential>().ToTable("LocalCredentials").HasKey(x => x.PrincipalId);
        b.Entity<LocalCredential>().Property(x => x.Version).IsConcurrencyToken();
        b.Entity<LocalCredential>().HasOne<Principal>().WithMany().HasForeignKey(x => x.PrincipalId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<PlatformSession>().ToTable("Sessions").HasKey(x => x.IdHash);
        b.Entity<PlatformSession>().HasOne<Principal>().WithMany().HasForeignKey(x => x.PrincipalId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<PlatformSession>().HasIndex(x => x.ExpiresAt);
        b.Entity<Passkey>().ToTable("Passkeys").HasKey(x => x.CredentialId);
        b.Entity<Passkey>().HasOne<Principal>().WithMany().HasForeignKey(x => x.PrincipalId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<Passkey>().Property(x => x.Version).IsConcurrencyToken();
        b.Entity<AuthCeremony>().ToTable("Ceremonies").HasKey(x => x.IdHash);
        b.Entity<AuthCeremony>().HasOne<Principal>().WithMany().HasForeignKey(x => x.PrincipalId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<PasskeyEnrollmentGrant>().ToTable("EnrollmentGrants").HasKey(x => x.IdHash);
        b.Entity<PasskeyEnrollmentGrant>().HasOne<Principal>().WithMany().HasForeignKey(x => x.PrincipalId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<SecurityEvent>().ToTable("SecurityEvents").HasKey(x => x.Id);
        b.Entity<PrincipalPreference>().ToTable("Preferences").HasKey(x => x.PrincipalId);
        b.Entity<PrincipalPreference>().Property(x => x.Locale).HasMaxLength(16);
        b.Entity<PrincipalPreference>().HasOne<Principal>().WithMany().HasForeignKey(x => x.PrincipalId).OnDelete(DeleteBehavior.Restrict);
    }

    private static void ConfigureTenant<T>(ModelBuilder b, string table) where T : class
    {
        b.Entity<T>().ToTable(table).HasKey("EnvironmentId", "Id");
        b.Entity<T>().HasOne<ManagedEnvironment>().WithMany().HasForeignKey("EnvironmentId").OnDelete(DeleteBehavior.Restrict);
    }
}

public sealed class DesignTimeFactory : IDesignTimeDbContextFactory<ConsoleDbContext>
{
    public ConsoleDbContext CreateDbContext(string[] args) => new(new DbContextOptionsBuilder<ConsoleDbContext>()
        .UseNpgsql(Environment.GetEnvironmentVariable("ConnectionStrings__Console") ?? "Host=localhost;Database=design_time_only;Username=unused")
        .Options);
}
