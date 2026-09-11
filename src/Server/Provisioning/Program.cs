using System.Security.Cryptography;
using System.Text;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

if (args.Length == 0)
{
    Console.WriteLine("Commands: migrate | create-environment <name> <dns> | bootstrap-owner <environment-guid> <operator-guid> <local-name> | provision-windows <operator-guid> <SID> <display-name> | enrollment-grant <principal-guid> | provision-connector-principal <environment-guid> <operator-guid> <name>");
    return;
}
if (Environment.GetEnvironmentVariable("CONSOLE_PROVISIONING_ALLOWED") != "true")
    throw new InvalidOperationException("Provisioning requires explicit CONSOLE_PROVISIONING_ALLOWED=true and an offline provisioning database identity.");
var connection = Environment.GetEnvironmentVariable("ConnectionStrings__Console") ?? throw new InvalidOperationException("Database connection required.");
await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(connection).Options);
if (args[0] == "migrate") { await db.Database.MigrateAsync(); Console.WriteLine("Migrations applied."); return; }
await using var tx = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);
var now = DateTimeOffset.UtcNow;
switch (args[0])
{
    case "provision-connector-principal" when args.Length == 4:
        var connectorEnv = Guid.Parse(args[1]); var connectorOperator = Guid.Parse(args[2]);
        if (connectorOperator == Guid.Empty || args[3].Length is < 1 or > 128 || !await db.Environments.AnyAsync(x => x.Id == connectorEnv))
            throw new ArgumentException("Valid environment, operator identity and name required.");
        var connector = new Principal { Id = Guid.NewGuid(), OperatorId = connectorOperator, Issuer = "connector", Subject = args[3], DisplayName = args[3], Enabled = true };
        db.Principals.Add(connector);
        db.Memberships.Add(new EnvironmentMembership { EnvironmentId = connectorEnv, PrincipalId = connector.Id, Active = true });
        db.SecurityEvents.Add(new SecurityEvent { PrincipalId = connector.Id, Action = "ConnectorPrincipalProvisioned", Result = "Success", OccurredAt = now, SourceIp = "local-cli" });
        await db.SaveChangesAsync(); await tx.CommitAsync();
        Console.WriteLine($"Connector principal ID: {connector.Id}"); return;
    case "create-environment" when args.Length == 3:
        if (args[1].Length is < 1 or > 160 || Uri.CheckHostName(args[2]) != UriHostNameType.Dns) throw new ArgumentException("Name and DNS required.");
        var env = new ManagedEnvironment { Id = Guid.NewGuid(), Name = args[1], CanonicalDns = args[2], DefaultLocale = "zh-TW", Version = 1 };
        db.Environments.Add(env);
        db.Scopes.Add(new Scope { EnvironmentId = env.Id, Id = Guid.NewGuid(), Kind = ScopeKind.All });
        foreach (var kind in new[] { "Owner", "Admin", "Manager", "Member", "Viewer", "HR" })
        {
            var role = new Role { EnvironmentId = env.Id, Id = Guid.NewGuid(), Name = kind, BuiltInKind = kind };
            db.Roles.Add(role);
            foreach (var p in RolePresets.GetPermissions(kind)) db.RolePermissions.Add(new RolePermission { EnvironmentId = env.Id, RoleId = role.Id, Permission = p });
        }
        db.SecurityEvents.Add(new SecurityEvent { Action = "EnvironmentProvisioned", Result = "Success", OccurredAt = now, SourceIp = "local-cli" });
        await db.SaveChangesAsync(); await tx.CommitAsync();
        Console.WriteLine($"Environment ID: {env.Id}"); return;
    case "bootstrap-owner" when args.Length == 4:
        var environmentId = Guid.Parse(args[1]); var operatorId = Guid.Parse(args[2]);
        if (operatorId == Guid.Empty || args[3].Length is < 1 or > 128) throw new ArgumentException("Stable operator ID and account name required.");
        if (!await db.Environments.AnyAsync(x => x.Id == environmentId)) throw new InvalidOperationException("Unknown environment.");
        // Offline provisioning is explicit. There is no web first-login promotion.
        var secret = ReadPassword();
        if (secret.Length is < 20 or > 1024) throw new ArgumentException("Use an offline-vaulted random password of at least 20 characters.");
        var principal = new Principal { Id = Guid.NewGuid(), OperatorId = operatorId, Issuer = "local", Subject = args[3], DisplayName = args[3], Enabled = true };
        db.Principals.Add(principal);
        db.LocalCredentials.Add(new LocalCredential { PrincipalId = principal.Id,
            PasswordHash = new PasswordHasher<Principal>(Microsoft.Extensions.Options.Options.Create(new PasswordHasherOptions { IterationCount = 210000 })).HashPassword(principal, secret) });
        db.Memberships.Add(new EnvironmentMembership { EnvironmentId = environmentId, PrincipalId = principal.Id, Active = true });
        var owner = await db.Roles.SingleAsync(x => x.EnvironmentId == environmentId && x.BuiltInKind == "Owner");
        var scope = await db.Scopes.FirstAsync(x => x.EnvironmentId == environmentId && x.Kind == ScopeKind.All);
        db.Assignments.Add(new RoleAssignment { EnvironmentId = environmentId, Id = Guid.NewGuid(), PrincipalId = principal.Id, RoleId = owner.Id, ScopeId = scope.Id });
        var token = await Grant(db, principal.Id, now);
        db.SecurityEvents.Add(new SecurityEvent { PrincipalId = principal.Id, Action = "EmergencyOwnerProvisioned", Result = "PasskeyEnrollmentRequired", OccurredAt = now, SourceIp = "local-cli" });
        await db.SaveChangesAsync(); await tx.CommitAsync();
        Console.WriteLine($"Principal ID: {principal.Id}");
        Console.WriteLine("ONE-TIME PASSKEY ENROLLMENT TOKEN (10 minutes; protect this console output):");
        Console.WriteLine(token); return;
    case "provision-windows" when args.Length == 4:
        var person = Guid.Parse(args[1]);
        if (person == Guid.Empty || !System.Text.RegularExpressions.Regex.IsMatch(args[2], "^S-1-[0-9]+(-[0-9]+)+$", System.Text.RegularExpressions.RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50))) throw new ArgumentException("Operator ID and Windows SID required.");
        var windows = new Principal { Id = Guid.NewGuid(), OperatorId = person, Issuer = "windows", Subject = args[2], DisplayName = args[3], Enabled = true };
        db.Principals.Add(windows);
        db.SecurityEvents.Add(new SecurityEvent { PrincipalId = windows.Id, Action = "WindowsPrincipalProvisioned", Result = "NoRolesGranted", OccurredAt = now, SourceIp = "local-cli" });
        await db.SaveChangesAsync(); await tx.CommitAsync(); Console.WriteLine($"Principal ID: {windows.Id}"); return;
    case "enrollment-grant" when args.Length == 2:
        var principalId = Guid.Parse(args[1]);
        if (!await db.Principals.AnyAsync(x => x.Id == principalId && x.Enabled)) throw new InvalidOperationException("Active principal required.");
        var enrollmentToken = await Grant(db, principalId, now);
        db.SecurityEvents.Add(new SecurityEvent { PrincipalId = principalId, Action = "PasskeyGrantIssued", Result = "Success", OccurredAt = now, SourceIp = "local-cli" });
        await db.SaveChangesAsync(); await tx.CommitAsync();
        Console.WriteLine("ONE-TIME PASSKEY ENROLLMENT TOKEN (10 minutes; protect this console output):"); Console.WriteLine(enrollmentToken); return;
    default: throw new ArgumentException("Unknown command or invalid arguments.");
}

static async Task<string> Grant(ConsoleDbContext db, Guid principal, DateTimeOffset now)
{
    await db.EnrollmentGrants.Where(x => x.PrincipalId == principal && x.ConsumedAt == null)
        .ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsumedAt, now));
    await db.Ceremonies.Where(x => x.PrincipalId == principal && x.Kind == "register" && x.ConsumedAt == null)
        .ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsumedAt, now));
    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    db.EnrollmentGrants.Add(new PasskeyEnrollmentGrant { IdHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))), PrincipalId = principal, ExpiresAt = now.AddMinutes(10) });
    return token;
}
static string ReadPassword()
{
    if (Console.IsInputRedirected) return Console.ReadLine() ?? "";
    Console.Write("Emergency password (hidden): "); var text = new StringBuilder();
    for (var key = Console.ReadKey(true); key.Key != ConsoleKey.Enter; key = Console.ReadKey(true))
    {
        if (key.Key == ConsoleKey.Backspace) { if (text.Length > 0) text.Length--; }
        else if (!char.IsControl(key.KeyChar)) text.Append(key.KeyChar);
    }
    Console.WriteLine(); return text.ToString();
}
