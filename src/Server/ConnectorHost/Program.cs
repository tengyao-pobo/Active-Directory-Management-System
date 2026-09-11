using ItManagement.ConnectorHost;
using ItManagement.DirectoryConnector;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

// One bounded read-only AD scan. Schedule with the deployment's service manager.
// No LDAP write implementation or browser-supplied connection settings exist here.
if (Environment.GetEnvironmentVariable("CONSOLE_CONNECTOR_ALLOWED") != "true")
    throw new InvalidOperationException("Connector execution must be explicitly enabled in protected service configuration.");
string Required(string key) => Environment.GetEnvironmentVariable(key) ?? throw new InvalidOperationException($"Missing {key}");
var environment = Guid.Parse(Required("CONSOLE_CONNECTOR_ENVIRONMENT_ID"));
var principal = Guid.Parse(Required("CONSOLE_CONNECTOR_PRINCIPAL_ID"));
var options = new DirectoryConnectorOptions { Host = Required("CONSOLE_CONNECTOR_HOST"), BaseDn = Required("CONSOLE_CONNECTOR_BASE_DN"),
    ExpectedDomainId = Guid.Parse(Required("CONSOLE_CONNECTOR_DOMAIN_ID")) };
await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(Required("ConnectionStrings__Console")).Options);
var unsafeRole = await db.Database.SqlQueryRaw<bool>("""
    SELECT (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR
        EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND (
            (c.relname NOT IN ('DirectoryObjects','DirectorySync') AND has_table_privilege(current_user,c.oid,'SELECT')) OR
            (c.relname NOT IN ('DirectoryObjects','DirectorySync','Audit') AND has_table_privilege(current_user,c.oid,'INSERT')) OR
            (c.relname NOT IN ('DirectoryObjects','DirectorySync') AND (has_table_privilege(current_user,c.oid,'UPDATE') OR has_table_privilege(current_user,c.oid,'DELETE'))) OR
            has_table_privilege(current_user,c.oid,'TRUNCATE'))) OR
        EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relowner=r.oid AND c.relkind='r')) AS "Value"
    FROM pg_roles r WHERE r.rolname=current_user
    """).SingleAsync();
if (unsafeRole) throw new InvalidOperationException("Connector requires a separate restricted non-owner database role.");
using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(5));
Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; cancellation.Cancel(); };
try
{
    var success = await new DirectorySynchronizer(db, TimeProvider.System).RunAsync(environment, principal, new LdapDirectoryReader(options), cancellation.Token);
    Console.WriteLine(success ? "Directory sync completed." : "Directory sync failed; see sanitized status.");
    return success ? 0 : 1;
}
catch (Exception)
{
    Console.Error.WriteLine("Connector unavailable; no successful synchronization was recorded.");
    return 1;
}
