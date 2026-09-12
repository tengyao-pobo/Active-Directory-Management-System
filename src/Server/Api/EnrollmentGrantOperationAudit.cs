using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

internal static class EnrollmentGrantOperationAudit
{
    private static readonly string Query = LoadQuery();

    public static Task<bool> IsValidAsync(ConsoleDbContext db, CancellationToken cancellationToken) =>
        CatalogAuditScope.RunAsync(db, CatalogAuditPath.Legacy,
            async (auditDb, token) => await auditDb.Database.SqlQueryRaw<int>(Query).SingleAsync(token) == 1, cancellationToken);

    private static string LoadQuery()
    {
        using var stream = typeof(EnrollmentGrantOperationAudit).Assembly.GetManifestResourceStream("EnrollmentGrantOperationsAudit.sql")
            ?? throw new InvalidOperationException("EnrollmentGrantOperationAuditUnavailable");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Replace(":'runtime_role'", "SESSION_USER", StringComparison.Ordinal)
            .Trim().TrimEnd(';').Replace("{", "{{", StringComparison.Ordinal).Replace("}", "}}", StringComparison.Ordinal);
    }
}
