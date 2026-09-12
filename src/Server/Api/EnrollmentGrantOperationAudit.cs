using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.Api;

internal static class EnrollmentGrantOperationAudit
{
    private static readonly string Query = LoadQuery();

    public static async Task<bool> IsValidAsync(ConsoleDbContext db, CancellationToken cancellationToken)
    {
        try { return await db.Database.SqlQueryRaw<int>(Query).SingleAsync(cancellationToken) == 1; }
        catch (NpgsqlException) when (!cancellationToken.IsCancellationRequested) { return false; }
    }

    private static string LoadQuery()
    {
        using var stream = typeof(EnrollmentGrantOperationAudit).Assembly.GetManifestResourceStream("EnrollmentGrantOperationsAudit.sql")
            ?? throw new InvalidOperationException("EnrollmentGrantOperationAuditUnavailable");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Replace(":'runtime_role'", "SESSION_USER", StringComparison.Ordinal)
            .Trim().TrimEnd(';').Replace("{", "{{", StringComparison.Ordinal).Replace("}", "}}", StringComparison.Ordinal);
    }
}
