using System.Data.Common;

namespace ItManagement.EnrollmentGrantDelivery;

internal static class PostgresEnrollmentDeliveryAuditResult
{
    internal static async Task<bool> ReadCatalogAsync(DbDataReader reader, CancellationToken ct)
    {
        if (reader.FieldCount != 1 || !Column(reader, 0, "is_valid", typeof(bool)) ||
            !await reader.ReadAsync(ct).ConfigureAwait(false) || reader.IsDBNull(0) || !reader.GetBoolean(0))
            return false;
        return await IsCompleteAsync(reader, ct).ConfigureAwait(false);
    }

    internal static async Task<bool> ReadProfileAsync(DbDataReader reader, CancellationToken ct)
    {
        if (reader.FieldCount != 3 || !Column(reader, 0, "is_valid", typeof(bool)) ||
            !Column(reader, 1, "diagnostic_code", typeof(string)) ||
            !Column(reader, 2, "profile_version", typeof(short)) ||
            !await reader.ReadAsync(ct).ConfigureAwait(false) ||
            reader.IsDBNull(0) || reader.IsDBNull(1) || reader.IsDBNull(2) ||
            !reader.GetBoolean(0) || reader.GetString(1) != "None" || reader.GetInt16(2) != 4)
            return false;
        return await IsCompleteAsync(reader, ct).ConfigureAwait(false);
    }

    private static bool Column(DbDataReader reader, int ordinal, string name, Type type) =>
        string.Equals(reader.GetName(ordinal), name, StringComparison.Ordinal) && reader.GetFieldType(ordinal) == type;

    private static async Task<bool> IsCompleteAsync(DbDataReader reader, CancellationToken ct) =>
        !await reader.ReadAsync(ct).ConfigureAwait(false) && !await reader.NextResultAsync(ct).ConfigureAwait(false);
}
