using System.Data;
using ItManagement.EnrollmentGrantDelivery;
using Xunit;

namespace EnrollmentGrantDelivery.Tests;

public sealed class PostgresEnrollmentDeliveryAuditResultTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AcceptsOnlyOneExactSuccessfulResult(bool profile)
    {
        using var table = ValidTable(profile);
        using var reader = table.CreateDataReader();
        Assert.True(await Read(profile, reader));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RejectsMissingOrDuplicateRows(bool profile)
    {
        using var table = ValidTable(profile);
        table.Rows.Clear();
        using (var empty = table.CreateDataReader()) Assert.False(await Read(profile, empty));
        var values = profile ? new object[] { true, "None", (short)4 } : [true];
        table.Rows.Add(values);
        table.Rows.Add(values);
        using var duplicate = table.CreateDataReader();
        Assert.False(await Read(profile, duplicate));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task RejectsTrailingResultsEvenWhenEmpty(bool profile, bool hasRow)
    {
        using var table = ValidTable(profile);
        using var trailing = ValidTable(profile);
        if (!hasRow) trailing.Rows.Clear();
        using var reader = new DataTableReader([table, trailing]);
        Assert.False(await Read(profile, reader));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RejectsFalseNullAndUnexpectedColumns(bool profile)
    {
        using var table = ValidTable(profile);
        table.Rows[0][0] = false;
        using (var failed = table.CreateDataReader()) Assert.False(await Read(profile, failed));
        table.Rows[0][0] = true;
        for (var ordinal = 0; ordinal < table.Columns.Count; ordinal++)
        {
            var value = table.Rows[0][ordinal];
            table.Rows[0][ordinal] = DBNull.Value;
            using (var missing = table.CreateDataReader()) Assert.False(await Read(profile, missing));
            table.Rows[0][ordinal] = value;
            var name = table.Columns[ordinal].ColumnName;
            table.Columns[ordinal].ColumnName = name.ToUpperInvariant();
            using (var renamed = table.CreateDataReader()) Assert.False(await Read(profile, renamed));
            table.Columns[ordinal].ColumnName = name;
        }
        table.Columns.Add("unexpected", typeof(bool));
        using var extra = table.CreateDataReader();
        Assert.False(await Read(profile, extra));
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 0)]
    [InlineData(true, 1)]
    [InlineData(true, 2)]
    public async Task RejectsWrongClrTypes(bool profile, int ordinal)
    {
        using var valid = ValidTable(profile);
        using var table = new DataTable();
        foreach (DataColumn column in valid.Columns)
            table.Columns.Add(column.ColumnName, column.Ordinal == ordinal ? typeof(int) : column.DataType);
        var row = valid.Rows[0].ItemArray;
        row[ordinal] = 1;
        table.Rows.Add(row);
        using var reader = table.CreateDataReader();
        Assert.False(await Read(profile, reader));
    }

    [Theory]
    [InlineData("None", 3)]
    [InlineData("None", 5)]
    [InlineData("none", 4)]
    [InlineData("PrivilegeAuditFailed", 4)]
    public async Task RejectsUnapprovedProfileOrDiagnostic(string diagnostic, int version)
    {
        using var table = ValidTable(true);
        table.Rows[0][1] = diagnostic;
        table.Rows[0][2] = (short)version;
        using var reader = table.CreateDataReader();
        Assert.False(await Read(true, reader));
    }

    private static Task<bool> Read(bool profile, DataTableReader reader) => profile
        ? PostgresEnrollmentDeliveryAuditResult.ReadProfileAsync(reader, CancellationToken.None)
        : PostgresEnrollmentDeliveryAuditResult.ReadCatalogAsync(reader, CancellationToken.None);

    private static DataTable ValidTable(bool profile)
    {
        var table = new DataTable();
        table.Columns.Add("is_valid", typeof(bool));
        if (profile)
        {
            table.Columns.Add("diagnostic_code", typeof(string));
            table.Columns.Add("profile_version", typeof(short));
            table.Rows.Add(true, "None", (short)4);
        }
        else table.Rows.Add(true);
        return table;
    }
}
