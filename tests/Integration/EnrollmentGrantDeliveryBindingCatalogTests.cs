using System.Data;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("missing-table")]
    [InlineData("missing-pk")]
    [InlineData("wrong-execution-key")]
    [InlineData("nonunique-status")]
    [InlineData("missing-delivery-index")]
    [InlineData("shape")]
    [InlineData("purpose")]
    [InlineData("unvalidated")]
    [InlineData("missing-fk")]
    [InlineData("default")]
    [InlineData("extra-column")]
    [InlineData("rls")]
    [InlineData("extra-policy")]
    [InlineData("disabled-triggers")]
    [InlineData("extra-index")]
    [InlineData("wrong-pk-key")]
    [InlineData("fk-cascade")]
    [InlineData("incoming-fk")]
    [InlineData("replica-identity")]
    [InlineData("included-column")]
    public async Task DeliveryBindingCatalogRejectsStructuralDrift(string drift)
    {
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }
        // Only stage the binding DDL in a rollback transaction. No installer is activated.
        var upgrade = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "upgrade-enrollment-execution-v3-to-v4.sql"));
        var start = upgrade.IndexOf("ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT", StringComparison.Ordinal);
        var end = upgrade.IndexOf("ALTER TABLE enrollment_execution.role_reservations DROP CONSTRAINT", start, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        await Execute(upgrade[start..end]);
        await Execute("SET LOCAL search_path=pg_catalog,pg_temp");
        await using var ownerCommand = new NpgsqlCommand("SELECT CURRENT_USER::text", connection, transaction);
        var owner = (string)(await ownerCommand.ExecuteScalarAsync())!;
        var audit = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-bindings.sql")))
            .Replace(":'expected_table_owner_role'", "@owner", StringComparison.Ordinal);
        async Task<bool> Valid()
        {
            await using var command = new NpgsqlCommand(audit, connection, transaction);
            command.Parameters.AddWithValue("owner", owner);
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(1, reader.FieldCount);
            Assert.Equal("is_valid", reader.GetName(0));
            var result = reader.GetBoolean(0);
            Assert.False(await reader.ReadAsync());
            Assert.False(await reader.NextResultAsync());
            return result;
        }
        Assert.True(await Valid());
        await Execute(drift switch
        {
            "none" => "SELECT 1",
            "missing-table" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" RENAME TO hidden_bindings_probe",
            "missing-pk" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT \"DirectoryDatabaseBindings_pkey\"",
            "wrong-execution-key" => "DROP INDEX public.enrollment_execution_environment_login; CREATE UNIQUE INDEX enrollment_execution_environment_login ON public.\"DirectoryDatabaseBindings\"(\"LoginRole\") WHERE \"Purpose\"='EnrollmentGrantExecution'",
            "nonunique-status" => "DROP INDEX public.enrollment_grant_status_environment_login; CREATE INDEX enrollment_grant_status_environment_login ON public.\"DirectoryDatabaseBindings\"(\"EnvironmentId\") WHERE \"Purpose\"='EnrollmentGrantStatusRefresh'",
            "missing-delivery-index" => "DROP INDEX public.enrollment_grant_delivery_environment_login",
            "shape" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT directory_database_binding_shape, ADD CONSTRAINT directory_database_binding_shape CHECK(true)",
            "purpose" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT directory_database_binding_purpose, ADD CONSTRAINT directory_database_binding_purpose CHECK(true)",
            "unvalidated" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT directory_database_binding_shape, ADD CONSTRAINT directory_database_binding_shape CHECK(true) NOT VALID",
            "missing-fk" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT \"DirectoryDatabaseBindings_EnvironmentId_fkey\"",
            "default" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" ALTER COLUMN \"ContractVersion\" SET DEFAULT 2",
            "extra-column" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" ADD COLUMN unexpected integer",
            "rls" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" ENABLE ROW LEVEL SECURITY",
            "extra-policy" => "CREATE POLICY unexpected ON public.\"DirectoryDatabaseBindings\" USING(true)",
            "disabled-triggers" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" DISABLE TRIGGER ALL",
            "extra-index" => "CREATE INDEX unexpected_binding_index ON public.\"DirectoryDatabaseBindings\"(\"Purpose\")",
            "wrong-pk-key" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT \"DirectoryDatabaseBindings_pkey\", ADD CONSTRAINT \"DirectoryDatabaseBindings_pkey\" PRIMARY KEY(\"Purpose\",\"LoginRole\")",
            "fk-cascade" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT \"DirectoryDatabaseBindings_EnvironmentId_fkey\", ADD CONSTRAINT \"DirectoryDatabaseBindings_EnvironmentId_fkey\" FOREIGN KEY(\"EnvironmentId\") REFERENCES public.\"Environments\"(\"Id\") ON DELETE CASCADE",
            "incoming-fk" => "CREATE TABLE public.unexpected_binding_reference(role name REFERENCES public.\"DirectoryDatabaseBindings\"(\"LoginRole\"))",
            "replica-identity" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" REPLICA IDENTITY USING INDEX \"DirectoryDatabaseBindings_pkey\"",
            "included-column" => "DROP INDEX public.enrollment_grant_status_environment_login; CREATE UNIQUE INDEX enrollment_grant_status_environment_login ON public.\"DirectoryDatabaseBindings\"(\"EnvironmentId\") INCLUDE(\"LoginRole\") WHERE \"Purpose\"='EnrollmentGrantStatusRefresh'",
            _ => throw new ArgumentOutOfRangeException(nameof(drift))
        });
        Assert.Equal(drift == "none", await Valid());
        await transaction.RollbackAsync();
    }
}
