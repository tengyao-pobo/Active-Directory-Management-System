using System.Data;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("table")]
    [InlineData("column")]
    [InlineData("sequence")]
    [InlineData("public-table")]
    [InlineData("public-sequence")]
    [InlineData("other-pair")]
    [InlineData("maintain")]
    [InlineData("schema-create")]
    [InlineData("database-create")]
    [InlineData("missing-role")]
    [InlineData("default-table")]
    [InlineData("default-public-sequence")]
    public async Task DeliveryRuntimeRelationAuditAllowsCatalogReadsButRejectsApplicationAccess(string drift)
    {
        // Exercise the exact global privilege slice; the complete profile remains closed.
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }
        var suffix = Guid.NewGuid().ToString("N");
        var runtime = "privilege_runtime_" + suffix;
        var other = "privilege_other_" + suffix;
        var schema = "privilege_schema_" + suffix;
        await Execute($"CREATE ROLE {QuoteIdentifier(runtime)} LOGIN NOINHERIT; CREATE ROLE {QuoteIdentifier(other)} LOGIN NOINHERIT;");
        var upgrade = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "upgrade-enrollment-execution-v3-to-v4.sql"));
        var start = upgrade.IndexOf("ALTER TABLE enrollment_execution.role_reservations DROP CONSTRAINT", StringComparison.Ordinal);
        var end = upgrade.IndexOf("INSERT INTO enrollment_execution.role_reservations", start, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        await Execute(upgrade[start..end]);
        await Execute($"""
            INSERT INTO enrollment_execution.role_reservations(role_name,role_oid,capability,role_kind,reservation_schema_version)
            SELECT rolname,oid,'EnrollmentGrantDelivery','DeliveryRuntime',1 FROM pg_catalog.pg_roles
            WHERE rolname IN('{runtime}','{other}');
            CREATE SCHEMA {QuoteIdentifier(schema)};
            CREATE TABLE {QuoteIdentifier(schema)}.probe(id integer);
            CREATE SEQUENCE {QuoteIdentifier(schema)}.probe_sequence;
            """);
        var audit = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        start = audit.IndexOf("-- BEGIN delivery runtime relation privileges", StringComparison.Ordinal);
        end = audit.IndexOf("-- END delivery runtime relation privileges", StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        await Execute($"""
            CREATE FUNCTION pg_temp.test_delivery_runtime_privileges() RETURNS boolean LANGUAGE plpgsql AS $test$
            DECLARE ok boolean := true;
            BEGIN
            {audit[start..end]}
            RETURN COALESCE(ok,false);
            END $test$;
            """);
        async Task<bool> Valid()
        {
            await using var command = new NpgsqlCommand("SELECT pg_temp.test_delivery_runtime_privileges()", connection, transaction);
            return (bool)(await command.ExecuteScalarAsync())!;
        }
        await using (var catalog = new NpgsqlCommand($"SELECT has_table_privilege('{runtime}','pg_catalog.pg_class','SELECT')", connection, transaction))
            Assert.Equal(true, await catalog.ExecuteScalarAsync());
        Assert.True(await Valid());
        await Execute(drift switch
        {
            "none" => "SELECT 1",
            "table" => $"GRANT SELECT ON {QuoteIdentifier(schema)}.probe TO {QuoteIdentifier(runtime)}",
            "column" => $"GRANT UPDATE(id) ON {QuoteIdentifier(schema)}.probe TO {QuoteIdentifier(runtime)}",
            "sequence" => $"GRANT USAGE ON SEQUENCE {QuoteIdentifier(schema)}.probe_sequence TO {QuoteIdentifier(runtime)}",
            "public-table" => $"GRANT SELECT ON {QuoteIdentifier(schema)}.probe TO PUBLIC",
            "public-sequence" => $"GRANT SELECT ON SEQUENCE {QuoteIdentifier(schema)}.probe_sequence TO PUBLIC",
            "other-pair" => $"GRANT DELETE ON {QuoteIdentifier(schema)}.probe TO {QuoteIdentifier(other)}",
            "maintain" => $"GRANT MAINTAIN ON {QuoteIdentifier(schema)}.probe TO {QuoteIdentifier(other)}",
            "schema-create" => $"GRANT CREATE ON SCHEMA {QuoteIdentifier(schema)} TO {QuoteIdentifier(other)}",
            "database-create" => $"GRANT CREATE ON DATABASE {QuoteIdentifier(connection.Database)} TO {QuoteIdentifier(other)}",
            "missing-role" => $"DROP ROLE {QuoteIdentifier(other)}",
            "default-table" => $"ALTER DEFAULT PRIVILEGES IN SCHEMA {QuoteIdentifier(schema)} GRANT SELECT ON TABLES TO {QuoteIdentifier(other)}",
            "default-public-sequence" => "ALTER DEFAULT PRIVILEGES GRANT USAGE ON SEQUENCES TO PUBLIC",
            _ => throw new ArgumentOutOfRangeException(nameof(drift))
        });
        Assert.Equal(drift == "none", await Valid());
        await transaction.RollbackAsync();
    }
}
