using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task Profile4ApiRelationIndexesMatchCompiledMigrations()
    {
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-relations.sql"));
        var migrations = new Migration[] { new global::Persistence.Migrations.EnrollmentGrantOperations(), new global::Persistence.Migrations.EnrollmentGrantPlans(), new global::Persistence.Migrations.InitialIdentityAndAccess() };
        var tables = new HashSet<string>(["EnrollmentGrantOperations", "EnrollmentGrantRecipientReservations", "Memberships"], StringComparer.Ordinal);
        var indexes = new List<(string Table, string[] Columns, bool Primary, bool Unique)>();
        foreach (var migration in migrations)
        foreach (var operation in migration.UpOperations)
        {
            if (operation is CreateTableOperation table && tables.Contains(table.Name))
                indexes.Add((table.Name, table.PrimaryKey!.Columns, true, true));
            if (operation is CreateIndexOperation index && tables.Contains(index.Table))
                indexes.Add((index.Table, index.Columns, false, index.IsUnique));
            if (operation is AddUniqueConstraintOperation unique && tables.Contains(unique.Table))
                indexes.Add((unique.Table, unique.Columns, false, true));
        }
        Assert.Equal(13, indexes.Count);
        foreach (var index in indexes)
            Assert.Contains($"('{index.Table}',ARRAY[{string.Join(',', index.Columns.Select(c => "'" + c + "'"))}],{index.Primary.ToString().ToLowerInvariant()},{index.Unique.ToString().ToLowerInvariant()})", catalog, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Profile4ApiRelationColumnsMatchCompiledMigrations()
    {
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-relations.sql"));
        foreach (var (migration, tableName) in new (Migration, string)[]
        {
            (new global::Persistence.Migrations.EnrollmentGrantOperations(), "EnrollmentGrantOperations"),
            (new global::Persistence.Migrations.EnrollmentGrantPlans(), "EnrollmentGrantRecipientReservations"),
            (new global::Persistence.Migrations.InitialIdentityAndAccess(), "Memberships")
        })
        {
            var table = Assert.Single(migration.UpOperations.OfType<CreateTableOperation>(), x => x.Name == tableName);
            foreach (var (column, index) in table.Columns.Select((column, index) => (column, index)))
            {
                Assert.False(column.IsNullable);
                Assert.Null(column.DefaultValue);
                Assert.Null(column.DefaultValueSql);
                Assert.Null(column.ComputedColumnSql);
                var type = column.ColumnType switch { "uuid" => 2950, "bytea" => 17, "bigint" => 20, "boolean" => 16, "timestamp with time zone" => 1184, "character varying(64)" => 1043, _ => throw new InvalidOperationException() };
                var modifier = type == 1043 ? 68 : -1;
                var collation = type == 1043 ? "pg_catalog.to_regcollation('pg_catalog.\"default\"')::oid" : "0::oid";
                Assert.Contains($"('{tableName}',{index + 1},'{column.Name}',{type}::oid,{modifier},{collation})", catalog, StringComparison.Ordinal);
            }
        }
    }

    private static async Task VerifyProfile4ApiRelationsAsync(NpgsqlConnection owner, NpgsqlConnection admin, NpgsqlConnection api, CancellationToken cancellationToken)
    {
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-relations.sql"), cancellationToken);
        async Task Check(bool expected)
        {
            await using var transaction = await api.BeginTransactionAsync(cancellationToken);
            await using (var path = new NpgsqlCommand("SET LOCAL search_path=pg_catalog,pg_temp", api))
                await path.ExecuteNonQueryAsync(cancellationToken);
            await using var command = new NpgsqlCommand(catalog, api);
            var result = (bool)(await command.ExecuteScalarAsync(cancellationToken))!;
            if (expected && !result)
            {
                var prefix = catalog[..catalog.LastIndexOf("\nSELECT COALESCE", StringComparison.Ordinal)];
                await using var diagnostic = new NpgsqlCommand(prefix + """

                    SELECT 'columns' AS kind,row_to_json(d)::text FROM ((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) UNION ALL (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)) d
                    UNION ALL SELECT 'constraints',row_to_json(d)::text FROM ((SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints) UNION ALL (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints)) d
                    UNION ALL SELECT 'indexes',row_to_json(d)::text FROM ((SELECT * FROM expected_indexes EXCEPT SELECT * FROM actual_indexes) UNION ALL (SELECT * FROM actual_indexes EXCEPT SELECT * FROM expected_indexes)) d
                    UNION ALL SELECT 'table_acl',row_to_json(d)::text FROM ((SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl) UNION ALL (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl)) d
                    UNION ALL SELECT 'column_acl',row_to_json(d)::text FROM ((SELECT * FROM expected_column_acl EXCEPT SELECT * FROM actual_column_acl) UNION ALL (SELECT * FROM actual_column_acl EXCEPT SELECT * FROM expected_column_acl)) d
                    """, api);
                var differences = new List<string>();
                await using var reader = await diagnostic.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken)) differences.Add(reader.GetString(0) + ":" + reader.GetString(1));
                Assert.Fail("Relation catalog rejected canonical fixture: " + string.Join("; ", differences));
            }
            Assert.Equal(expected, result);
            await transaction.RollbackAsync(cancellationToken);
        }
        await Check(true);
        async Task Drift(string mutation, string restoreSql, NpgsqlConnection? writer = null)
        {
            try
            {
                await using var change = new NpgsqlCommand(mutation, writer ?? owner);
                await change.ExecuteNonQueryAsync(cancellationToken);
                await Check(false);
            }
            finally
            {
                await using var restore = new NpgsqlCommand(restoreSql, writer ?? owner) { CommandTimeout = 10 };
                await restore.ExecuteNonQueryAsync(CancellationToken.None);
            }
            await Check(true);
        }
        async Task<List<string[]>> ReadRows(string sql)
        {
            var rows = new List<string[]>();
            await using var transaction = await owner.BeginTransactionAsync(cancellationToken);
            await using (var path = new NpgsqlCommand("SET LOCAL search_path=pg_catalog,pg_temp", owner))
                await path.ExecuteNonQueryAsync(cancellationToken);
            await using var command = new NpgsqlCommand(sql, owner);
            await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
                while (await reader.ReadAsync(cancellationToken))
                    rows.Add(Enumerable.Range(0, reader.FieldCount).Select(reader.GetString).ToArray());
            await transaction.RollbackAsync(cancellationToken);
            return rows;
        }
        var prefix = """
            WITH relations AS (SELECT c.* FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname='public' AND c.relname IN('EnrollmentGrantOperations','EnrollmentGrantRecipientReservations','Memberships'))
            """;
        var grants = await ReadRows(prefix + """
            SELECT pg_catalog.format('%s ON TABLE public.%I',a.privilege_type,c.relname),pg_catalog.quote_ident(r.rolname),
              CASE WHEN a.grantee=c.relowner THEN 'owner' ELSE 'other' END
            FROM relations c CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            UNION ALL
            SELECT pg_catalog.format('%s (%I) ON TABLE public.%I',acl.privilege_type,a.attname,c.relname),pg_catalog.quote_ident(r.rolname),'other'
            FROM relations c JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
            CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl JOIN pg_catalog.pg_roles r ON r.oid=acl.grantee
            """);
        Assert.Equal(83, grants.Count);
        foreach (var grant in grants)
        {
            await Drift($"REVOKE {grant[0]} FROM {grant[1]}", $"GRANT {grant[0]} TO {grant[1]}");
            if (grant[2] == "other")
                await Drift($"GRANT {grant[0]} TO {grant[1]} WITH GRANT OPTION", $"REVOKE GRANT OPTION FOR {grant[0]} FROM {grant[1]}");
        }
        var columns = await ReadRows(prefix + """
            SELECT pg_catalog.format('public.%I',c.relname),pg_catalog.quote_ident(a.attname),
              CASE a.atttypid WHEN 2950 THEN '''11111111-1111-1111-1111-111111111111''::uuid'
                WHEN 17 THEN '''probe''::bytea' WHEN 16 THEN 'true' WHEN 20 THEN '1'
                WHEN 1184 THEN '''2000-01-01T00:00:00Z''::timestamptz' WHEN 1043 THEN '''probe''' END
            FROM relations c JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid WHERE a.attnum>0
            """);
        Assert.Equal(29, columns.Count);
        foreach (var column in columns)
        {
            await Drift($"ALTER TABLE {column[0]} RENAME COLUMN {column[1]} TO api_catalog_renamed",
                $"ALTER TABLE {column[0]} RENAME COLUMN api_catalog_renamed TO {column[1]}");
            await Drift($"ALTER TABLE {column[0]} ALTER COLUMN {column[1]} SET DEFAULT {column[2]}",
                $"ALTER TABLE {column[0]} ALTER COLUMN {column[1]} DROP DEFAULT");
        }
        var checks = await ReadRows(prefix + """
            SELECT pg_catalog.format('public.%I',c.relname),pg_catalog.quote_ident(k.conname),pg_catalog.pg_get_constraintdef(k.oid,true)
            FROM relations c JOIN pg_catalog.pg_constraint k ON k.conrelid=c.oid WHERE k.contype='c'
            """);
        Assert.Equal(9, checks.Count);
        foreach (var check in checks)
        {
            var drop = $"ALTER TABLE {check[0]} DROP CONSTRAINT {check[1]};";
            var restore = drop + $"ALTER TABLE {check[0]} ADD CONSTRAINT {check[1]} {check[2]}";
            await Drift(drop + $"ALTER TABLE {check[0]} ADD CONSTRAINT {check[1]} CHECK (true)", restore);
            await Drift(drop + $"ALTER TABLE {check[0]} ADD CONSTRAINT {check[1]} {check[2]} NOT VALID", restore);
        }
        var foreignKeys = await ReadRows(prefix + """
            SELECT pg_catalog.format('public.%I',c.relname),pg_catalog.quote_ident(k.conname),pg_catalog.pg_get_constraintdef(k.oid,true)
            FROM relations c JOIN pg_catalog.pg_constraint k ON k.conrelid=c.oid WHERE k.contype='f'
            """);
        Assert.Equal(7, foreignKeys.Count);
        foreach (var foreignKey in foreignKeys)
        {
            var drop = $"ALTER TABLE {foreignKey[0]} DROP CONSTRAINT {foreignKey[1]};";
            var add = $"ALTER TABLE {foreignKey[0]} ADD CONSTRAINT {foreignKey[1]} ";
            var changed = foreignKey[2].Replace("ON DELETE RESTRICT", "ON DELETE CASCADE", StringComparison.Ordinal);
            Assert.NotEqual(foreignKey[2], changed);
            // FK revalidation needs full referenced-row visibility in this FORCE-RLS fixture.
            await Drift(drop + add + changed, drop + add + foreignKey[2], admin);
            await Drift(drop + add + foreignKey[2] + " NOT VALID", drop + add + foreignKey[2], admin);
        }
        var indexes = await ReadRows(prefix + """
            SELECT pg_catalog.format('public.%I',c.relname),pg_catalog.quote_ident(ic.relname),pg_catalog.pg_get_indexdef(idx.indexrelid),
              CASE WHEN EXISTS(SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.conindid=idx.indexrelid) THEN 'constraint' ELSE 'free' END
            FROM relations c JOIN pg_catalog.pg_index idx ON idx.indrelid=c.oid JOIN pg_catalog.pg_class ic ON ic.oid=idx.indexrelid
            """);
        Assert.Equal(13, indexes.Count);
        foreach (var index in indexes)
        {
            if (index[3] == "free") await Drift($"DROP INDEX public.{index[1]}", index[2]);
            await Drift($"ALTER TABLE {index[0]} CLUSTER ON {index[1]}", $"ALTER TABLE {index[0]} SET WITHOUT CLUSTER");
        }
        foreach (var table in new[] { "EnrollmentGrantOperations", "Memberships", "EnrollmentGrantRecipientReservations" })
        {
            await Drift($"GRANT SELECT ON TABLE public.\"{table}\" TO PUBLIC", $"REVOKE SELECT ON TABLE public.\"{table}\" FROM PUBLIC");
            await Drift($"GRANT SELECT (\"EnvironmentId\") ON TABLE public.\"{table}\" TO PUBLIC", $"REVOKE SELECT (\"EnvironmentId\") ON TABLE public.\"{table}\" FROM PUBLIC");
            await Drift($"ALTER TABLE public.\"{table}\" REPLICA IDENTITY FULL", $"ALTER TABLE public.\"{table}\" REPLICA IDENTITY DEFAULT");
            await Drift($"CREATE INDEX api_catalog_extra ON public.\"{table}\" (\"EnvironmentId\")", "DROP INDEX IF EXISTS public.api_catalog_extra");
            await Drift($"ALTER TABLE public.\"{table}\" ADD CONSTRAINT api_catalog_extra CHECK (true)", $"ALTER TABLE public.\"{table}\" DROP CONSTRAINT api_catalog_extra");
            await Drift($"CREATE RULE api_catalog_extra AS ON UPDATE TO public.\"{table}\" DO INSTEAD NOTHING", $"DROP RULE api_catalog_extra ON public.\"{table}\"");
        }
    }
}
