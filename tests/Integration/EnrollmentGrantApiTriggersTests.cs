using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task Profile4ApiTriggerContractsMatchCanonicalSources()
    {
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-triggers.sql"));
        var sources = new List<string>();
        foreach (var migration in new Migration[] { new global::Persistence.Migrations.BindIsolationToMembership(), new global::Persistence.Migrations.EnrollmentGrantPlans(), new global::Persistence.Migrations.EnrollmentGrantOperations(), new global::ItManagement.Persistence.Migrations.EnrollmentGrantQueuedAnchors(), new global::ItManagement.Persistence.Migrations.EnrollmentGrantExecutionQueue() })
            sources.AddRange(migration.UpOperations.OfType<SqlOperation>().Select(x => x.Sql));
        foreach (var file in new[] { "enrollment-execution-profile.sql", "enrollment-delivery-profile.sql", "enrollment-execution-queue.sql", "enrollment-profile4-publication.sql" })
            sources.Add(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, file)));
        var expectedPublic = Regex.Matches(catalog, @"(?m)^ \('([^']+)','([^']+)','([^']+)',(\d+),(true|false),'([OA])'\)").Select(m => "public|" + string.Join('|', m.Groups.Cast<Group>().Skip(1).Select(g => g.Value)));
        var expectedPrivate = Regex.Matches(catalog, @"UNION ALL SELECT '([^']+)','([^']+)','([^']+)','([^']+)',(\d+),(true|false),'([OA])'").Select(m => string.Join('|', m.Groups.Cast<Group>().Skip(1).Select(g => g.Value)));
        var expected = expectedPublic.Concat(expectedPrivate).Order().ToArray();
        var roots = Regex.Matches(catalog, @"(?m)^ \('([^']+)',(?:true|false),.*?'([0-9a-f]{64})'\)");
        var rootNames = roots.Select(x => x.Groups[1].Value).ToHashSet(StringComparer.Ordinal);
        var actual = new List<string>();
        foreach (var source in sources)
        foreach (Match trigger in Regex.Matches(source, "CREATE (?<constraint>CONSTRAINT )?TRIGGER (?<name>\\w+)\\s+(?<timing>BEFORE|AFTER) (?<events>[A-Z ]+) ON (?:(?<schema>\\w+)\\.)?(?:\"(?<table>\\w+)\"|(?<table>\\w+))\\s+(?<deferred>DEFERRABLE INITIALLY DEFERRED\\s+)?FOR EACH ROW\\s+EXECUTE FUNCTION (?<function>[a-z0-9_.]+)\\(\\);"))
        {
            if (!rootNames.Contains(trigger.Groups["function"].Value)) continue;
            var code = 1 | (trigger.Groups["timing"].Value == "BEFORE" ? 2 : 0);
            var events = trigger.Groups["events"].Value;
            if (events.Contains("INSERT", StringComparison.Ordinal)) code |= 4;
            if (events.Contains("DELETE", StringComparison.Ordinal)) code |= 8;
            if (events.Contains("UPDATE", StringComparison.Ordinal)) code |= 16;
            var name = trigger.Groups["name"].Value;
            var enabled = source.Contains("ENABLE ALWAYS TRIGGER " + name + ";", StringComparison.Ordinal) ? "A" : "O";
            var schema = trigger.Groups["schema"].Success ? trigger.Groups["schema"].Value : "public";
            actual.Add($"{schema}|{trigger.Groups["table"].Value}|{name}|{trigger.Groups["function"].Value}|{code}|{trigger.Groups["deferred"].Success.ToString().ToLowerInvariant()}|{enabled}");
        }
        Assert.Equal(28, expected.Length);
        Assert.True(expected.SequenceEqual(actual.Order()), "Expected only: " + string.Join(";", expected.Except(actual)) + " Actual only: " + string.Join(";", actual.Except(expected)));
        Assert.Equal(12, roots.Count);
        foreach (Match root in roots)
        {
            // Later installation SQL intentionally replaces the legacy queue validator.
            var definitions = sources.SelectMany(source => Regex.Matches(source.Replace("\r\n", "\n", StringComparison.Ordinal), @"CREATE (?:OR REPLACE )?FUNCTION " + Regex.Escape(root.Groups[1].Value) + @"\(\) RETURNS trigger\s+.*?AS (?<delimiter>\$function\$|\$\$)(?<body>.*?)\k<delimiter>;", RegexOptions.Singleline).Cast<Match>()).ToArray();
            Assert.NotEmpty(definitions);
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(definitions[^1].Groups["body"].Value))).ToLowerInvariant();
            Assert.Equal(root.Groups[2].Value, hash);
        }
    }

    private static async Task VerifyProfile4ApiTriggersAsync(NpgsqlConnection owner, NpgsqlConnection admin, NpgsqlConnection api, CancellationToken cancellationToken)
    {
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-triggers.sql"), cancellationToken);
        async Task Check(bool expected)
        {
            await using var transaction = await api.BeginTransactionAsync(cancellationToken);
            await using (var path = new NpgsqlCommand("SET LOCAL search_path=pg_catalog,pg_temp", api))
                await path.ExecuteNonQueryAsync(cancellationToken);
            await using var command = new NpgsqlCommand(catalog, api);
            var valid = (bool)(await command.ExecuteScalarAsync(cancellationToken))!;
            if (expected && !valid)
            {
                var diagnosticPrefix = catalog[..catalog.LastIndexOf("\nSELECT COALESCE", StringComparison.Ordinal)];
                var start = catalog.LastIndexOf("SELECT COALESCE((SELECT ", StringComparison.Ordinal) + "SELECT COALESCE((SELECT ".Length;
                var conditions = catalog[start..catalog.LastIndexOf(" FROM owner_role o),false)", StringComparison.Ordinal)].Replace("\r\n", "\n", StringComparison.Ordinal).Split("\n AND ");
                await using var checks = new NpgsqlCommand(diagnosticPrefix + "\nSELECT ARRAY[" + string.Join(",", conditions.Select(x => "(" + x + ")")) + "] FROM owner_role o", api);
                var values = (bool[])(await checks.ExecuteScalarAsync(cancellationToken))!;
                await using var diagnostic = new NpgsqlCommand(diagnosticPrefix + """

                    SELECT 'ri',row_to_json(d)::text FROM ((SELECT * FROM expected_ri EXCEPT SELECT * FROM actual_ri) UNION ALL (SELECT * FROM actual_ri EXCEPT SELECT * FROM expected_ri)) d
                    UNION ALL SELECT 'constraint',row_to_json(k)::text FROM pg_catalog.pg_constraint k WHERE k.oid IN(SELECT tgconstraint FROM attachments)
                    UNION ALL SELECT 'function',row_to_json(d)::text FROM (SELECT name,proconfig,configuration,pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(prosrc,'UTF8')),'hex')=body_hash hash_ok,proacl::text FROM functions) d
                    UNION ALL SELECT 'attachment',row_to_json(d)::text FROM (SELECT table_name,trigger_name,tgtype,type_code,tgconstrindid,tgconstrrelid FROM attachments) d
                    """, api);
                var details = new List<string>();
                await using var reader = await diagnostic.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken)) details.Add(reader.GetString(0) + ":" + reader.GetString(1));
                Assert.Fail("Conditions: " + string.Join(",", values.Select((x, i) => i + "=" + x)) + "; " + string.Join("; ", details));
            }
            Assert.Equal(expected, valid);
            await transaction.RollbackAsync(cancellationToken);
        }
        async Task Drift(string mutation, string restoration, NpgsqlConnection writer)
        {
            try
            {
                await using var change = new NpgsqlCommand(mutation, writer);
                await change.ExecuteNonQueryAsync(cancellationToken);
                await Check(false);
            }
            finally
            {
                await using var restore = new NpgsqlCommand(restoration, writer) { CommandTimeout = 10 };
                await restore.ExecuteNonQueryAsync(CancellationToken.None);
            }
            await Check(true);
        }
        await Check(true);
        var prefix = catalog[..catalog.LastIndexOf("\nSELECT COALESCE", StringComparison.Ordinal)];
        var triggers = new List<(string Table, string Name, string Definition, string Enabled, bool Internal)>();
        await using (var command = new NpgsqlCommand(prefix + """

            SELECT pg_catalog.quote_ident(n.nspname)||'.'||pg_catalog.quote_ident(c.relname),
                pg_catalog.quote_ident(t.tgname),pg_catalog.pg_get_triggerdef(t.oid),t.tgenabled::text,t.tgisinternal
            FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE t.oid IN(SELECT oid FROM attachments) OR t.tgconstraint IN(SELECT oid FROM foreign_keys)
            """, owner))
        {
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                triggers.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetBoolean(4)));
        }
        Assert.Equal(56, triggers.Count);
        foreach (var trigger in triggers)
        {
            var writer = trigger.Internal ? admin : owner;
            var enable = $"ALTER TABLE {trigger.Table} ENABLE {(trigger.Enabled == "A" ? "ALWAYS " : "")}TRIGGER {trigger.Name}";
            await Drift($"ALTER TABLE {trigger.Table} DISABLE TRIGGER {trigger.Name}", enable, writer);
            await Drift($"ALTER TABLE {trigger.Table} ENABLE REPLICA TRIGGER {trigger.Name}", enable, writer);
            if (trigger.Internal) continue;
            await Drift($"ALTER TABLE {trigger.Table} ENABLE {(trigger.Enabled == "A" ? "" : "ALWAYS ")}TRIGGER {trigger.Name}", enable, writer);
            await Drift($"DROP TRIGGER {trigger.Name} ON {trigger.Table}", trigger.Definition + ";" + enable, writer);
            await Drift($"ALTER TRIGGER {trigger.Name} ON {trigger.Table} RENAME TO api_trigger_drift",
                $"ALTER TRIGGER api_trigger_drift ON {trigger.Table} RENAME TO {trigger.Name}", writer);
            if (trigger.Definition.Contains("INITIALLY DEFERRED", StringComparison.Ordinal))
            {
                foreach (var replacement in new[] { "DEFERRABLE INITIALLY IMMEDIATE", "NOT DEFERRABLE INITIALLY IMMEDIATE" })
                    await Drift($"DROP TRIGGER {trigger.Name} ON {trigger.Table};" + trigger.Definition.Replace("DEFERRABLE INITIALLY DEFERRED", replacement, StringComparison.Ordinal),
                        $"DROP TRIGGER {trigger.Name} ON {trigger.Table};" + trigger.Definition + ";" + enable, writer);
            }
        }
        await Drift("CREATE TRIGGER api_trigger_extra BEFORE UPDATE ON public.\"Environments\" FOR EACH ROW EXECUTE FUNCTION public.guard_operator_identity()",
            "DROP TRIGGER api_trigger_extra ON public.\"Environments\"", owner);
        await Drift("CREATE TRIGGER api_trigger_extra BEFORE UPDATE ON public.\"Roles\" FOR EACH ROW EXECUTE FUNCTION public.guard_operator_identity()",
            "DROP TRIGGER api_trigger_extra ON public.\"Roles\"", owner);
        var representative = Assert.Single(triggers, t => t.Name == "enrollment_execution_worker_environment_guard");
        foreach (var changed in new[] {
            representative.Definition.Replace("BEFORE UPDATE", "BEFORE INSERT", StringComparison.Ordinal),
            representative.Definition.Replace("enrollment_execution.reject_worker_update()", "public.guard_operator_identity()", StringComparison.Ordinal),
            representative.Definition.Replace("FOR EACH ROW", "FOR EACH ROW WHEN (false)", StringComparison.Ordinal),
            representative.Definition.Replace("reject_worker_update()", "reject_worker_update('drift')", StringComparison.Ordinal)
        })
        {
            Assert.NotEqual(representative.Definition, changed);
            await Drift($"DROP TRIGGER {representative.Name} ON {representative.Table};" + changed,
                $"DROP TRIGGER {representative.Name} ON {representative.Table};" + representative.Definition, owner);
        }
        await using var identity = new NpgsqlCommand("SELECT pg_catalog.quote_ident(SESSION_USER)", api);
        var apiRole = (string)(await identity.ExecuteScalarAsync(cancellationToken))!;
        await using var ownerIdentity = new NpgsqlCommand("SELECT pg_catalog.quote_ident(SESSION_USER)", owner);
        var ownerRole = (string)(await ownerIdentity.ExecuteScalarAsync(cancellationToken))!;
        await using var adminIdentity = new NpgsqlCommand("SELECT pg_catalog.quote_ident(SESSION_USER)", admin);
        var adminRole = (string)(await adminIdentity.ExecuteScalarAsync(cancellationToken))!;
        foreach (Match root in Regex.Matches(catalog, @"(?m)^ \('([^']+)',(true|false),.*?'([0-9a-f]{64})'\)"))
        {
            var name = root.Groups[1].Value;
            var signature = name + "()";
            await using var definition = new NpgsqlCommand("SELECT pg_catalog.pg_get_functiondef(p.oid) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=@schema AND p.proname=@name AND p.proargtypes::text=''", owner);
            definition.Parameters.AddWithValue("schema", name.Split('.')[0]);
            definition.Parameters.AddWithValue("name", name.Split('.')[1]);
            var original = (string)(await definition.ExecuteScalarAsync(cancellationToken))!;
            Assert.Equal(2, Regex.Matches(original, Regex.Escape("$function$")).Count);
            foreach (var mutation in new[] {
                original.Insert(original.LastIndexOf("$function$", StringComparison.Ordinal), "\n-- trigger body drift\n"),
                $"ALTER FUNCTION {signature} SET search_path=pg_catalog",
                $"ALTER FUNCTION {signature} SECURITY {(root.Groups[2].Value == "true" ? "INVOKER" : "DEFINER")}",
                $"ALTER FUNCTION {signature} IMMUTABLE",
                $"ALTER FUNCTION {signature} PARALLEL SAFE",
                $"ALTER FUNCTION {signature} RETURNS NULL ON NULL INPUT"
            }) await Drift(mutation, original, owner);
            foreach (var grantee in new[] { "PUBLIC", apiRole })
                await Drift($"GRANT EXECUTE ON FUNCTION {signature} TO {grantee}", $"REVOKE EXECUTE ON FUNCTION {signature} FROM {grantee}", owner);
            await Drift($"CREATE FUNCTION {name}(text) RETURNS boolean LANGUAGE sql AS 'SELECT false'", $"DROP FUNCTION {name}(text)", owner);
            await Drift($"ALTER FUNCTION {signature} OWNER TO {adminRole}", $"ALTER FUNCTION {signature} OWNER TO {ownerRole}", admin);
        }
    }
}
