using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task Profile4AuditSplitMatchesIndependentSources()
    {
        async Task<string> Read(string name) => (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, name))).Replace("\r\n", "\n", StringComparison.Ordinal);
        static Match Function(string source, string name)
        {
            var matches = Regex.Matches(source, @"CREATE (?:OR REPLACE )?FUNCTION enrollment_execution\." + Regex.Escape(name) + @"\(p_environment uuid\)(?<header>.*?)AS \$function\$(?<body>.*?)\$function\$;", RegexOptions.Singleline);
            Assert.Single(matches);
            return matches[0];
        }
        var original = Function(await Read("enrollment-execution-profile.sql"), "audit_execution_privileges");
        var candidateSource = await Read("enrollment-profile4-structure-audit.sql");
        var candidate = Function(candidateSource, "audit_execution_profile_structure");
        Assert.Equal(original.Groups["header"].Value.Replace("SECURITY DEFINER", "SECURITY INVOKER", StringComparison.Ordinal), candidate.Groups["header"].Value);
        const string final = "    RETURN QUERY SELECT COALESCE(ok,false),CASE WHEN COALESCE(ok,false) THEN 'None' ELSE 'ProfileDrift' END,4::smallint;";
        Assert.Equal(1, original.Groups["body"].Value.Split(final, StringSplitOptions.None).Length - 1);
        var blocks = new List<string>();
        foreach (var name in new[] { "audit-enrollment-profile4-readiness-structure.sql", "audit-enrollment-profile4-readiness-functions.sql" })
        {
            var source = await Read(name);
            var query = source[source.IndexOf("WITH ", StringComparison.Ordinal)..].Trim().TrimEnd(';')
                .Replace(":'expected_table_owner_role'", "(SELECT rolname FROM pg_catalog.pg_roles WHERE oid=table_owner)", StringComparison.Ordinal);
            blocks.Add($"    -- BEGIN generated {name}\n    ok := ok AND (\n{query}\n    );\n    -- END generated {name}\n");
        }
        Assert.Equal(original.Groups["body"].Value.Replace(final, string.Join("\n", blocks) + "\n" + final, StringComparison.Ordinal), candidate.Groups["body"].Value);
        Assert.DoesNotContain(":'expected_table_owner_role'", candidateSource, StringComparison.Ordinal);
        Assert.EndsWith("REVOKE ALL ON FUNCTION enrollment_execution.audit_execution_profile_structure(uuid) FROM PUBLIC;\n", candidateSource, StringComparison.Ordinal);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(candidate.Groups["body"].Value))).ToLowerInvariant();
        var runtime = await Read("enrollment-profile4-runtime-audit.sql");
        var constants = Regex.Matches(runtime, "expected_structure_hash constant text := '([0-9a-f]{64})';");
        Assert.Single(constants);
        Assert.Equal(hash, constants[0].Groups[1].Value);
    }
}
