using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task Profile4HistoryTransitionPinsCurrentSources()
    {
        async Task<string> Read(string name) => (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, name))).Replace("\r\n", "\n", StringComparison.Ordinal);
        var candidate = await Read("audit-enrollment-profile4-history-transition.sql");
        foreach (var (name, constant) in new[] {
            ("enrollment-profile4-structure-audit.sql", "expected_audit_hash"),
            ("enrollment-profile4-runtime-audit.sql", "expected_runtime_audit_hash") })
        {
            var bodies = Regex.Matches(await Read(name), @"AS \$function\$(?<body>.*?)\$function\$;", RegexOptions.Singleline);
            Assert.Single(bodies);
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(bodies[0].Groups["body"].Value))).ToLowerInvariant();
            var values = Regex.Matches(candidate, constant + " constant text := '([0-9a-f]{64})';");
            Assert.Single(values);
            Assert.Equal(hash, values[0].Groups[1].Value);
        }
        const string manifestPattern = "expected_manifest constant bytea := decode\\('([0-9a-f]{64})','hex'\\);";
        var manifests = Regex.Matches(candidate, manifestPattern);
        Assert.Single(manifests);
        Assert.Equal(Regex.Match(await Read("enrollment-profile4-ready.sql"), manifestPattern).Groups[1].Value, manifests[0].Groups[1].Value);
        var original = await Read("audit-enrollment-delivery-history.sql");
        const string startMarker = "      IF EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy WHERE policy.polname IN(";
        var start = original.IndexOf(startMarker, StringComparison.Ordinal);
        var end = original.LastIndexOf("    END LOOP;", StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        // Preserve the complete reviewed temporary-policy and row-scan/cleanup implementation.
        Assert.Contains(original[start..(end + "    END LOOP;".Length)], candidate, StringComparison.Ordinal);
        Assert.DoesNotContain(":'expected_", candidate, StringComparison.Ordinal);
        var bootstrap = await Read("activate-enrollment-profile4-candidate.sql");
        Assert.Contains("CREATE TEMP TABLE profile4_history_expected", bootstrap, StringComparison.Ordinal);
        Assert.Contains("ON COMMIT DROP", bootstrap, StringComparison.Ordinal);
        Assert.Contains("true,:'expected_generation'::bigint,:'expected_installation_nonce'::uuid,decode(:'expected_manifest_sha256','hex')", bootstrap, StringComparison.Ordinal);
        Assert.DoesNotContain("DROP TABLE", bootstrap, StringComparison.OrdinalIgnoreCase);
    }
}
