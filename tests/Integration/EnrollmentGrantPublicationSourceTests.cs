using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task Profile4PublicationTemplateAndRenderedPinsMatchIndependentSources()
    {
        async Task<string> Read(string name) => (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, name))).Replace("\r\n", "\n", StringComparison.Ordinal);
        static string Body(string source)
        {
            var matches = Regex.Matches(source, @"AS \$function\$(?<body>.*?)\$function\$;", RegexOptions.Singleline);
            Assert.Single(matches);
            return matches[0].Groups["body"].Value;
        }
        static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
        const string placeholder = "__RUNTIME_AUDIT_SHA256__";
        var template = await Read("enrollment-profile4-publication.template.sql");
        Assert.Equal(1, template.Split(placeholder, StringSplitOptions.None).Length - 1);
        Assert.Contains("    expected_runtime_hash constant text := '" + placeholder + "';", Body(template), StringComparison.Ordinal);
        var runtimeHash = Hash(Body(await Read("enrollment-profile4-runtime-audit.sql")));
        var rendered = await Read("enrollment-profile4-publication.sql");
        Assert.Equal(template.Replace(placeholder, runtimeHash, StringComparison.Ordinal), rendered);
        var metadata = await Read("audit-enrollment-profile4-publication-metadata.sql");
        var templatePins = Regex.Matches(metadata, "'([0-9a-f]{64})' -- generated publication template SHA-256");
        Assert.Single(templatePins);
        Assert.Equal(Hash(Body(template)), templatePins[0].Groups[1].Value);
        var catalog = await Read("audit-enrollment-profile4-publication.sql");
        var query = metadata[metadata.IndexOf("WITH ", StringComparison.Ordinal)..].Trim().TrimEnd(';');
        var expected = "-- Unconsumed exact rendered publication guard attestation for history and external composition.\nSELECT (\n" + query +
            "\n) AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p\n WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.guard_profile4_publication()')\n" +
            " AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.replace(p.prosrc,E'\\r\\n',E'\\n'),'UTF8')),'hex')='" + Hash(Body(rendered)) + "') AS is_valid;\n";
        Assert.Equal(expected, catalog);
        var history = await Read("audit-enrollment-profile4-history-transition.sql");
        Assert.Contains(catalog[catalog.IndexOf("SELECT (", StringComparison.Ordinal)..].Trim().TrimEnd(';')
            .Replace(":'expected_table_owner_role'", "(SELECT rolname FROM pg_catalog.pg_roles WHERE oid=owner_oid)", StringComparison.Ordinal), history, StringComparison.Ordinal);
    }
}
