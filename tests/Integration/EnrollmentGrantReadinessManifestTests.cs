using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task Profile4ManifestMatchesIndependentSourceBundle()
    {
        string[] names = ["audit-enrollment-delivery-acks.sql", "audit-enrollment-delivery-envelopes.sql",
            "audit-enrollment-delivery-history-rows.sql", "audit-enrollment-delivery-permits.sql",
            "audit-enrollment-delivery-results.sql", "audit-enrollment-delivery-status.sql",
            "audit-enrollment-delivery-stops.sql", "enrollment-profile4-readiness.sql"];
        var bundle = new StringBuilder("enrollment-profile4-attestation-v1\n");
        foreach (var name in names)
        {
            var source = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, name))).Replace("\r\n", "\n", StringComparison.Ordinal);
            Assert.DoesNotContain("expected_manifest constant", source, StringComparison.Ordinal);
            bundle.Append(name).Append('\n').Append(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source))).ToLowerInvariant()).Append('\n');
        }
        var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(bundle.ToString()))).ToLowerInvariant();
        var function = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-profile4-ready.sql"));
        var constants = Regex.Matches(function, "expected_manifest constant bytea := decode\\('([0-9a-f]{64})','hex'\\);");
        Assert.Single(constants);
        Assert.Equal(expected, constants[0].Groups[1].Value);
    }
}
