using ItManagement.EnrollmentGrantDelivery;
using Xunit;

namespace EnrollmentGrantDelivery.Tests;

public sealed class EnrollmentDeliveryAuditGateTests
{
    [Fact]
    public void UnfinishedPublicProfileCannotAttestReadiness()
    {
        using var stream = typeof(PostgresEnrollmentGrantDeliveryStore).Assembly
            .GetManifestResourceStream("EnrollmentDeliveryCatalogAudit");
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream!);
        var statements = reader.ReadToEnd().Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.Length != 0 && !line.StartsWith("--", StringComparison.Ordinal));
        Assert.Equal("SELECT false AS is_valid;", string.Join("\n", statements));
    }
}
