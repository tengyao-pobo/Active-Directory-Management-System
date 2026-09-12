using ItManagement.EnrollmentWorker;
using Xunit;

namespace EnrollmentWorker.Tests;

public sealed class EnrollmentWorkerCertificateFileTests
{
    [Fact]
    public void MissingCertificateAndDirectoriesAreRejectedWithFixedDiagnostic()
    {
        foreach (var path in new[] { Path.GetTempPath(), Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pem") })
        {
            var error = Assert.Throws<InvalidOperationException>(() => PostgresEnrollmentWorkerEnvironment.RequireLocalCertificateFile(path));
            Assert.Equal("EnrollmentWorkerCertificateFileInvalid", error.Message);
            Assert.Null(error.InnerException);
        }
    }

    [Fact]
    public void LocalRegularFilePassesLocationCheckBeforeProviderParsesCertificate()
    {
        var path = Path.Combine(Path.GetTempPath(), "worker-cert-test-" + Guid.NewGuid() + ".pem");
        try
        {
            File.WriteAllText(path, "synthetic file; no certificate or secret");
            PostgresEnrollmentWorkerEnvironment.RequireLocalCertificateFile(path);
        }
        finally { File.Delete(path); }
    }
}
