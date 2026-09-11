using ItManagement.Agent.Spool;

namespace ItManagement.Agent.Tests;

public sealed class EnvelopeDigestTests
{
    [Fact]
    public void Compute_MatchesVersionTwoLengthFramedVector()
    {
        var digest = EnvelopeDigest.Compute(
            1,
            Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"),
            7,
            42,
            Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100"),
            DateTimeOffset.Parse("2026-01-02T03:04:05.6789012+08:00"),
            new string('a', 64));

        Assert.Equal("9d5e37fd0dc090c58fb2e99005e3711bce5f6d5e37492eefc866c6b6ef09eda3", digest);
    }
}
