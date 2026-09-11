using ItManagement.DirectoryConnector;

namespace DirectoryConnector.Tests;

public sealed class DistinguishedNameTests
{
    [Theory]
    [InlineData("CN=Doe\\, Jane,OU=People,DC=example,DC=com", "OU=People,DC=example,DC=com")]
    [InlineData("CN=Before\\0dAfter,DC=example,DC=com", "DC=example,DC=com")]
    [InlineData("OU=Sales+CN=Smith\\+Jones,DC=example,DC=com", "DC=example,DC=com")]
    public void GetParent_HandlesEscapedSeparators(string value, string expected)
    {
        Assert.Equal(expected, DistinguishedName.GetParent(value));
    }

    [Fact]
    public void AreEqual_NormalizesCaseHexEscapesAndMultiValuedRdnOrder()
    {
        Assert.True(DistinguishedName.AreEqual(
            "CN=Lu\\C4\\8Di\\C4\\87+UID=42,DC=EXAMPLE,DC=COM",
            "uid=42+cn=Lučić,dc=example,dc=com"));
        Assert.True(DistinguishedName.AreEqual("CN=😀,DC=example", "cn=\\F0\\9F\\98\\80,dc=example"));
    }

    [Fact]
    public void ComparisonKey_DoesNotCollideAcrossEscapedRdnSeparators()
    {
        var oneRdn = DistinguishedName.GetComparisonKey("CN=a\\,OU=b,DC=example");
        var twoRdns = DistinguishedName.GetComparisonKey("CN=a,OU=b,DC=example");

        Assert.NotEqual(oneRdn, twoRdns);
        Assert.True(DistinguishedName.AreEqual("CN=Sam\\ ,DC=example", "cn=Sam\\20,dc=example"));
    }

    [Fact]
    public void IsDescendantOf_UsesParsedRdnsRatherThanStringSuffix()
    {
        Assert.True(DistinguishedName.IsDescendantOf(
            "CN=Doe\\, Jane,OU=People,DC=example,DC=com",
            "OU=People,DC=example,DC=com"));
        Assert.False(DistinguishedName.IsDescendantOf(
            "CN=Jane,OU=NotPeople,DC=example,DC=com",
            "OU=People,DC=example,DC=com"));
        Assert.False(DistinguishedName.IsDescendantOf(
            "OU=People,DC=example,DC=com",
            "OU=People,DC=example,DC=com"));
        Assert.True(DistinguishedName.IsDescendantOf(
            "OU=People,DC=example,DC=com",
            "OU=People,DC=example,DC=com",
            includeSelf: true));
    }

    [Theory]
    [InlineData("CN=Broken\\")]
    [InlineData("CN=Missing, ,DC=example")]
    [InlineData("CN=Bad\\GG,DC=example")]
    public void Parse_RejectsInvalidDns(string value)
    {
        Assert.Throws<FormatException>(() => DistinguishedName.Parse(value));
    }
}
