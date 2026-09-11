using ItManagement.DirectoryConnector;

namespace DirectoryConnector.Tests;

public sealed class LdapFilterTests
{
    [Fact]
    public void EscapeAssertionValue_EscapesEveryFilterMetaCharacter()
    {
        Assert.Equal("a\\2a\\28b\\29\\5c\\00", LdapFilter.EscapeAssertionValue("a*(b)\\\0"));
        Assert.Equal("Lučić", LdapFilter.EscapeAssertionValue("Lučić"));
    }

    [Fact]
    public void EscapeBinaryGuid_UsesActiveDirectoryByteOrder()
    {
        var guid = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");

        Assert.Equal(
            "\\33\\22\\11\\00\\55\\44\\77\\66\\88\\99\\aa\\bb\\cc\\dd\\ee\\ff",
            LdapFilter.EscapeBinary(guid));
    }
}
