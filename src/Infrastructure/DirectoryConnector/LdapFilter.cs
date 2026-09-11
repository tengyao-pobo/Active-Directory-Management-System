using System.Text;

namespace ItManagement.DirectoryConnector;

public static class LdapFilter
{
    public static string EscapeAssertionValue(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var result = new StringBuilder(value.Length);
        foreach (var rune in value.EnumerateRunes())
        {
            if (rune.Value is 0x00 or 0x28 or 0x29 or 0x2a or 0x5c)
            {
                result.Append('\\').Append(rune.Value.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
            }
            else
            {
                result.Append(rune);
            }
        }

        return result.ToString();
    }

    public static string EscapeBinary(Guid value) => EscapeBinary(value.ToByteArray());

    public static string EscapeBinary(ReadOnlySpan<byte> value)
    {
        var result = new StringBuilder(value.Length * 3);
        foreach (var valueByte in value)
        {
            result.Append('\\').Append(valueByte.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
        }

        return result.ToString();
    }
}
