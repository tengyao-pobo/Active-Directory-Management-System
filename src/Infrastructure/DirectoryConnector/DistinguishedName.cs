using System.Collections.ObjectModel;
using System.Buffers;
using System.Text;

namespace ItManagement.DirectoryConnector;

public sealed class DistinguishedName
{
    private readonly IReadOnlyList<string> canonicalRdns;
    private readonly IReadOnlyList<string> originalRdns;

    private DistinguishedName(IReadOnlyList<string> canonicalRdns, IReadOnlyList<string> originalRdns)
    {
        this.canonicalRdns = canonicalRdns;
        this.originalRdns = originalRdns;
    }

    public static DistinguishedName Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException("A distinguished name cannot be empty.");
        }

        var rdns = SplitUnescaped(value, ',');
        var canonical = rdns.Select(CanonicalizeRdn).ToArray();
        return new DistinguishedName(
            new ReadOnlyCollection<string>(canonical),
            new ReadOnlyCollection<string>(rdns.ToArray()));
    }

    public string? Parent => originalRdns.Count <= 1 ? null : string.Join(',', originalRdns.Skip(1));

    public bool EqualsDn(DistinguishedName other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return canonicalRdns.SequenceEqual(other.canonicalRdns, StringComparer.Ordinal);
    }

    public bool IsDescendantOf(DistinguishedName ancestor, bool includeSelf = false)
    {
        ArgumentNullException.ThrowIfNull(ancestor);
        if (canonicalRdns.Count < ancestor.canonicalRdns.Count
            || (!includeSelf && canonicalRdns.Count == ancestor.canonicalRdns.Count))
        {
            return false;
        }

        return canonicalRdns
            .Skip(canonicalRdns.Count - ancestor.canonicalRdns.Count)
            .SequenceEqual(ancestor.canonicalRdns, StringComparer.Ordinal);
    }

    public static string? GetParent(string value) => Parse(value).Parent;

    public static string GetComparisonKey(string value)
    {
        var parsed = Parse(value);
        return string.Concat(parsed.canonicalRdns.Select(rdn => $"{rdn.Length}:{rdn}"));
    }

    public static bool AreEqual(string left, string right) => Parse(left).EqualsDn(Parse(right));

    public static bool IsDescendantOf(string candidate, string ancestor, bool includeSelf = false) =>
        Parse(candidate).IsDescendantOf(Parse(ancestor), includeSelf);

    private static string CanonicalizeRdn(string rdn)
    {
        var avas = SplitUnescaped(rdn, '+');
        var canonicalAvas = new List<string>(avas.Count);
        foreach (var ava in avas)
        {
            var equalsIndex = FindUnescaped(ava, '=');
            if (equalsIndex <= 0)
            {
                throw new FormatException("A relative distinguished name is invalid.");
            }

            var attribute = ava[..equalsIndex].Trim();
            var rawValue = ava[(equalsIndex + 1)..];
            if (!IsAttributeType(attribute))
            {
                throw new FormatException("A distinguished name attribute type is invalid.");
            }

            var decodedValue = DecodeValue(rawValue);
            var canonicalAttribute = attribute.ToUpperInvariant();
            var canonicalValue = decodedValue.Normalize(NormalizationForm.FormKC).ToUpperInvariant();
            canonicalAvas.Add($"{canonicalAttribute.Length}:{canonicalAttribute}{canonicalValue.Length}:{canonicalValue}");
        }

        canonicalAvas.Sort(StringComparer.Ordinal);
        return string.Concat(canonicalAvas.Select(ava => $"{ava.Length}:{ava}"));
    }

    private static string DecodeValue(string value)
    {
        if (value.StartsWith('#'))
        {
            if (value.Length == 1 || (value.Length - 1) % 2 != 0 || !value[1..].All(Uri.IsHexDigit))
            {
                throw new FormatException("A hexadecimal distinguished name value is invalid.");
            }

            return value.ToUpperInvariant();
        }

        var bytes = new List<byte>();
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] == '\\')
            {
                if (++index >= value.Length)
                {
                    throw new FormatException("A distinguished name escape is incomplete.");
                }

                if (index + 1 < value.Length && Uri.IsHexDigit(value[index]) && Uri.IsHexDigit(value[index + 1]))
                {
                    bytes.Add(Convert.ToByte(value.Substring(index, 2), 16));
                    index++;
                }
                else
                {
                    if (value[index] is not (' ' or '"' or '#' or '+' or ',' or ';' or '<' or '=' or '>' or '\\'))
                    {
                        throw new FormatException("A distinguished name escape is invalid.");
                    }

                    AppendUtf8(bytes, value[index]);
                }
            }
            else
            {
                var status = Rune.DecodeFromUtf16(value.AsSpan(index), out var rune, out var consumed);
                if (status != OperationStatus.Done)
                {
                    throw new FormatException("A distinguished name contains invalid UTF-16.");
                }

                AppendUtf8(bytes, rune);
                index += consumed - 1;
            }
        }

        try
        {
            return new UTF8Encoding(false, true).GetString(bytes.ToArray());
        }
        catch (DecoderFallbackException exception)
        {
            throw new FormatException("A distinguished name contains invalid UTF-8.", exception);
        }
    }

    private static void AppendUtf8(List<byte> bytes, char value) => AppendUtf8(bytes, new Rune(value));

    private static void AppendUtf8(List<byte> bytes, Rune value)
    {
        Span<byte> encoded = stackalloc byte[4];
        var count = value.EncodeToUtf8(encoded);
        for (var index = 0; index < count; index++)
        {
            bytes.Add(encoded[index]);
        }
    }

    private static List<string> SplitUnescaped(string value, char separator)
    {
        var parts = new List<string>();
        var start = 0;
        var escaped = false;
        var quoted = false;
        for (var index = 0; index < value.Length; index++)
        {
            var current = value[index];
            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (current == '\\')
            {
                escaped = true;
            }
            else if (current == '"')
            {
                quoted = !quoted;
            }
            else if (current == separator && !quoted)
            {
                AddPart(value, start, index, parts);
                start = index + 1;
            }
        }

        if (escaped || quoted)
        {
            throw new FormatException("A distinguished name is incomplete.");
        }

        AddPart(value, start, value.Length, parts);
        return parts;
    }

    private static void AddPart(string value, int start, int end, List<string> parts)
    {
        while (start < end && char.IsWhiteSpace(value[start]))
        {
            start++;
        }

        while (end > start && char.IsWhiteSpace(value[end - 1]) && !IsEscaped(value, end - 1, start))
        {
            end--;
        }

        var part = value[start..end];
        if (part.Length == 0)
        {
            throw new FormatException("A distinguished name component cannot be empty.");
        }

        parts.Add(part);
    }

    private static bool IsEscaped(string value, int index, int lowerBound)
    {
        var slashCount = 0;
        for (var position = index - 1; position >= lowerBound && value[position] == '\\'; position--)
        {
            slashCount++;
        }

        return slashCount % 2 != 0;
    }

    private static int FindUnescaped(string value, char target)
    {
        var escaped = false;
        for (var index = 0; index < value.Length; index++)
        {
            if (escaped)
            {
                escaped = false;
            }
            else if (value[index] == '\\')
            {
                escaped = true;
            }
            else if (value[index] == target)
            {
                return index;
            }
        }

        return -1;
    }

    private static bool IsAttributeType(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        if (char.IsLetter(value[0]))
        {
            return value.All(character => char.IsLetterOrDigit(character) || character == '-');
        }

        return value.Split('.').All(part => part.Length > 0 && part.All(char.IsDigit));
    }
}
