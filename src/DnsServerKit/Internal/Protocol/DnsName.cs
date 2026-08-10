using System.Text;

namespace DnsServerKit.Internal.Protocol;

/// <summary>Represents an immutable DNS domain name.</summary>
internal sealed class DnsName : IEquatable<DnsName>
{
    /// <summary>Gets the presentation-format domain name supplied by the caller.</summary>
    public string Value { get; }

    /// <summary>Gets the canonical DNS wire-format name.</summary>
    public ReadOnlySpan<byte> WireBytes => _wireBytes;

    internal int WireHashCode { get; }
    private const uint HashOffset = 2166136261;
    private const uint HashPrime = 16777619;
    private readonly byte[] _wireBytes;

    public DnsName(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        Span<byte> wireBytes = stackalloc byte[255];
        var wireLength = Encode(value.AsSpan(), wireBytes);

        Value = value.Length == 0 ? "." : value;
        _wireBytes = wireBytes[..wireLength]
            .ToArray();
        WireHashCode = ComputeWireHash(_wireBytes);
    }

    private DnsName(string value, byte[] canonicalWireBytes)
    {
        Value = value;
        _wireBytes = canonicalWireBytes;
        WireHashCode = ComputeWireHash(_wireBytes);
    }

    public bool Equals(DnsName? other)
    {
        if (ReferenceEquals(this, other))
            return true;

        return other is not null
               && WireHashCode == other.WireHashCode
               && _wireBytes.AsSpan()
                   .SequenceEqual(other._wireBytes);
    }

    public override bool Equals(object? obj)
    {
        return obj is DnsName other && Equals(other);
    }

    public override int GetHashCode()
    {
        return WireHashCode;
    }

    public override string ToString()
    {
        return Value;
    }

    internal static DnsName FromWire(ReadOnlySpan<byte> wireName)
    {
        if (wireName.Length == 0 || wireName[^1] != 0)
            throw new FormatException("The DNS wire name must end with a zero-length label.");

        var valueBuilder = new StringBuilder(wireName.Length);
        var canonicalWireBytes = wireName.ToArray();
        var offset = 0;
        var firstLabel = true;

        while (offset < canonicalWireBytes.Length)
        {
            var labelLength = canonicalWireBytes[offset++];
            if (labelLength == 0)
                break;

            if (!firstLabel)
                valueBuilder.Append('.');

            for (var labelIndex = 0; labelIndex < labelLength; labelIndex++)
            {
                var value = canonicalWireBytes[offset++];
                canonicalWireBytes[offset - 1] = ToLowerAscii(value);

                if (value is >= 0x21 and <= 0x7E && value is not (byte)'.' and not (byte)'\\')
                {
                    valueBuilder.Append((char)value);
                }
                else
                {
                    valueBuilder.Append('\\');
                    valueBuilder.Append((char)('0' + value / 100));
                    valueBuilder.Append((char)('0' + value / 10 % 10));
                    valueBuilder.Append((char)('0' + value % 10));
                }
            }

            firstLabel = false;
        }

        var valueString = valueBuilder.Length == 0 ? "." : valueBuilder.ToString();
        return new DnsName(valueString, canonicalWireBytes);
    }

    internal static int StartWireHash()
    {
        return unchecked((int)HashOffset);
    }

    internal static int AppendWireHash(int hashCode, byte value)
    {
        var hash = unchecked((uint)hashCode);
        hash ^= ToLowerAscii(value);
        hash *= HashPrime;

        return unchecked((int)hash);
    }

    internal static int ComputeWireHash(ReadOnlySpan<byte> wireName)
    {
        var hashCode = StartWireHash();
        foreach (var value in wireName)
            hashCode = AppendWireHash(hashCode, value);

        return hashCode;
    }

    internal static int ComputeZoneHash(int nameHashCode, ushort @class)
    {
        var hashCode = AppendWireHash(nameHashCode, (byte)(@class >> 8));
        hashCode = AppendWireHash(hashCode, (byte)@class);

        return hashCode;
    }

    internal bool WireEquals(ReadOnlySpan<byte> other)
    {
        if (_wireBytes.Length != other.Length)
            return false;

        for (var index = 0; index < _wireBytes.Length; index++)
        {
            if (_wireBytes[index] != ToLowerAscii(other[index]))
                return false;
        }

        return true;
    }

    internal static int Encode(ReadOnlySpan<char> value, Span<byte> destination)
    {
        if (value.Length == 0 || value.SequenceEqual("."))
        {
            destination[0] = 0;
            return 1;
        }

        var destinationOffset = 1;
        var labelLengthOffset = 0;
        var labelLength = 0;
        var characterIndex = 0;

        while (characterIndex < value.Length)
        {
            var character = value[characterIndex];
            if (character == '.')
            {
                if (labelLength == 0)
                    throw new FormatException("A DNS name cannot contain an empty label.");

                destination[labelLengthOffset] = (byte)labelLength;
                characterIndex++;
                if (characterIndex == value.Length)
                {
                    if (destinationOffset >= destination.Length)
                        throw new FormatException("A DNS name cannot exceed 255 octets.");

                    destination[destinationOffset++] = 0;
                    return destinationOffset;
                }

                if (destinationOffset >= destination.Length)
                    throw new FormatException("A DNS name cannot exceed 255 octets.");

                labelLengthOffset = destinationOffset++;
                labelLength = 0;
                continue;
            }

            byte labelByte;
            if (character == '\\')
            {
                characterIndex++;
                if (characterIndex >= value.Length)
                    throw new FormatException("A DNS name cannot end with an incomplete escape sequence.");

                var escapedCharacter = value[characterIndex];
                if (escapedCharacter is >= '0' and <= '9')
                {
                    if (characterIndex + 2 >= value.Length || value[characterIndex + 1] is < '0' or > '9' || value[characterIndex + 2] is < '0' or > '9')
                        throw new FormatException("A numeric DNS name escape must contain exactly three decimal digits.");

                    var escapedOctet = (escapedCharacter - '0') * 100 + (value[characterIndex + 1] - '0') * 10 + (value[characterIndex + 2] - '0');
                    if (escapedOctet > byte.MaxValue)
                        throw new FormatException("A numeric DNS name escape cannot exceed 255.");

                    labelByte = (byte)escapedOctet;
                    characterIndex += 3;
                }
                else
                {
                    if (escapedCharacter > byte.MaxValue)
                        throw new FormatException("A DNS label character cannot exceed one octet.");

                    labelByte = (byte)escapedCharacter;
                    characterIndex++;
                }
            }
            else
            {
                if (character > byte.MaxValue)
                    throw new FormatException("A DNS label character cannot exceed one octet.");

                labelByte = (byte)character;
                characterIndex++;
            }

            if (labelLength == 63)
                throw new FormatException("A DNS label cannot exceed 63 octets.");

            if (destinationOffset >= destination.Length)
                throw new FormatException("A DNS name cannot exceed 255 octets.");

            destination[destinationOffset++] = ToLowerAscii(labelByte);
            labelLength++;
        }

        destination[labelLengthOffset] = (byte)labelLength;
        if (destinationOffset >= destination.Length)
            throw new FormatException("A DNS name cannot exceed 255 octets.");

        destination[destinationOffset++] = 0;
        return destinationOffset;
    }

    internal static byte ToLowerAscii(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;
    }
}
