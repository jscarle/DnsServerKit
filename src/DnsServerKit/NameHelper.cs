using System.Text;

namespace DnsServerKit;

public static class NameHelper
{
    public static string DecodeDnsName(ReadOnlySpan<byte> span, ref int offset)
    {
        var nameBuilder = new StringBuilder();

        while (offset < span.Length)
        {
            var length = span[offset];

            // If length is zero, we've reached the end of the name
            if (length == 0)
            {
                offset++;
                break;
            }

            // Check for pointers (compression)
            if ((length & 0xC0) == 0xC0)
            {
                // The next byte is part of the pointer
                var pointer = ((length & 0x3F) << 8) | span[offset + 1];
                offset += 2;
                var pointerOffset = pointer; // Save the current pointer
                DecodeDnsName(span, ref pointerOffset);
                break;
            }

            // Move to the next label part
            offset++;
            if (nameBuilder.Length > 0)
            {
                nameBuilder.Append('.');
            }

            var slice = span.Slice(offset, length);
            var str = Encoding.ASCII.GetString(slice);
            nameBuilder.Append(str);
            offset += length;
        }

        return nameBuilder.ToString();
    }
    
    public static byte[] EncodeDnsName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return [0];
        }

        var labels = name.Split('.');
        var result = new List<byte>();

        foreach (var label in labels)
        {
            if (label.Length > 63)
            {
                throw new ArgumentException("Each label in the DNS name must be 63 characters or less.", nameof(name));
            }

            var length = (byte)label.Length;
            result.Add(length);
            var bytes = Encoding.ASCII.GetBytes(label);
            result.AddRange(bytes);
        }

        // Add the terminating zero byte
        result.Add(0);

        return result.ToArray();
    }
}
