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
}
