using System.Text;

namespace DnsServerKit;

public static class NameHelper
{
    public static string DecodeDnsName(ReadOnlySpan<byte> span, ref int offset)
    {
        var nameBuilder = new StringBuilder();
        var currentOffset = offset;
        HashSet<int>? pointerOffsets = null;
        var remainingPointerJumps = span.Length;
        var followedPointer = false;

        while (currentOffset < span.Length)
        {
            var length = span[currentOffset];

            // If length is zero, we've reached the end of the name
            if (length == 0)
            {
                if (!followedPointer)
                    offset = currentOffset + 1;

                return nameBuilder.ToString();
            }

            // Check for pointers (compression)
            if ((length & 0xC0) == 0xC0)
            {
                if (currentOffset + 1 >= span.Length)
                    throw new FormatException("The DNS compression pointer is truncated.");

                if (remainingPointerJumps == 0)
                    throw new FormatException("The DNS compression pointer jump limit was exceeded.");

                pointerOffsets ??= new HashSet<int>();
                if (!pointerOffsets.Add(currentOffset))
                    throw new FormatException("The DNS compression pointer contains a cycle.");

                // The next byte is part of the pointer
                var pointer = ((length & 0x3F) << 8) | span[currentOffset + 1];
                if (pointer >= span.Length)
                    throw new FormatException("The DNS compression pointer points outside the packet.");

                if (pointer >= currentOffset)
                    throw new FormatException("The DNS compression pointer must point to a prior name.");

                if (!followedPointer)
                {
                    offset = currentOffset + 2;
                    followedPointer = true;
                }

                remainingPointerJumps--;
                currentOffset = pointer;
                continue;
            }

            if ((length & 0xC0) != 0)
                throw new FormatException("The DNS label uses a reserved length prefix.");

            // Move to the next label part
            currentOffset++;
            if (nameBuilder.Length > 0)
            {
                nameBuilder.Append('.');
            }

            if (length > span.Length - currentOffset)
                throw new FormatException("The DNS label is truncated.");

            var slice = span.Slice(currentOffset, length);
            var str = Encoding.ASCII.GetString(slice);
            nameBuilder.Append(str);
            currentOffset += length;
        }

        throw new FormatException("The DNS name is not terminated within the packet.");
    }
}
