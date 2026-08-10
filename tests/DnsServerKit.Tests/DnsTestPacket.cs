using System.Buffers.Binary;
using DnsServerKit.Internal.Protocol;

namespace DnsServerKit.Tests;

internal static class DnsTestPacket
{
    public static byte[] CreateQuery(
        string name = "example.com",
        ushort type = 1,
        ushort @class = 1,
        ushort transactionId = 0x1234,
        ushort flags = 0,
        ushort questionCount = 1,
        ushort answerCount = 0,
        ushort authorityCount = 0,
        ushort additionalCount = 0)
    {
        var wireName = new DnsName(name).WireBytes;
        var packet = new byte[12 + wireName.Length + 4];
        BinaryPrimitives.WriteUInt16BigEndian(packet, transactionId);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), questionCount);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6), answerCount);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(8), authorityCount);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), additionalCount);
        wireName.CopyTo(packet.AsSpan(12));
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(12 + wireName.Length), type);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(14 + wireName.Length), @class);

        return packet;
    }

    public static string ReadName(ReadOnlySpan<byte> packet, ref int offset)
    {
        var labels = new List<string>();
        var currentOffset = offset;
        var followedPointer = false;
        var remainingJumps = packet.Length;

        while (true)
        {
            var labelLength = packet[currentOffset++];
            if (labelLength == 0)
            {
                if (!followedPointer)
                    offset = currentOffset;

                return string.Join('.', labels);
            }

            if ((labelLength & 0xC0) == 0xC0)
            {
                if (remainingJumps-- == 0)
                    throw new FormatException("Compression pointer cycle.");

                var pointer = ((labelLength & 0x3F) << 8) | packet[currentOffset++];
                if (!followedPointer)
                {
                    offset = currentOffset;
                    followedPointer = true;
                }

                currentOffset = pointer;
                continue;
            }

            labels.Add(System.Text.Encoding.ASCII.GetString(packet.Slice(currentOffset, labelLength)));
            currentOffset += labelLength;
        }
    }
}
