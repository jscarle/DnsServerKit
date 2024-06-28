using System.Buffers.Binary;
using System.Text;
using DnsServerKit.ResourceRecords;
using DnsServerKit.Responses;

namespace DnsServerKit;

public sealed class DnsWriter
{
    public static ReadOnlyMemory<byte> GetBytes(DnsResponse dnsResponse)
    {
        var memoryStream = new MemoryStream();
        var namePositions = new Dictionary<string, int>();

        var headerBytes = new byte[12];

        // Transaction ID
        BinaryPrimitives.WriteUInt16BigEndian(headerBytes.AsSpan(0, 2), dnsResponse.ID);

        // Flags
        var flags = (ushort)(
            (dnsResponse.QR ? 0x8000 : 0) |
            ((ushort)dnsResponse.OpCode << 11) |
            (dnsResponse.AA ? 0x0400 : 0) |
            (dnsResponse.TC ? 0x0200 : 0) |
            (dnsResponse.RD ? 0x0100 : 0) |
            (dnsResponse.RA ? 0x0080 : 0) |
            (dnsResponse.Z << 4) |
            (ushort)dnsResponse.RCode
        );
        BinaryPrimitives.WriteUInt16BigEndian(headerBytes.AsSpan(2, 2), flags);

        // Question Count
        BinaryPrimitives.WriteUInt16BigEndian(headerBytes.AsSpan(4, 2), dnsResponse.QDCount);

        // Answer Record Count
        BinaryPrimitives.WriteUInt16BigEndian(headerBytes.AsSpan(6, 2), dnsResponse.ANCount);

        // Authority Record Count
        BinaryPrimitives.WriteUInt16BigEndian(headerBytes.AsSpan(8, 2), dnsResponse.NSCount);

        // Additional Record Count
        BinaryPrimitives.WriteUInt16BigEndian(headerBytes.AsSpan(10, 2), dnsResponse.ARCount);
        
        memoryStream.Write(headerBytes);

        foreach (var question in dnsResponse.Questions)
        {
            WriteName(memoryStream, question.Name, namePositions);
            
            var questionBytes = new byte[4];

            // Encode Type
            BinaryPrimitives.WriteUInt16BigEndian(questionBytes.AsSpan(0, 2), (ushort)question.Type);

            // Encode Class
            BinaryPrimitives.WriteUInt16BigEndian(questionBytes.AsSpan(2, 2), (ushort)question.Class);
            
            memoryStream.Write(questionBytes);
        }

        foreach (var answer in dnsResponse.Answers)
        {
            if (answer is ARecord aRecord)
            {
                WriteName(memoryStream, aRecord.Name, namePositions);

                var answerBytes = new byte[8];

                // Encode Type
                BinaryPrimitives.WriteUInt16BigEndian(answerBytes.AsSpan(0, 2), (ushort)aRecord.Type);

                // Encode Class
                BinaryPrimitives.WriteUInt16BigEndian(answerBytes.AsSpan(2, 2), (ushort)aRecord.Class);

                // Encode TTL
                BinaryPrimitives.WriteUInt32BigEndian(answerBytes.AsSpan(4, 4), aRecord.Ttl);
                
                memoryStream.Write(answerBytes);

                var ipAddressBytes = aRecord.IpAddress.GetAddressBytes();
                var dataLength = (ushort)ipAddressBytes.Length;

                var dataLengthBytes = new byte[2];

                // Encode data length
                BinaryPrimitives.WriteUInt16BigEndian(dataLengthBytes.AsSpan(0, 2), dataLength);
                
                memoryStream.Write(dataLengthBytes);
                memoryStream.Write(ipAddressBytes);
            }
        }

        return new ReadOnlyMemory<byte>(memoryStream.ToArray());
    }

    private static void WriteName(MemoryStream stream, string name, Dictionary<string, int> namePositions)
    {
        var labels = name.Split('.');
        for (int i = 0; i < labels.Length; i++)
        {
            var label = string.Join('.', labels.Skip(i));
            if (namePositions.TryGetValue(label, out int position))
            {
                // Write pointer to the existing label
                var pointer = (ushort)(0xC000 | position);
                var pointerBytes = new byte[2];
                BinaryPrimitives.WriteUInt16BigEndian(pointerBytes.AsSpan(), pointer);
                stream.Write(pointerBytes);
                return;
            }
            else
            {
                // Write the label length and content
                var labelBytes = Encoding.ASCII.GetBytes(labels[i]);
                stream.WriteByte((byte)labelBytes.Length);
                stream.Write(labelBytes);
                // Store position of this label
                namePositions[label] = (int)stream.Position - labelBytes.Length - 1;
            }
        }
        // Write the final zero byte
        stream.WriteByte(0);
    }
}