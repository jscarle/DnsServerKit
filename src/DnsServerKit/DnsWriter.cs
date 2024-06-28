using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using DnsServerKit.Queries;
using DnsServerKit.ResourceRecords;
using DnsServerKit.Responses;
using JetBrains.Annotations;

namespace DnsServerKit;

[MustDisposeResource]
public sealed class DnsWriter : IDisposable
{
    private readonly DnsResponse _dnsResponse;
    private readonly Dictionary<string, int> _namePositions = new();
    private byte[] _bytes;

    public DnsWriter(DnsResponse dnsResponse)
    {
        _dnsResponse = dnsResponse;
    }

    public ReadOnlyMemory<byte> GetBytes()
    {
        using var memoryStream = new MemoryStream(512);

        WriteHeader(memoryStream, _dnsResponse);

        foreach (var question in _dnsResponse.Questions)
        {
            WriteName(memoryStream, question.Name);
            WriteQuestion(memoryStream, question);
        }

        foreach (var answer in _dnsResponse.Answers)
        {
            WriteName(memoryStream, answer.Name);
            WriteAnswer(memoryStream, answer);
            WriteAnswerData(memoryStream, answer);
        }

        var memory = ToReadOnlyMemory(memoryStream);
        return memory;
    }

    private static void WriteHeader(MemoryStream memoryStream, DnsResponse dnsResponse)
    {
        var bytes = ArrayPool<byte>.Shared.Rent(12);

        // Transaction ID
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0, 2), dnsResponse.ID);

        // Flags
        var flags = (ushort)((dnsResponse.QR ? 0x8000 : 0)
                             | ((ushort)dnsResponse.OpCode << 11)
                             | (dnsResponse.AA ? 0x0400 : 0)
                             | (dnsResponse.TC ? 0x0200 : 0)
                             | (dnsResponse.RD ? 0x0100 : 0)
                             | (dnsResponse.RA ? 0x0080 : 0)
                             | (dnsResponse.Z << 4)
                             | (ushort)dnsResponse.RCode);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2, 2), flags);

        // Question Count
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4, 2), dnsResponse.QDCount);

        // Answer Record Count
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6, 2), dnsResponse.ANCount);

        // Authority Record Count
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8, 2), dnsResponse.NSCount);

        // Additional Record Count
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10, 2), dnsResponse.ARCount);

        // Write header
        memoryStream.Write(bytes, 0, 12);
        
        ArrayPool<byte>.Shared.Return(bytes);
    }

    private static void WriteQuestion(MemoryStream memoryStream, DnsQuestion question)
    {
        var bytes = ArrayPool<byte>.Shared.Rent(4);

        // Encode Type
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0, 2), (ushort)question.Type);

        // Encode Class
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2, 2), (ushort)question.Class);

        // Write question
        memoryStream.Write(bytes, 0, 4);
        
        ArrayPool<byte>.Shared.Return(bytes);
    }

    private static void WriteAnswer(MemoryStream memoryStream, IResourceRecord resourceRecord)
    {
        var bytes = ArrayPool<byte>.Shared.Rent(8);

        // Encode Type
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0, 2), (ushort)resourceRecord.Type);

        // Encode Class
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2, 2), (ushort)resourceRecord.Class);

        // Encode TTL
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4, 4), resourceRecord.Ttl);

        // Write answer
        memoryStream.Write(bytes, 0, 8);
        
        ArrayPool<byte>.Shared.Return(bytes);
    }

    private static void WriteAnswerData(MemoryStream memoryStream, IResourceRecord answer)
    {
        if (answer is ARecord aRecord)
            WriteARecord(memoryStream, aRecord);
    }

    private static void WriteARecord(MemoryStream memoryStream, ARecord aRecord)
    {
        // Encode IP address
        var ipAddressBytes = aRecord.IpAddress.GetAddressBytes();
        
        // Calculate total length
        var length = (ushort)ipAddressBytes.Length;

        // Write record
        WriteLength(memoryStream, length);
        memoryStream.Write(ipAddressBytes, 0, ipAddressBytes.Length);
    }

    private static void WriteLength(MemoryStream memoryStream, ushort length)
    {
        var bytes = ArrayPool<byte>.Shared.Rent(2);

        // Encode data length
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0, 2), length);

        memoryStream.Write(bytes, 0, 2);
        
        ArrayPool<byte>.Shared.Return(bytes);
    }

    private void WriteName(MemoryStream memoryStream, string name)
    {
        var labels = name.Split('.');
        for (var i = 0; i < labels.Length; i++)
        {
            var label = string.Join('.', labels.Skip(i));
            if (_namePositions.TryGetValue(label, out var position))
            {
                // Write pointer to the existing label
                var pointer = (ushort)(0xC000 | position);
                var pointerBytes = ArrayPool<byte>.Shared.Rent(2);
                BinaryPrimitives.WriteUInt16BigEndian(pointerBytes.AsSpan(0, 2), pointer);
                memoryStream.Write(pointerBytes, 0, 2);
                ArrayPool<byte>.Shared.Return(pointerBytes);
                return;
            }
            // Write the label length and content
            var labelBytes = Encoding.ASCII.GetBytes(labels[i]);
            memoryStream.WriteByte((byte)labelBytes.Length);
            memoryStream.Write(labelBytes);
            // Store position of this label
            _namePositions[label] = (int)memoryStream.Position - labelBytes.Length - 1;
        }
        // Write the final zero byte
        memoryStream.WriteByte(0);
    }

    private ReadOnlyMemory<byte> ToReadOnlyMemory(MemoryStream memoryStream)
    {
        var length = (int)memoryStream.Position;
        
        _bytes = ArrayPool<byte>.Shared.Rent(length);
        
        memoryStream.Position = 0;
        memoryStream.ReadExactly(_bytes, 0, length);
        
        var memory = new ReadOnlyMemory<byte>(_bytes, 0, length);
        
        return memory;
    }

    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(_bytes);
    }
}
