using System.Buffers.Binary;
using System.Collections.ObjectModel;
using DnsServerKit.ResourceRecords;

namespace DnsServerKit.Data;

/// <summary>Represents an immutable set of records sharing an owner name, type, and class.</summary>
public sealed class DnsRecordSet
{
    private const int ResourceRecordHeaderLength = 12;
    private readonly byte[] _encodedAnswers;
    private readonly int[] _recordEndOffsets;

    public DnsName Name { get; }

    public ushort Type { get; }

    public ushort Class { get; }

    public ReadOnlyCollection<DnsResourceRecord> Records { get; }

    internal ReadOnlySpan<byte> EncodedAnswers => _encodedAnswers;

    internal ReadOnlySpan<int> RecordEndOffsets => _recordEndOffsets;

    internal DnsRecordSet(DnsResourceRecord[] records)
    {
        if (records.Length == 0)
            throw new ArgumentException("A DNS record set must contain at least one record.", nameof(records));
        if (records.Length > ushort.MaxValue)
            throw new ArgumentException("A DNS record set cannot contain more than 65,535 records.", nameof(records));

        Name = records[0].Name;
        Type = records[0].Type;
        Class = records[0].Class;

        var encodedLength = 0;
        foreach (var record in records)
        {
            if (!record.Name.Equals(Name) || record.Type != Type || record.Class != Class)
                throw new ArgumentException("Every record in an RRset must have the same owner name, type, and class.", nameof(records));

            encodedLength = checked(encodedLength + ResourceRecordHeaderLength + record.ResourceData.Length);
        }

        _encodedAnswers = new byte[encodedLength];
        _recordEndOffsets = new int[records.Length];

        var offset = 0;
        for (var recordIndex = 0; recordIndex < records.Length; recordIndex++)
        {
            var record = records[recordIndex];
            var resourceData = record.ResourceData;

            BinaryPrimitives.WriteUInt16BigEndian(_encodedAnswers.AsSpan(offset), 0xC00C);
            BinaryPrimitives.WriteUInt16BigEndian(_encodedAnswers.AsSpan(offset + 2), record.Type);
            BinaryPrimitives.WriteUInt16BigEndian(_encodedAnswers.AsSpan(offset + 4), record.Class);
            BinaryPrimitives.WriteUInt32BigEndian(_encodedAnswers.AsSpan(offset + 6), record.Ttl);
            BinaryPrimitives.WriteUInt16BigEndian(_encodedAnswers.AsSpan(offset + 10), (ushort)resourceData.Length);
            resourceData.CopyTo(_encodedAnswers.AsSpan(offset + ResourceRecordHeaderLength));

            offset += ResourceRecordHeaderLength + resourceData.Length;
            _recordEndOffsets[recordIndex] = offset;
        }

        Records = Array.AsReadOnly(records);
    }
}
