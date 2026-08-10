using System.Buffers.Binary;
using DnsServerKit.Parameters;
using DnsServerKit.Queries;
using DnsServerKit.ResourceRecords;
using DnsServerKit.Responses;
using Xunit;

namespace DnsServerKit.Tests;

public sealed class DnsWriterTests
{
    [Fact]
    public void GetBytes_WhenAnswerIsPtrRecord_WritesTypeLengthAndTargetName()
    {
        const string ownerName = "4.3.2.1.in-addr.arpa";
        const string targetName = "localhost";
        var question = new DnsQuestion
        {
            Name = ownerName,
            Type = RecordType.Ptr,
            Class = DnsClass.Internet,
        };
        var query = new DnsQuery(
            0x1234,
            false,
            DnsOperation.Query,
            false,
            false,
            false,
            false,
            0,
            ResponseCode.NoError,
            1,
            0,
            0,
            0,
            [question]);
        var ptrRecord = new PtrRecord
        {
            Name = ownerName,
            TargetName = targetName,
            Ttl = 300,
        };
        var response = new DnsResponse(query, false, true, [ptrRecord]);
        using var writer = new DnsWriter(response);

        var bytes = writer.GetBytes().ToArray();

        var offset = 12;
        var questionName = NameHelper.DecodeDnsName(bytes, ref offset);
        offset += 4;

        var answerName = NameHelper.DecodeDnsName(bytes, ref offset);
        var answerType = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset, 2));
        offset += 2;
        var answerClass = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset, 2));
        offset += 2;
        var answerTtl = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset, 4));
        offset += 4;
        var resourceDataLength = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset, 2));
        offset += 2;

        var resourceDataStartOffset = offset;
        var ptrTargetName = NameHelper.DecodeDnsName(bytes, ref offset);

        Assert.Equal(RecordType.Ptr, ptrRecord.Type);
        Assert.Equal(ownerName, questionName);
        Assert.Equal(ownerName, answerName);
        Assert.Equal((ushort)RecordType.Ptr, answerType);
        Assert.Equal((ushort)DnsClass.Internet, answerClass);
        Assert.Equal(300U, answerTtl);
        Assert.Equal((ushort)(offset - resourceDataStartOffset), resourceDataLength);
        Assert.Equal(targetName, ptrTargetName);
        Assert.Equal(bytes.Length, offset);
    }
}
