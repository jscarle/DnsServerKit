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
    public void GetBytes_WhenNameUsesRootTrailingDotOrEscapedOctets_WritesCanonicalWireName()
    {
        (string Name, byte[] ExpectedBytes)[] testCases =
        [
            (string.Empty, [0x00]),
            (".", [0x00]),
            ("example.com.", [0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 0x03, (byte)'c', (byte)'o', (byte)'m', 0x00]),
            (@"a\.b.\000\255", [0x03, (byte)'a', (byte)'.', (byte)'b', 0x02, 0x00, 0xFF, 0x00]),
            ("\u00FF", [0x01, 0xFF, 0x00]),
        ];

        foreach (var testCase in testCases)
        {
            var question = new DnsQuestion
            {
                Name = testCase.Name,
                Type = RecordType.A,
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
            var response = new DnsResponse(query, false, true, ResponseCode.NoError);
            using var writer = new DnsWriter(response);

            var bytes = writer.GetBytes().ToArray();
            var encodedNameBytes = bytes.AsSpan(12, bytes.Length - 16).ToArray();

            Assert.Equal(testCase.ExpectedBytes, encodedNameBytes);
        }
    }

    [Fact]
    public void GetBytes_WhenNameIs255Octets_WritesName()
    {
        var name = string.Join(
            '.',
            new string('a', 63),
            new string('b', 63),
            new string('c', 63),
            new string('d', 61));
        var question = new DnsQuestion
        {
            Name = name,
            Type = RecordType.A,
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
        var response = new DnsResponse(query, false, true, ResponseCode.NoError);
        using var writer = new DnsWriter(response);

        var bytes = writer.GetBytes().ToArray();

        Assert.Equal(255, bytes.Length - 16);
    }

    [Fact]
    public void GetBytes_WhenNameContainsEmptyLabelOrExceedsLimits_ThrowsFormatException()
    {
        var nameExceeding255Octets = string.Join(
            '.',
            new string('a', 63),
            new string('b', 63),
            new string('c', 63),
            new string('d', 62));
        string[] invalidNames =
        [
            "example..com",
            new string('a', 64),
            nameExceeding255Octets,
            @"\256",
            "example\\",
        ];

        foreach (var invalidName in invalidNames)
        {
            var question = new DnsQuestion
            {
                Name = invalidName,
                Type = RecordType.A,
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
            var response = new DnsResponse(query, false, true, ResponseCode.NoError);
            using var writer = new DnsWriter(response);

            Assert.Throws<FormatException>(() => writer.GetBytes());
        }
    }

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
