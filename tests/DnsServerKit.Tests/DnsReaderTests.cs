using System.Buffers.Binary;
using DnsServerKit.Parameters;
using Xunit;

namespace DnsServerKit.Tests;

public sealed class DnsReaderTests
{
    [Fact]
    public void TryReadBytes_WhenHeaderIsTruncated_ReturnsFailureWithoutResponse()
    {
        for (var packetLength = 0; packetLength < 12; packetLength++)
        {
            var packet = new byte[packetLength];

            var result = DnsReader.TryReadBytes(packet);

            Assert.True(result.IsFailure(out var error, out _));
            var readError = Assert.IsType<DnsReadError>(error);
            Assert.Null(readError.Response);
        }
    }

    [Fact]
    public void TryReadBytes_WhenMessageIsResponse_ReturnsFailureWithoutResponse()
    {
        var packet = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(packet, 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 0x8000);

        var result = DnsReader.TryReadBytes(packet);

        Assert.True(result.IsFailure(out var error, out _));
        var readError = Assert.IsType<DnsReadError>(error);
        Assert.Null(readError.Response);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(15)]
    public void TryReadBytes_WhenOperationIsUnsupported_ReturnsNotImplementedResponse(int operation)
    {
        var packet = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(packet, 0x1234);
        var flags = (ushort)((operation << 11) | 0x0100);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), flags);

        var result = DnsReader.TryReadBytes(packet);

        Assert.True(result.IsFailure(out var error, out _));
        var readError = Assert.IsType<DnsReadError>(error);
        Assert.True(readError.Response.HasValue);
        var response = readError.Response.Value;
        Assert.Equal(0x1234, response.TransactionId);
        Assert.Equal(operation, (byte)response.Operation);
        Assert.True(response.RecursionDesired);
        Assert.Equal(ResponseCode.NotImplemented, response.ResponseCode);
    }

    [Fact]
    public void TryReadBytes_WhenQueryHeaderIsInvalid_ReturnsFormatErrorResponse()
    {
        (ushort Flags, ushort QuestionCount, ushort AnswerCount, ushort AuthorityCount, ushort AdditionalCount)[] invalidHeaders =
        [
            (0x0400, 1, 0, 0, 0),
            (0x0080, 1, 0, 0, 0),
            (0x0040, 1, 0, 0, 0),
            (0x0001, 1, 0, 0, 0),
            (0x0000, 0, 0, 0, 0),
            (0x0000, 2, 0, 0, 0),
            (0x0000, ushort.MaxValue, 0, 0, 0),
            (0x0000, 1, 1, 0, 0),
            (0x0000, 1, 0, 1, 0),
            (0x0000, 1, 0, 0, 1),
        ];

        foreach (var invalidHeader in invalidHeaders)
        {
            var packet = new byte[17];
            BinaryPrimitives.WriteUInt16BigEndian(packet, 0x1234);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), invalidHeader.Flags);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), invalidHeader.QuestionCount);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6), invalidHeader.AnswerCount);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(8), invalidHeader.AuthorityCount);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), invalidHeader.AdditionalCount);
            packet[12] = 0x00;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(13), (ushort)RecordType.A);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(15), (ushort)DnsClass.Internet);

            var result = DnsReader.TryReadBytes(packet);

            Assert.True(result.IsFailure(out var error, out _));
            var readError = Assert.IsType<DnsReadError>(error);
            Assert.True(readError.Response.HasValue);
            Assert.Equal(ResponseCode.FormatError, readError.Response.Value.ResponseCode);
        }
    }

    [Fact]
    public void TryReadBytes_WhenAuthenticDataAndCheckingDisabledFlagsAreSet_ReadsQuery()
    {
        byte[] dnsQuery =
        [
            0x12, 0x34,
            0x00, 0x30,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00,
            0x00, 0x01,
            0x00, 0x01,
        ];

        var result = DnsReader.TryReadBytes(dnsQuery);

        Assert.False(result.IsFailure(out _, out _));
    }

    [Fact]
    public void TryReadBytes_WhenQuestionCountIsMaximum_DoesNotAllocateFromQuestionCount()
    {
        var packet = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(packet, 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), ushort.MaxValue);
        _ = DnsReader.TryReadBytes(packet);

        var allocatedBytesBefore = GC.GetAllocatedBytesForCurrentThread();
        var result = DnsReader.TryReadBytes(packet);
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - allocatedBytesBefore;

        Assert.True(result.IsFailure(out var error, out _));
        Assert.IsType<DnsReadError>(error);
        Assert.InRange(allocatedBytes, 0, 16 * 1024);
    }

    [Fact]
    public void DecodeDnsName_WhenPointerReferencesPriorName_DecodesNameAndAdvancesPastPointer()
    {
        byte[] packet =
        [
            0x03, (byte)'w', (byte)'w', (byte)'w', 0x00,
            0xC0, 0x00,
        ];
        var offset = 5;

        var name = NameHelper.DecodeDnsName(packet, ref offset);

        Assert.Equal("www", name);
        Assert.Equal(7, offset);
    }

    [Fact]
    public void DecodeDnsName_WhenLabelsEndWithPointer_DecodesCompleteNameAndAdvancesPastPointer()
    {
        byte[] packet =
        [
            0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            0x03, (byte)'c', (byte)'o', (byte)'m', 0x00,
            0x03, (byte)'w', (byte)'w', (byte)'w', 0xC0, 0x00,
        ];
        var offset = 13;

        var name = NameHelper.DecodeDnsName(packet, ref offset);

        Assert.Equal("www.example.com", name);
        Assert.Equal(19, offset);
    }

    [Fact]
    public void TryReadBytes_WhenNamePointerReferencesItself_ReturnsFailure()
    {
        byte[] dnsQuery =
        [
            0x12, 0x34,
            0x00, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0xC0, 0x0C,
            0x00, 0x01,
            0x00, 0x01,
        ];

        var result = DnsReader.TryReadBytes(dnsQuery);

        Assert.True(result.IsFailure(out var error, out _));
        var readError = Assert.IsType<DnsReadError>(error);
        Assert.True(readError.Response.HasValue);
        Assert.Equal(ResponseCode.FormatError, readError.Response.Value.ResponseCode);
        Assert.IsType<FormatException>(readError.Exception);
    }

    [Fact]
    public void TryReadBytes_WhenReceivedDatagramEndsInsideName_DoesNotReadRemainingBufferBytes()
    {
        byte[] receiveBuffer =
        [
            0x12, 0x34,
            0x00, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x03, (byte)'w', (byte)'w', (byte)'w',
            0x00,
            0x00, 0x01,
            0x00, 0x01,
        ];
        const int receivedBytes = 16;
        var receivedDatagram = receiveBuffer.AsMemory(0, receivedBytes);

        var fullBufferResult = DnsReader.TryReadBytes(receiveBuffer);
        var receivedDatagramResult = DnsReader.TryReadBytes(receivedDatagram);

        Assert.False(fullBufferResult.IsFailure(out _, out _));
        Assert.True(receivedDatagramResult.IsFailure(out _, out _));
    }

    [Fact]
    public void TryReadBytes_WhenQuestionTypeIsUnregistered_PreservesWireValue()
    {
        const ushort unregisteredRecordType = 65400;
        byte[] dnsQuery =
        [
            0x12, 0x34,
            0x00, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00,
            unregisteredRecordType >> 8, unregisteredRecordType & 0xFF,
            0x00, 0x01,
        ];

        var result = DnsReader.TryReadBytes(dnsQuery);

        Assert.False(result.IsFailure(out _, out var parsedQuery));
        Assert.Equal(unregisteredRecordType, (ushort)parsedQuery.Questions[0].Type);
    }

    [Fact]
    public void TryReadBytes_WhenQuestionClassIsUnregistered_PreservesWireValue()
    {
        const ushort unregisteredDnsClass = 65400;
        byte[] dnsQuery =
        [
            0x12, 0x34,
            0x00, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00,
            0x00, 0x01,
            unregisteredDnsClass >> 8, unregisteredDnsClass & 0xFF,
        ];

        var result = DnsReader.TryReadBytes(dnsQuery);

        Assert.False(result.IsFailure(out _, out var parsedQuery));
        Assert.Equal(unregisteredDnsClass, (ushort)parsedQuery.Questions[0].Class);
    }

    [Fact]
    public void TryReadBytes_WhenMessageContainsTrailingData_ReturnsFormatErrorResponse()
    {
        byte[] dnsQuery =
        [
            0x12, 0x34,
            0x00, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00,
            0x00, 0x01,
            0x00, 0x01,
            0xFF,
        ];

        var result = DnsReader.TryReadBytes(dnsQuery);

        Assert.True(result.IsFailure(out var error, out _));
        var readError = Assert.IsType<DnsReadError>(error);
        Assert.True(readError.Response.HasValue);
        Assert.Equal(ResponseCode.FormatError, readError.Response.Value.ResponseCode);
    }
}
