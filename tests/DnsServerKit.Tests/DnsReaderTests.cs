using Xunit;

namespace DnsServerKit.Tests;

public sealed class DnsReaderTests
{
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

        Assert.True(result.IsFailure(out _, out _));
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
}
