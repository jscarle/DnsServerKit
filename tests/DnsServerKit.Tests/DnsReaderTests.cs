using System.Buffers.Binary;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Parameters;
using Xunit;

namespace DnsServerKit.Tests;

public sealed class DnsReaderTests
{
    [Fact]
    public void Read_WhenHeaderIsTruncated_DropsPacketWithoutResponse()
    {
        var context = new DnsQueryContext();
        for (var packetLength = 0; packetLength < 12; packetLength++)
        {
            var result = DnsReader.Read(new byte[packetLength], context);

            Assert.Equal(DnsReadOutcome.Drop, result.Outcome);
            Assert.Equal(DnsReadFailure.TruncatedHeader, result.Failure);
            Assert.Equal(default, result.ErrorResponse);
        }
    }

    [Fact]
    public void Read_WhenMessageIsResponse_DropsPacketWithoutResponse()
    {
        var packet = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(packet, 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 0x8000);
        var context = new DnsQueryContext();

        var result = DnsReader.Read(packet, context);

        Assert.Equal(DnsReadOutcome.Drop, result.Outcome);
        Assert.Equal(DnsReadFailure.InboundResponse, result.Failure);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(15)]
    public void Read_WhenOperationIsUnsupported_ReturnsNotImplemented(int operation)
    {
        var flags = (ushort)((operation << 11) | 0x0100);
        var packet = DnsTestPacket.CreateQuery(flags: flags);
        var context = new DnsQueryContext();

        var result = DnsReader.Read(packet, context);

        Assert.Equal(DnsReadOutcome.ErrorResponse, result.Outcome);
        Assert.Equal(DnsReadFailure.UnsupportedOperation, result.Failure);
        Assert.Equal((byte)operation, result.ErrorResponse.Operation);
        Assert.True(result.ErrorResponse.RecursionDesired);
        Assert.Equal(ResponseCode.NotImplemented, result.ErrorResponse.ResponseCode);
    }

    [Fact]
    public void Read_WhenQueryHeaderIsInvalid_ReturnsFormatError()
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
        var context = new DnsQueryContext();

        foreach (var invalidHeader in invalidHeaders)
        {
            var packet = DnsTestPacket.CreateQuery(
                flags: invalidHeader.Flags,
                questionCount: invalidHeader.QuestionCount,
                answerCount: invalidHeader.AnswerCount,
                authorityCount: invalidHeader.AuthorityCount,
                additionalCount: invalidHeader.AdditionalCount);

            var result = DnsReader.Read(packet, context);

            Assert.Equal(DnsReadOutcome.ErrorResponse, result.Outcome);
            Assert.Equal(DnsReadFailure.InvalidHeader, result.Failure);
            Assert.Equal(ResponseCode.FormatError, result.ErrorResponse.ResponseCode);
        }
    }

    [Fact]
    public void Read_WhenAuthenticDataAndCheckingDisabledAreSet_ReadsQuery()
    {
        var packet = DnsTestPacket.CreateQuery(flags: 0x0030);
        var context = new DnsQueryContext();

        var result = DnsReader.Read(packet, context);

        Assert.Equal(DnsReadOutcome.Query, result.Outcome);
        Assert.True(context.AuthenticData);
        Assert.True(context.CheckingDisabled);
    }

    [Fact]
    public void Read_WhenQuestionNameIsMalformed_ReturnsFormatError()
    {
        byte[][] packets =
        [
            [0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1],
            [0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x40, 0, 1, 0, 1],
            [0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, (byte)'w'],
        ];
        var context = new DnsQueryContext();

        foreach (var packet in packets)
        {
            var result = DnsReader.Read(packet, context);

            Assert.Equal(DnsReadOutcome.ErrorResponse, result.Outcome);
            Assert.Equal(DnsReadFailure.InvalidName, result.Failure);
            Assert.Equal(ResponseCode.FormatError, result.ErrorResponse.ResponseCode);
            Assert.Null(result.Exception);
        }
    }

    [Fact]
    public void Read_WhenQuestionIsTruncated_ReturnsFormatError()
    {
        byte[] packet = [0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        var context = new DnsQueryContext();

        var result = DnsReader.Read(packet, context);

        Assert.Equal(DnsReadFailure.TruncatedQuestion, result.Failure);
        Assert.Equal(ResponseCode.FormatError, result.ErrorResponse.ResponseCode);
    }

    [Fact]
    public void Read_WhenMessageContainsTrailingData_ReturnsFormatError()
    {
        var validPacket = DnsTestPacket.CreateQuery();
        var packet = new byte[validPacket.Length + 1];
        validPacket.CopyTo(packet, 0);
        packet[^1] = 0xFF;
        var context = new DnsQueryContext();

        var result = DnsReader.Read(packet, context);

        Assert.Equal(DnsReadFailure.TrailingData, result.Failure);
        Assert.Equal(ResponseCode.FormatError, result.ErrorResponse.ResponseCode);
    }

    [Fact]
    public void Read_WhenQuestionTypeAndClassAreUnregistered_PreservesWireValues()
    {
        const ushort type = 65400;
        const ushort @class = 65399;
        var packet = DnsTestPacket.CreateQuery(type: type, @class: @class);
        var context = new DnsQueryContext();

        var result = DnsReader.Read(packet, context);

        Assert.Equal(DnsReadOutcome.Query, result.Outcome);
        Assert.Equal(type, context.Question.Type);
        Assert.Equal(@class, context.Question.Class);
    }

    [Fact]
    public void Materialize_WhenContextAndBufferAreReused_RetainsOriginalQuery()
    {
        var buffer = new byte[512];
        var firstPacket = DnsTestPacket.CreateQuery("first.example", transactionId: 0x1111);
        firstPacket.CopyTo(buffer, 0);
        var context = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, firstPacket.Length), context);
        var materialized = context.Materialize();

        var secondPacket = DnsTestPacket.CreateQuery("second.example", transactionId: 0x2222);
        secondPacket.CopyTo(buffer, 0);
        _ = DnsReader.Read(buffer.AsMemory(0, secondPacket.Length), context);

        Assert.Equal((ushort)0x1111, materialized.TransactionId);
        Assert.Equal((byte)DnsOperation.Query, materialized.Operation);
        Assert.Equal("first.example", materialized.Question.Name.Value);
        Assert.Equal((ushort)RecordType.A, materialized.Question.Type);
        Assert.Equal((ushort)DnsClass.Internet, materialized.Question.Class);
        Assert.Equal((ushort)0x2222, context.TransactionId);
        Assert.Equal("second.example", context.Question.MaterializeName().Value);
    }

    [Fact]
    public void Read_WhenWarmed_DoesNotAllocateForSuccessOrExpectedFailure()
    {
        var validPacket = DnsTestPacket.CreateQuery();
        var invalidPacket = DnsTestPacket.CreateQuery(questionCount: ushort.MaxValue);
        var context = new DnsQueryContext();
        _ = DnsReader.Read(validPacket, context);
        _ = DnsReader.Read(invalidPacket, context);

        var beforeValid = GC.GetAllocatedBytesForCurrentThread();
        var validResult = DnsReader.Read(validPacket, context);
        var validAllocations = GC.GetAllocatedBytesForCurrentThread() - beforeValid;

        var beforeInvalid = GC.GetAllocatedBytesForCurrentThread();
        var invalidResult = DnsReader.Read(invalidPacket, context);
        var invalidAllocations = GC.GetAllocatedBytesForCurrentThread() - beforeInvalid;

        Assert.Equal(DnsReadOutcome.Query, validResult.Outcome);
        Assert.Equal(DnsReadOutcome.ErrorResponse, invalidResult.Outcome);
        Assert.Equal(0, validAllocations);
        Assert.Equal(0, invalidAllocations);
    }
}
