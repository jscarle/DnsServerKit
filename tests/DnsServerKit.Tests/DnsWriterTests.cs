using System.Buffers.Binary;
using System.Net;
using DnsServerKit.Data;
using DnsServerKit.Parameters;
using DnsServerKit.Queries;
using DnsServerKit.ResourceRecords;
using DnsServerKit.Responses;
using Xunit;

namespace DnsServerKit.Tests;

public sealed class DnsWriterTests
{
    [Fact]
    public void Write_WhenAnswerIsARecord_WritesExactManagedRecordSetResponse()
    {
        var queryBytes = DnsTestPacket.CreateQuery(transactionId: 0x1234, flags: 0x0100);
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        Assert.Equal(DnsReadOutcome.Query, DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query).Outcome);

        var builder = new DnsDataSetBuilder();
        builder.Add(new ARecord(new DnsName("example.com"), IPAddress.Parse("192.0.2.1"), 300));
        var dataSet = builder.Build();
        Assert.True(dataSet.TryResolve(query.Question, out var answerSet));
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);

        var length = DnsWriter.Write(buffer, response);

        Assert.Equal(queryBytes.Length + 16, length);
        Assert.Equal((ushort)0x1234, BinaryPrimitives.ReadUInt16BigEndian(buffer));
        Assert.Equal((ushort)0x8180, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2)));
        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(4)));
        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(6)));
        Assert.Equal((ushort)0xC00C, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(queryBytes.Length)));
        Assert.Equal((ushort)RecordType.A, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(queryBytes.Length + 2)));
        Assert.Equal(300U, BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(queryBytes.Length + 6)));
        Assert.Equal((ushort)4, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(queryBytes.Length + 10)));
        Assert.Equal(new byte[] { 192, 0, 2, 1 }, buffer.AsSpan(queryBytes.Length + 12, 4).ToArray());
    }

    [Fact]
    public void Write_WhenAnswerIsPtrRecord_WritesPreencodedTargetName()
    {
        var ownerName = new DnsName("1.2.0.192.in-addr.arpa");
        var targetName = new DnsName("host.example.com");
        var queryBytes = DnsTestPacket.CreateQuery(ownerName.Value, (ushort)RecordType.Ptr);
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var builder = new DnsDataSetBuilder();
        var ptrRecord = new PtrRecord(ownerName, targetName, 60);
        builder.Add(ptrRecord);
        var dataSet = builder.Build();
        Assert.True(dataSet.TryResolve(query.Question, out var answerSet));
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);

        var length = DnsWriter.Write(buffer, response);
        var offset = queryBytes.Length + 12;
        var decodedTarget = DnsTestPacket.ReadName(buffer.AsSpan(0, length), ref offset);

        Assert.Equal("host.example.com", decodedTarget);
        Assert.Equal(length, offset);
        Assert.Same(targetName, ptrRecord.TargetName);
    }

    [Fact]
    public void Write_WhenResponseHasNoAnswer_WritesQuestionAndResponseCode()
    {
        var queryBytes = DnsTestPacket.CreateQuery();
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var response = new DnsResponseContext();
        response.Set(query, null, ResponseCode.NotZone, false, true);

        var length = DnsWriter.Write(buffer, response);

        Assert.Equal(queryBytes.Length, length);
        Assert.Equal((ushort)0x808A, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2)));
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(6)));
    }

    [Fact]
    public void Write_WhenRecordSetExceedsUdpLimit_TruncatesAtRecordBoundary()
    {
        var name = new DnsName("example.com");
        var builder = new DnsDataSetBuilder();
        for (var recordIndex = 0; recordIndex < 100; recordIndex++)
            builder.Add(new ARecord(name, IPAddress.Parse("192.0.2.1")));

        var dataSet = builder.Build();
        var queryBytes = DnsTestPacket.CreateQuery();
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        Assert.True(dataSet.TryResolve(query.Question, out var answerSet));
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);

        var length = DnsWriter.Write(buffer, response);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2));
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(6));

        Assert.True(length <= 512);
        Assert.NotEqual((ushort)0, (ushort)(flags & 0x0200));
        Assert.InRange(answerCount, (ushort)1, (ushort)99);
        Assert.Equal(queryBytes.Length + (answerCount * 16), length);
    }

    [Theory]
    [InlineData(ResponseCode.FormatError)]
    [InlineData(ResponseCode.NotImplemented)]
    [InlineData(ResponseCode.ServerFailure)]
    public void WriteErrorResponse_WhenResponseCodeIsSupported_WritesExactHeader(ResponseCode responseCode)
    {
        var destination = new byte[12];
        var errorResponse = new DnsErrorResponse(0x1234, 15, true, responseCode);

        var writtenBytes = DnsWriter.WriteErrorResponse(destination, errorResponse, true);

        var flags = BinaryPrimitives.ReadUInt16BigEndian(destination.AsSpan(2));
        var expectedFlags = (ushort)(0x8000 | 0x7800 | 0x0100 | 0x0080 | (byte)responseCode);
        Assert.Equal(12, writtenBytes);
        Assert.Equal((ushort)0x1234, BinaryPrimitives.ReadUInt16BigEndian(destination));
        Assert.Equal(expectedFlags, flags);
        Assert.Equal(0U, BinaryPrimitives.ReadUInt32BigEndian(destination.AsSpan(4)));
        Assert.Equal(0U, BinaryPrimitives.ReadUInt32BigEndian(destination.AsSpan(8)));
    }

    [Fact]
    public void WriteErrorResponse_WhenWarmed_DoesNotAllocate()
    {
        var destination = new byte[12];
        var errorResponse = new DnsErrorResponse(0x1234, 0, false, ResponseCode.FormatError);
        _ = DnsWriter.WriteErrorResponse(destination, errorResponse, true);

        var allocatedBytesBefore = GC.GetAllocatedBytesForCurrentThread();
        var writtenBytes = DnsWriter.WriteErrorResponse(destination, errorResponse, true);
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - allocatedBytesBefore;

        Assert.Equal(12, writtenBytes);
        Assert.Equal(0, allocatedBytes);
    }

    [Fact]
    public void Write_WhenWarmed_DoesNotAllocateForManagedResponseVariants()
    {
        var builder = new DnsDataSetBuilder();
        builder.Add(new ARecord(new DnsName("example.com"), IPAddress.Parse("192.0.2.1")));
        builder.Add(new PtrRecord(new DnsName("1.2.0.192.in-addr.arpa"), new DnsName("host.example.com")));
        var dataSet = builder.Build();

        var aQueryBytes = DnsTestPacket.CreateQuery();
        var aBuffer = new byte[512];
        aQueryBytes.CopyTo(aBuffer, 0);
        var aQuery = new DnsQueryContext();
        _ = DnsReader.Read(aBuffer.AsMemory(0, aQueryBytes.Length), aQuery);
        _ = dataSet.TryResolve(aQuery.Question, out var aAnswerSet);
        var aResponse = new DnsResponseContext();
        aResponse.Set(aQuery, aAnswerSet, ResponseCode.NoError, false, true);
        _ = DnsWriter.Write(aBuffer, aResponse);

        var ptrQueryBytes = DnsTestPacket.CreateQuery("1.2.0.192.in-addr.arpa", (ushort)RecordType.Ptr);
        var ptrBuffer = new byte[512];
        ptrQueryBytes.CopyTo(ptrBuffer, 0);
        var ptrQuery = new DnsQueryContext();
        _ = DnsReader.Read(ptrBuffer.AsMemory(0, ptrQueryBytes.Length), ptrQuery);
        _ = dataSet.TryResolve(ptrQuery.Question, out var ptrAnswerSet);
        var ptrResponse = new DnsResponseContext();
        ptrResponse.Set(ptrQuery, ptrAnswerSet, ResponseCode.NoError, false, true);
        _ = DnsWriter.Write(ptrBuffer, ptrResponse);

        var missQueryBytes = DnsTestPacket.CreateQuery("missing.example");
        var missBuffer = new byte[512];
        missQueryBytes.CopyTo(missBuffer, 0);
        var missQuery = new DnsQueryContext();
        _ = DnsReader.Read(missBuffer.AsMemory(0, missQueryBytes.Length), missQuery);
        var missResponse = new DnsResponseContext();
        missResponse.Set(missQuery, null, ResponseCode.NotZone, false, true);
        _ = DnsWriter.Write(missBuffer, missResponse);

        var errorBuffer = new byte[12];
        var formatError = new DnsErrorResponse(0x1234, 0, false, ResponseCode.FormatError);
        var notImplemented = new DnsErrorResponse(0x5678, 15, true, ResponseCode.NotImplemented);
        _ = DnsWriter.WriteErrorResponse(errorBuffer, formatError, true);
        _ = DnsWriter.WriteErrorResponse(errorBuffer, notImplemented, true);

        var beforeResponseSet = GC.GetAllocatedBytesForCurrentThread();
        aResponse.Set(aQuery, aAnswerSet, ResponseCode.NoError, false, true);
        var responseSetAllocations = GC.GetAllocatedBytesForCurrentThread() - beforeResponseSet;

        var beforeA = GC.GetAllocatedBytesForCurrentThread();
        var aLength = DnsWriter.Write(aBuffer, aResponse);
        var aAllocations = GC.GetAllocatedBytesForCurrentThread() - beforeA;

        var beforePtr = GC.GetAllocatedBytesForCurrentThread();
        var ptrLength = DnsWriter.Write(ptrBuffer, ptrResponse);
        var ptrAllocations = GC.GetAllocatedBytesForCurrentThread() - beforePtr;

        var beforeMiss = GC.GetAllocatedBytesForCurrentThread();
        var missLength = DnsWriter.Write(missBuffer, missResponse);
        var missAllocations = GC.GetAllocatedBytesForCurrentThread() - beforeMiss;

        var beforeFormatError = GC.GetAllocatedBytesForCurrentThread();
        var formatErrorLength = DnsWriter.WriteErrorResponse(errorBuffer, formatError, true);
        var formatErrorAllocations = GC.GetAllocatedBytesForCurrentThread() - beforeFormatError;

        var beforeNotImplemented = GC.GetAllocatedBytesForCurrentThread();
        var notImplementedLength = DnsWriter.WriteErrorResponse(errorBuffer, notImplemented, true);
        var notImplementedAllocations = GC.GetAllocatedBytesForCurrentThread() - beforeNotImplemented;

        Assert.True(aLength > aQueryBytes.Length);
        Assert.True(ptrLength > ptrQueryBytes.Length);
        Assert.Equal(missQueryBytes.Length, missLength);
        Assert.Equal(12, formatErrorLength);
        Assert.Equal(12, notImplementedLength);
        Assert.Equal(0, responseSetAllocations);
        Assert.Equal(0, aAllocations);
        Assert.Equal(0, ptrAllocations);
        Assert.Equal(0, missAllocations);
        Assert.Equal(0, formatErrorAllocations);
        Assert.Equal(0, notImplementedAllocations);
    }

    [Fact]
    public void ParseLookupAndWrite_WhenWarmed_DoesNotAllocate()
    {
        var queryBytes = DnsTestPacket.CreateQuery();
        var buffer = new byte[512];
        var query = new DnsQueryContext();
        var response = new DnsResponseContext();
        var builder = new DnsDataSetBuilder();
        builder.Add(new ARecord(new DnsName("example.com"), IPAddress.Parse("192.0.2.1")));
        var dataSet = builder.Build();

        queryBytes.AsSpan().CopyTo(buffer);
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        _ = dataSet.TryResolve(query.Question, out var warmAnswerSet);
        response.Set(query, warmAnswerSet, ResponseCode.NoError, false, true);
        _ = DnsWriter.Write(buffer, response);

        queryBytes.AsSpan().CopyTo(buffer);
        var allocatedBytesBefore = GC.GetAllocatedBytesForCurrentThread();
        var readResult = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var found = dataSet.TryResolve(query.Question, out var answerSet);
        response.Set(query, answerSet, ResponseCode.NoError, false, true);
        var responseLength = DnsWriter.Write(buffer, response);
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - allocatedBytesBefore;

        Assert.Equal(DnsReadOutcome.Query, readResult.Outcome);
        Assert.True(found);
        Assert.True(responseLength > queryBytes.Length);
        Assert.Equal(0, allocatedBytes);
    }

    [Fact]
    public void Materialize_WhenResponseContextIsReused_RetainsManagedQueryAndRecords()
    {
        var queryBytes = DnsTestPacket.CreateQuery(transactionId: 0x1234);
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var builder = new DnsDataSetBuilder();
        builder.Add(new ARecord(new DnsName("example.com"), IPAddress.Parse("192.0.2.1")));
        var dataSet = builder.Build();
        _ = dataSet.TryResolve(query.Question, out var answerSet);
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);
        var materialized = response.Materialize();

        var secondQuery = DnsTestPacket.CreateQuery("other.example", transactionId: 0x5678);
        secondQuery.AsSpan().CopyTo(buffer);
        _ = DnsReader.Read(buffer.AsMemory(0, secondQuery.Length), query);
        response.Set(query, null, ResponseCode.NotZone, false, true);

        Assert.Equal((ushort)0x1234, materialized.Query.TransactionId);
        Assert.Equal("example.com", materialized.Query.Question.Name.Value);
        Assert.Single(materialized.Answers);
        Assert.False(materialized.AuthoritativeAnswer);
        Assert.True(materialized.RecursionAvailable);
        Assert.Equal(ResponseCode.NoError, materialized.ResponseCode);
    }
}
