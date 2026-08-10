using System.Buffers.Binary;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Internal.Responses;
using DnsServerKit.Parameters;
using DnsServerKit.Records;
using DnsServerKit.Zones;
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

        var zoneBuilder = CreateRootZoneBuilder();
        zoneBuilder.AddRecordSet(CreateARecordSet(300, "example.com", "192.0.2.1"));
        var store = CreateStore(zoneBuilder);
        Assert.True(store.TryResolve(query.Question, out var answerSet));
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
        Assert.Equal((ushort)DnsClass.Internet, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(queryBytes.Length + 4)));
        Assert.Equal(300U, BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(queryBytes.Length + 6)));
        Assert.Equal((ushort)4, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(queryBytes.Length + 10)));
        Assert.Equal(new byte[] { 192, 0, 2, 1 }, buffer.AsSpan(queryBytes.Length + 12, 4).ToArray());
    }

    [Fact]
    public void Write_WhenAnswerIsPtrRecord_WritesPreencodedTargetName()
    {
        var queryBytes = DnsTestPacket.CreateQuery("1.2.0.192.in-addr.arpa", (ushort)RecordType.Ptr);
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var zoneBuilder = CreateRootZoneBuilder();
        zoneBuilder.AddRecordSet(CreatePtrRecordSet(60, "1.2.0.192.in-addr.arpa", "host.example.com"));
        var store = CreateStore(zoneBuilder);
        Assert.True(store.TryResolve(query.Question, out var answerSet));
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);

        var length = DnsWriter.Write(buffer, response);
        var offset = queryBytes.Length + 12;
        var decodedTarget = DnsTestPacket.ReadName(buffer.AsSpan(0, length), ref offset);

        Assert.Equal("host.example.com", decodedTarget);
        Assert.Equal(length, offset);
    }

    [Fact]
    public void Write_WhenAnswerIsSoaRecord_WritesDomainNamesAndNumericFieldsInWireOrder()
    {
        var queryBytes = DnsTestPacket.CreateQuery("example.com", (ushort)RecordType.Soa);
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var zoneBuilder = new DnsZoneBuilder("example.com");
        zoneBuilder.AddRecordSet(CreateSoaRecordSet(
            900,
            "ns1.example.com",
            "first.last@example.com",
            2026081001));
        zoneBuilder.AddRecordSet(CreateNsRecordSet(900, "ns1.example.com"));
        var store = CreateStore(zoneBuilder);
        _ = store.TryResolve(query.Question, out var answerSet);
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);

        var length = DnsWriter.Write(buffer, response);
        var answerOffset = queryBytes.Length;
        var resourceDataOffset = answerOffset + 12;
        var primaryNameServer = DnsTestPacket.ReadName(buffer.AsSpan(0, length), ref resourceDataOffset);
        var responsibleMailboxOffset = resourceDataOffset;
        var responsibleMailbox = DnsTestPacket.ReadName(buffer.AsSpan(0, length), ref resourceDataOffset);

        Assert.Equal((ushort)RecordType.Soa, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(answerOffset + 2)));
        Assert.Equal(900U, BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(answerOffset + 6)));
        Assert.Equal("ns1.example.com", primaryNameServer);
        Assert.Equal(10, buffer[responsibleMailboxOffset]);
        Assert.Equal("first.last.example.com", responsibleMailbox);
        Assert.Equal(2026081001U, BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(resourceDataOffset)));
        Assert.Equal(3600U, BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(resourceDataOffset + 4)));
        Assert.Equal(600U, BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(resourceDataOffset + 8)));
        Assert.Equal(1_209_600U, BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(resourceDataOffset + 12)));
        Assert.Equal(300U, BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(resourceDataOffset + 16)));
        Assert.Equal(length, resourceDataOffset + 20);
    }

    [Fact]
    public void Write_WhenAnswerIsNsRrSet_WritesEveryNameServerWithSharedTtl()
    {
        var queryBytes = DnsTestPacket.CreateQuery("example.com", (ushort)RecordType.Ns);
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var zoneBuilder = new DnsZoneBuilder("example.com");
        zoneBuilder.AddRecordSet(CreateSoaRecordSet(300, "ns1.example.com", "hostmaster@example.com", 1));
        zoneBuilder.AddRecordSet(CreateNsRecordSet(600, "ns1.example.com", "ns2.example.com"));
        var store = CreateStore(zoneBuilder);
        _ = store.TryResolve(query.Question, out var answerSet);
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);

        var length = DnsWriter.Write(buffer, response);
        var firstAnswerOffset = queryBytes.Length;
        var firstTargetOffset = firstAnswerOffset + 12;
        var firstNameServer = DnsTestPacket.ReadName(buffer.AsSpan(0, length), ref firstTargetOffset);
        var secondAnswerOffset = firstTargetOffset;
        var secondTargetOffset = secondAnswerOffset + 12;
        var secondNameServer = DnsTestPacket.ReadName(buffer.AsSpan(0, length), ref secondTargetOffset);

        Assert.Equal((ushort)2, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(6)));
        Assert.Equal(600U, BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(firstAnswerOffset + 6)));
        Assert.Equal(600U, BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(secondAnswerOffset + 6)));
        Assert.Equal("ns1.example.com", firstNameServer);
        Assert.Equal("ns2.example.com", secondNameServer);
        Assert.Equal(length, secondTargetOffset);
    }

    [Fact]
    public void Write_WhenAnswerIsAaaaRecord_WritesSixteenAddressOctets()
    {
        var queryBytes = DnsTestPacket.CreateQuery("ipv6.example.com", (ushort)RecordType.Aaaa);
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var zoneBuilder = CreateRootZoneBuilder();
        zoneBuilder.AddAaaaRecord(120, "ipv6.example.com", "2001:db8::1");
        var store = CreateStore(zoneBuilder);
        _ = store.TryResolve(query.Question, out var answerSet);
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);

        var length = DnsWriter.Write(buffer, response);
        var answerOffset = queryBytes.Length;

        Assert.Equal(queryBytes.Length + 28, length);
        Assert.Equal((ushort)RecordType.Aaaa, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(answerOffset + 2)));
        Assert.Equal((ushort)16, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(answerOffset + 10)));
        Assert.Equal(
            new byte[] { 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            buffer.AsSpan(answerOffset + 12, 16).ToArray());
    }

    [Fact]
    public void Write_WhenRequestedTypeIsAtCnameOwner_WritesCanonicalNameAnswer()
    {
        var queryBytes = DnsTestPacket.CreateQuery("alias.example.com");
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var zoneBuilder = CreateRootZoneBuilder();
        zoneBuilder.AddCnameRecord(180, "alias.example.com", "target.example.com");
        var store = CreateStore(zoneBuilder);
        Assert.True(store.TryResolve(query.Question, out var answerSet));
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);

        var length = DnsWriter.Write(buffer, response);
        var answerOffset = queryBytes.Length;
        var targetOffset = answerOffset + 12;
        var target = DnsTestPacket.ReadName(buffer.AsSpan(0, length), ref targetOffset);

        Assert.IsType<CnameRecordSet>(answerSet);
        Assert.Equal((ushort)RecordType.CName, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(answerOffset + 2)));
        Assert.Equal("target.example.com", target);
        Assert.Equal(length, targetOffset);
    }

    [Fact]
    public void Write_WhenAnswerIsMxRecordSet_WritesPreferenceAndExchangeForEveryRecord()
    {
        var queryBytes = DnsTestPacket.CreateQuery("example.com", (ushort)RecordType.Mx);
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var zoneBuilder = CreateRootZoneBuilder();
        zoneBuilder.AddMxRecord(
            240,
            "example.com",
            new MxRecord { Preference = 10, Exchange = "mail1.example.com" },
            new MxRecord { Preference = 20, Exchange = "mail2.example.com" });
        var store = CreateStore(zoneBuilder);
        _ = store.TryResolve(query.Question, out var answerSet);
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);

        var length = DnsWriter.Write(buffer, response);
        var firstAnswerOffset = queryBytes.Length;
        var firstExchangeOffset = firstAnswerOffset + 14;
        var firstExchange = DnsTestPacket.ReadName(buffer.AsSpan(0, length), ref firstExchangeOffset);
        var secondAnswerOffset = firstExchangeOffset;
        var secondExchangeOffset = secondAnswerOffset + 14;
        var secondExchange = DnsTestPacket.ReadName(buffer.AsSpan(0, length), ref secondExchangeOffset);

        Assert.Equal((ushort)2, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(6)));
        Assert.Equal((ushort)10, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(firstAnswerOffset + 12)));
        Assert.Equal((ushort)20, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(secondAnswerOffset + 12)));
        Assert.Equal("mail1.example.com", firstExchange);
        Assert.Equal("mail2.example.com", secondExchange);
        Assert.Equal(length, secondExchangeOffset);
    }

    [Fact]
    public void Write_WhenTxtTextExceedsCharacterStringLimit_SplitsUtf8TextWithinOneRecord()
    {
        var queryBytes = DnsTestPacket.CreateQuery("txt.example.com", (ushort)RecordType.Txt);
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var zoneBuilder = CreateRootZoneBuilder();
        zoneBuilder.AddTxtRecord(300, "txt.example.com", new string('a', 256), "é");
        var store = CreateStore(zoneBuilder);
        _ = store.TryResolve(query.Question, out var answerSet);
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);

        var length = DnsWriter.Write(buffer, response);
        var firstAnswerOffset = queryBytes.Length;
        var firstResourceDataOffset = firstAnswerOffset + 12;
        var secondAnswerOffset = firstResourceDataOffset + 258;
        var secondResourceDataOffset = secondAnswerOffset + 12;

        Assert.Equal((ushort)2, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(6)));
        Assert.Equal((ushort)258, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(firstAnswerOffset + 10)));
        Assert.Equal((byte)255, buffer[firstResourceDataOffset]);
        Assert.All(buffer.AsSpan(firstResourceDataOffset + 1, 255).ToArray(), value => Assert.Equal((byte)'a', value));
        Assert.Equal((byte)1, buffer[firstResourceDataOffset + 256]);
        Assert.Equal((byte)'a', buffer[firstResourceDataOffset + 257]);
        Assert.Equal((ushort)3, BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(secondAnswerOffset + 10)));
        Assert.Equal(new byte[] { 2, 0xC3, 0xA9 }, buffer.AsSpan(secondResourceDataOffset, 3).ToArray());
        Assert.Equal(secondResourceDataOffset + 3, length);
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
        var ipv4Addresses = new string[100];
        for (var recordIndex = 0; recordIndex < 100; recordIndex++)
            ipv4Addresses[recordIndex] = $"192.0.2.{recordIndex}";

        var zoneBuilder = CreateRootZoneBuilder();
        zoneBuilder.AddRecordSet(CreateARecordSet(0, "example.com", ipv4Addresses));
        var store = CreateStore(zoneBuilder);
        var queryBytes = DnsTestPacket.CreateQuery();
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        Assert.True(store.TryResolve(query.Question, out var answerSet));
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
    [InlineData((ushort)ResponseCode.FormatError)]
    [InlineData((ushort)ResponseCode.NotImplemented)]
    [InlineData((ushort)ResponseCode.ServerFailure)]
    public void WriteErrorResponse_WhenResponseCodeIsSupported_WritesExactHeader(ushort responseCodeValue)
    {
        var responseCode = (ResponseCode)responseCodeValue;
        var destination = new byte[12];
        var errorResponse = new DnsErrorResponse(0x1234, 15, true, responseCode);

        var writtenBytes = DnsWriter.WriteErrorResponse(destination, errorResponse, true);

        var flags = BinaryPrimitives.ReadUInt16BigEndian(destination.AsSpan(2));
        var expectedFlags = (ushort)(0x8000 | 0x7800 | 0x0100 | 0x0080 | (ushort)responseCode);
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
    public void Write_WhenWarmed_DoesNotAllocateForNameServerAndStartOfAuthorityAnswers()
    {
        var store = CreateStore(CreateRootZoneBuilder());

        var nameServerQueryBytes = DnsTestPacket.CreateQuery(".", (ushort)RecordType.Ns);
        var nameServerBuffer = new byte[512];
        nameServerQueryBytes.CopyTo(nameServerBuffer, 0);
        var nameServerQuery = new DnsQueryContext();
        _ = DnsReader.Read(nameServerBuffer.AsMemory(0, nameServerQueryBytes.Length), nameServerQuery);
        _ = store.TryResolve(nameServerQuery.Question, out var nameServerAnswerSet);
        var nameServerResponse = new DnsResponseContext();
        nameServerResponse.Set(nameServerQuery, nameServerAnswerSet, ResponseCode.NoError, false, true);
        _ = DnsWriter.Write(nameServerBuffer, nameServerResponse);

        var startOfAuthorityQueryBytes = DnsTestPacket.CreateQuery(".", (ushort)RecordType.Soa);
        var startOfAuthorityBuffer = new byte[512];
        startOfAuthorityQueryBytes.CopyTo(startOfAuthorityBuffer, 0);
        var startOfAuthorityQuery = new DnsQueryContext();
        _ = DnsReader.Read(
            startOfAuthorityBuffer.AsMemory(0, startOfAuthorityQueryBytes.Length),
            startOfAuthorityQuery);
        _ = store.TryResolve(startOfAuthorityQuery.Question, out var startOfAuthorityAnswerSet);
        var startOfAuthorityResponse = new DnsResponseContext();
        startOfAuthorityResponse.Set(
            startOfAuthorityQuery,
            startOfAuthorityAnswerSet,
            ResponseCode.NoError,
            false,
            true);
        _ = DnsWriter.Write(startOfAuthorityBuffer, startOfAuthorityResponse);

        var beforeNameServer = GC.GetAllocatedBytesForCurrentThread();
        var nameServerLength = DnsWriter.Write(nameServerBuffer, nameServerResponse);
        var nameServerAllocations = GC.GetAllocatedBytesForCurrentThread() - beforeNameServer;

        var beforeStartOfAuthority = GC.GetAllocatedBytesForCurrentThread();
        var startOfAuthorityLength = DnsWriter.Write(startOfAuthorityBuffer, startOfAuthorityResponse);
        var startOfAuthorityAllocations = GC.GetAllocatedBytesForCurrentThread() - beforeStartOfAuthority;

        Assert.True(nameServerLength > nameServerQueryBytes.Length);
        Assert.True(startOfAuthorityLength > startOfAuthorityQueryBytes.Length);
        Assert.Equal(0, nameServerAllocations);
        Assert.Equal(0, startOfAuthorityAllocations);
    }

    [Fact]
    public void Write_WhenWarmed_DoesNotAllocateForManagedResponseVariants()
    {
        var zoneBuilder = CreateRootZoneBuilder();
        zoneBuilder.AddRecordSet(CreateARecordSet(0, "example.com", "192.0.2.1"));
        zoneBuilder.AddRecordSet(CreatePtrRecordSet(0, "1.2.0.192.in-addr.arpa", "host.example.com"));
        var store = CreateStore(zoneBuilder);

        var aQueryBytes = DnsTestPacket.CreateQuery();
        var aBuffer = new byte[512];
        aQueryBytes.CopyTo(aBuffer, 0);
        var aQuery = new DnsQueryContext();
        _ = DnsReader.Read(aBuffer.AsMemory(0, aQueryBytes.Length), aQuery);
        _ = store.TryResolve(aQuery.Question, out var aAnswerSet);
        var aResponse = new DnsResponseContext();
        aResponse.Set(aQuery, aAnswerSet, ResponseCode.NoError, false, true);
        _ = DnsWriter.Write(aBuffer, aResponse);

        var ptrQueryBytes = DnsTestPacket.CreateQuery("1.2.0.192.in-addr.arpa", (ushort)RecordType.Ptr);
        var ptrBuffer = new byte[512];
        ptrQueryBytes.CopyTo(ptrBuffer, 0);
        var ptrQuery = new DnsQueryContext();
        _ = DnsReader.Read(ptrBuffer.AsMemory(0, ptrQueryBytes.Length), ptrQuery);
        _ = store.TryResolve(ptrQuery.Question, out var ptrAnswerSet);
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
        var zoneBuilder = CreateRootZoneBuilder();
        zoneBuilder.AddRecordSet(CreateARecordSet(0, "example.com", "192.0.2.1"));
        var store = CreateStore(zoneBuilder);

        queryBytes.AsSpan().CopyTo(buffer);
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        _ = store.TryResolve(query.Question, out var warmAnswerSet);
        response.Set(query, warmAnswerSet, ResponseCode.NoError, false, true);
        _ = DnsWriter.Write(buffer, response);

        queryBytes.AsSpan().CopyTo(buffer);
        var allocatedBytesBefore = GC.GetAllocatedBytesForCurrentThread();
        var readResult = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var found = store.TryResolve(query.Question, out var answerSet);
        response.Set(query, answerSet, ResponseCode.NoError, false, true);
        var responseLength = DnsWriter.Write(buffer, response);
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - allocatedBytesBefore;

        Assert.Equal(DnsReadOutcome.Query, readResult.Outcome);
        Assert.True(found);
        Assert.True(responseLength > queryBytes.Length);
        Assert.Equal(0, allocatedBytes);
    }

    [Fact]
    public void ParseLookupAndWrite_WhenNewRecordTypesAreWarmed_DoesNotAllocate()
    {
        var zoneBuilder = CreateRootZoneBuilder();
        zoneBuilder.AddAaaaRecord(300, "ipv6.example", "2001:db8::1");
        zoneBuilder.AddCnameRecord(300, "alias.example", "target.example");
        zoneBuilder.AddMxRecord(300, "mail.example", new MxRecord { Preference = 10, Exchange = "mx.example" });
        zoneBuilder.AddTxtRecord(300, "txt.example", "v=spf1 -all");
        var store = CreateStore(zoneBuilder);
        var queryBytes = new[]
        {
            DnsTestPacket.CreateQuery("ipv6.example", (ushort)RecordType.Aaaa),
            DnsTestPacket.CreateQuery("alias.example"),
            DnsTestPacket.CreateQuery("mail.example", (ushort)RecordType.Mx),
            DnsTestPacket.CreateQuery("txt.example", (ushort)RecordType.Txt),
        };
        var buffers = new[] { new byte[512], new byte[512], new byte[512], new byte[512] };
        var queries = new[] { new DnsQueryContext(), new DnsQueryContext(), new DnsQueryContext(), new DnsQueryContext() };
        var responses = new[] { new DnsResponseContext(), new DnsResponseContext(), new DnsResponseContext(), new DnsResponseContext() };

        for (var recordTypeIndex = 0; recordTypeIndex < queryBytes.Length; recordTypeIndex++)
        {
            queryBytes[recordTypeIndex].AsSpan().CopyTo(buffers[recordTypeIndex]);
            _ = DnsReader.Read(buffers[recordTypeIndex].AsMemory(0, queryBytes[recordTypeIndex].Length), queries[recordTypeIndex]);
            _ = store.TryResolve(queries[recordTypeIndex].Question, out var answerSet);
            responses[recordTypeIndex].Set(queries[recordTypeIndex], answerSet, ResponseCode.NoError, false, true);
            _ = DnsWriter.Write(buffers[recordTypeIndex], responses[recordTypeIndex]);
        }

        var allocations = new long[queryBytes.Length];
        for (var recordTypeIndex = 0; recordTypeIndex < queryBytes.Length; recordTypeIndex++)
        {
            queryBytes[recordTypeIndex].AsSpan().CopyTo(buffers[recordTypeIndex]);
            var allocatedBytesBefore = GC.GetAllocatedBytesForCurrentThread();
            var readResult = DnsReader.Read(
                buffers[recordTypeIndex].AsMemory(0, queryBytes[recordTypeIndex].Length),
                queries[recordTypeIndex]);
            var found = store.TryResolve(queries[recordTypeIndex].Question, out var answerSet);
            responses[recordTypeIndex].Set(queries[recordTypeIndex], answerSet, ResponseCode.NoError, false, true);
            var responseLength = DnsWriter.Write(buffers[recordTypeIndex], responses[recordTypeIndex]);
            allocations[recordTypeIndex] = GC.GetAllocatedBytesForCurrentThread() - allocatedBytesBefore;

            Assert.Equal(DnsReadOutcome.Query, readResult.Outcome);
            Assert.True(found);
            Assert.True(responseLength > queryBytes[recordTypeIndex].Length);
        }

        Assert.All(allocations, allocation => Assert.Equal(0, allocation));
    }

    [Fact]
    public void Materialize_WhenResponseContextIsReused_RetainsManagedQueryAndRecords()
    {
        var queryBytes = DnsTestPacket.CreateQuery(transactionId: 0x1234);
        var buffer = new byte[512];
        queryBytes.AsSpan().CopyTo(buffer);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(buffer.AsMemory(0, queryBytes.Length), query);
        var zoneBuilder = CreateRootZoneBuilder();
        zoneBuilder.AddRecordSet(CreateARecordSet(0, "example.com", "192.0.2.1"));
        var store = CreateStore(zoneBuilder);
        _ = store.TryResolve(query.Question, out var answerSet);
        var response = new DnsResponseContext();
        response.Set(query, answerSet, ResponseCode.NoError, false, true);
        var materialized = response.Materialize();

        var secondQuery = DnsTestPacket.CreateQuery("other.example", transactionId: 0x5678);
        secondQuery.AsSpan().CopyTo(buffer);
        _ = DnsReader.Read(buffer.AsMemory(0, secondQuery.Length), query);
        response.Set(query, null, ResponseCode.NotZone, false, true);

        Assert.Equal((ushort)0x1234, materialized.Query.TransactionId);
        Assert.Equal("example.com", materialized.Query.Question.Name.Value);
        Assert.Equal(1, materialized.AnswerSet!.Count);
        Assert.False(materialized.AuthoritativeAnswer);
        Assert.True(materialized.RecursionAvailable);
        Assert.Equal(ResponseCode.NoError, materialized.ResponseCode);
    }

    private static DnsZoneBuilder CreateRootZoneBuilder()
    {
        var builder = new DnsZoneBuilder(".");
        builder.AddRecordSet(CreateSoaRecordSet(300, "ns1.example", "hostmaster@example", 1));
        builder.AddRecordSet(CreateNsRecordSet(300, "ns1.example"));

        return builder;
    }

    private static DnsZoneStore CreateStore(DnsZoneBuilder zoneBuilder)
    {
        var zoneSetBuilder = new DnsZoneSetBuilder();
        zoneSetBuilder.Load(zoneBuilder);
        var zoneSet = zoneSetBuilder.Build();
        var store = new DnsZoneStore();
        store.Load(zoneSet);

        return store;
    }

    private static ARecordSet CreateARecordSet(
        uint ttl,
        string name,
        params IReadOnlyCollection<string> addresses)
    {
        var records = new ARecord[addresses.Count];
        var recordIndex = 0;
        foreach (var address in addresses)
            records[recordIndex++] = new ARecord { Address = address };

        return new ARecordSet
        {
            Name = name,
            Ttl = ttl,
            Records = records,
        };
    }

    private static PtrRecordSet CreatePtrRecordSet(uint ttl, string name, string target)
    {
        return new PtrRecordSet
        {
            Name = name,
            Ttl = ttl,
            Records = [new PtrRecord { Target = target }],
        };
    }

    private static NsRecordSet CreateNsRecordSet(
        uint ttl,
        params IReadOnlyCollection<string> nameServers)
    {
        var records = new NsRecord[nameServers.Count];
        var recordIndex = 0;
        foreach (var nameServer in nameServers)
            records[recordIndex++] = new NsRecord { NameServer = nameServer };

        return new NsRecordSet
        {
            Name = "@",
            Ttl = ttl,
            Records = records,
        };
    }

    private static SoaRecordSet CreateSoaRecordSet(
        uint ttl,
        string primaryNameServer,
        string responsibleMailbox,
        uint serial)
    {
        return new SoaRecordSet
        {
            Name = "@",
            Ttl = ttl,
            Record = new SoaRecord
            {
                PrimaryNameServer = primaryNameServer,
                ResponsibleMailbox = responsibleMailbox,
                Serial = serial,
                Refresh = 3600,
                Retry = 600,
                Expire = 1_209_600,
                Minimum = 300,
            },
        };
    }
}
