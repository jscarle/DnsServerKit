using System.Buffers.Binary;
using DnsServerKit.Internal.Lookup;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Internal.Responses;
using DnsServerKit.Parameters;
using DnsServerKit.Records;
using DnsServerKit.Zones;
using Xunit;

namespace DnsServerKit.Tests;

public sealed class DnsAuthoritativeSemanticsTests
{
    [Fact]
    public void Resolve_WhenNameAndTypeExist_ReturnsAuthoritativeCompleteAnswer()
    {
        var zoneBuilder = CreateZoneBuilder("example.com");
        zoneBuilder.AddRecordSet(new ARecordSet
        {
            Name = "www",
            Ttl = 600,
            Records =
            [
                new ARecord { Address = "192.0.2.1" },
                new ARecord { Address = "192.0.2.2" },
            ],
        });
        var store = CreateStore(zoneBuilder);

        var response = Execute(store, "www.example.com", (ushort)RecordType.A);

        Assert.Equal((ushort)0x8400, response.Flags);
        Assert.Equal((ushort)2, response.AnswerCount);
        Assert.Equal((ushort)0, response.AuthorityCount);
        Assert.Equal((ushort)0, response.AdditionalCount);
        var offset = response.QuestionEnd;
        var firstRecord = ReadRecord(response.Buffer, ref offset);
        var secondRecord = ReadRecord(response.Buffer, ref offset);
        Assert.Equal("www.example.com", firstRecord.Name);
        Assert.Equal((ushort)RecordType.A, firstRecord.Type);
        Assert.Equal((ushort)DnsClass.Internet, firstRecord.Class);
        Assert.Equal(600U, firstRecord.Ttl);
        Assert.Equal((ushort)RecordType.A, secondRecord.Type);
        Assert.Equal(response.Length, offset);
    }

    [Fact]
    public void Resolve_WhenTypeOrNameIsAbsent_DistinguishesNoDataEmptyNonTerminalAndNxDomain()
    {
        var zoneBuilder = CreateZoneBuilder("example.com");
        zoneBuilder.AddARecord(600, "www", "192.0.2.1");
        zoneBuilder.AddARecord(600, "host.branch", "192.0.2.2");
        var store = CreateStore(zoneBuilder);

        var noData = Execute(store, "www.example.com", (ushort)RecordType.Aaaa);
        var emptyNonTerminal = Execute(store, "branch.example.com", (ushort)RecordType.A);
        var nameError = Execute(store, "missing.example.com", (ushort)RecordType.A);

        Assert.Equal(ResponseCode.NoError, AssertNegative(noData));
        Assert.Equal(ResponseCode.NoError, AssertNegative(emptyNonTerminal));
        Assert.Equal(ResponseCode.NxDomain, AssertNegative(nameError));
    }

    [Fact]
    public void Resolve_WhenClassOrMetaTypeIsNotServed_UsesRefusedOrNotImplementedWithoutAuthority()
    {
        var zoneBuilder = CreateZoneBuilder("example.com");
        zoneBuilder.AddARecord(600, "www", "192.0.2.1");
        var store = CreateStore(zoneBuilder);

        var anyClass = Execute(store, "www.example.com", (ushort)RecordType.A, (ushort)DnsClass.Any);
        var unservedClass = Execute(store, "www.example.com", (ushort)RecordType.A, (ushort)DnsClass.Hesiod);
        var outsideZone = Execute(store, "www.example.net", (ushort)RecordType.A);
        var zoneTransfer = Execute(store, "example.com", (ushort)RecordType.AxFr);
        var obsoleteMetaType = Execute(store, "example.com", (ushort)RecordType.MailA);

        AssertError(anyClass, ResponseCode.Refused);
        AssertError(unservedClass, ResponseCode.Refused);
        AssertError(outsideZone, ResponseCode.Refused);
        AssertError(zoneTransfer, ResponseCode.Refused);
        AssertError(obsoleteMetaType, ResponseCode.NotImplemented);
    }

    [Fact]
    public void Resolve_WhenZonesShareApex_AnswersOnlyTheExactConcreteClass()
    {
        var internetBuilder = CreateZoneBuilder("example.com");
        internetBuilder.AddARecord(600, "www", "192.0.2.1");
        var chaosBuilder = CreateZoneBuilder("example.com", DnsClass.Chaos);
        chaosBuilder.AddARecord(600, "www", "192.0.2.2");
        var store = CreateStore(internetBuilder, chaosBuilder);

        var internetResponse = Execute(store, "www.example.com", (ushort)RecordType.A);
        var chaosResponse = Execute(store, "www.example.com", (ushort)RecordType.A, (ushort)DnsClass.Chaos);

        var internetOffset = internetResponse.QuestionEnd;
        var internetRecord = ReadRecord(internetResponse.Buffer, ref internetOffset);
        var chaosOffset = chaosResponse.QuestionEnd;
        var chaosRecord = ReadRecord(chaosResponse.Buffer, ref chaosOffset);
        Assert.Equal((ushort)DnsClass.Internet, internetRecord.Class);
        Assert.Equal((byte)1, internetResponse.Buffer[internetResponse.Length - 1]);
        Assert.Equal((ushort)DnsClass.Chaos, chaosRecord.Class);
        Assert.Equal((byte)2, chaosResponse.Buffer[chaosResponse.Length - 1]);
    }

    [Fact]
    public void Resolve_WhenOrdinaryTypeIsUnknown_AppliesNoDataAndNxDomainRules()
    {
        var zoneBuilder = CreateZoneBuilder("example.com");
        zoneBuilder.AddARecord(600, "www", "192.0.2.1");
        var store = CreateStore(zoneBuilder);

        var noData = Execute(store, "www.example.com", 65_000);
        var nameError = Execute(store, "missing.example.com", 65_000);

        Assert.Equal(ResponseCode.NoError, AssertNegative(noData));
        Assert.Equal(ResponseCode.NxDomain, AssertNegative(nameError));
    }

    [Fact]
    public void Resolve_WhenTypeIsAny_ReturnsSmallestCompleteRecordSet()
    {
        var zoneBuilder = CreateZoneBuilder("example.com");
        zoneBuilder.AddARecord(600, "multi", "192.0.2.1");
        zoneBuilder.AddTxtRecord(600, "multi", new string('a', 200));
        var store = CreateStore(zoneBuilder);

        var response = Execute(store, "multi.example.com", (ushort)RecordType.All);

        Assert.Equal((ushort)0x8400, response.Flags);
        Assert.Equal((ushort)1, response.AnswerCount);
        var offset = response.QuestionEnd;
        var record = ReadRecord(response.Buffer, ref offset);
        Assert.Equal((ushort)RecordType.A, record.Type);
        Assert.Equal(response.Length, offset);
    }

    [Fact]
    public void Resolve_WhenQueryCrossesDelegation_ReturnsReferralAndBailiwickGlue()
    {
        var parentBuilder = CreateZoneBuilder("example.com");
        parentBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "child",
            Ttl = 600,
            Records =
            [
                new NsRecord { NameServer = "ns1.child.example.com" },
                new NsRecord { NameServer = "ns1.sibling.example.com" },
                new NsRecord { NameServer = "ns1.example.net" },
            ],
        });
        parentBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "sibling",
            Ttl = 600,
            Records = [new NsRecord { NameServer = "ns1.sibling.example.com" }],
        });
        parentBuilder.AddARecord(600, "ns1.child", "192.0.2.10");
        parentBuilder.AddARecord(600, "ns1.sibling", "192.0.2.11");
        var store = CreateStore(parentBuilder);

        var response = Execute(store, "www.child.example.com", (ushort)RecordType.A);

        Assert.Equal((ushort)0x8000, response.Flags);
        Assert.Equal((ushort)0, response.AnswerCount);
        Assert.Equal((ushort)3, response.AuthorityCount);
        Assert.Equal((ushort)2, response.AdditionalCount);
        var offset = response.QuestionEnd;
        for (var recordIndex = 0; recordIndex < 3; recordIndex++)
        {
            var nameServer = ReadRecord(response.Buffer, ref offset);
            Assert.Equal("child.example.com", nameServer.Name);
            Assert.Equal((ushort)RecordType.Ns, nameServer.Type);
        }

        var firstGlue = ReadRecord(response.Buffer, ref offset);
        var secondGlue = ReadRecord(response.Buffer, ref offset);
        Assert.Equal("ns1.child.example.com", firstGlue.Name);
        Assert.Equal("ns1.sibling.example.com", secondGlue.Name);
        Assert.Equal(response.Length, offset);
    }

    [Fact]
    public void Resolve_WhenDelegationSignerIsQueriedAtCut_ReturnsParentAuthoritativeNoData()
    {
        var parentBuilder = CreateZoneBuilder("example.com");
        parentBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "child",
            Ttl = 600,
            Records = [new NsRecord { NameServer = "ns1.child.example.com" }],
        });
        parentBuilder.AddARecord(600, "ns1.child", "192.0.2.10");
        var store = CreateStore(parentBuilder);

        var response = Execute(store, "child.example.com", 43);

        Assert.Equal(ResponseCode.NoError, AssertNegative(response));
    }

    [Fact]
    public void Resolve_WhenChildZoneIsLoaded_UsesChildAuthorityExceptForParentSideDelegationSigner()
    {
        var parentBuilder = CreateZoneBuilder("example.com");
        parentBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "child",
            Ttl = 600,
            Records = [new NsRecord { NameServer = "ns1.child.example.com" }],
        });
        parentBuilder.AddARecord(600, "ns1.child", "192.0.2.10");
        var childBuilder = CreateZoneBuilder("child.example.com");
        childBuilder.AddARecord(600, "www", "192.0.2.20");
        var store = CreateStore(parentBuilder, childBuilder);

        var childAnswer = Execute(store, "www.child.example.com", (ushort)RecordType.A);
        var delegationSigner = Execute(store, "child.example.com", 43);

        Assert.Equal((ushort)0x8400, childAnswer.Flags);
        Assert.Equal((ushort)1, childAnswer.AnswerCount);
        Assert.Equal(ResponseCode.NoError, AssertNegative(delegationSigner));
        var offset = delegationSigner.QuestionEnd;
        var startOfAuthority = ReadRecord(delegationSigner.Buffer, ref offset);
        Assert.Equal("example.com", startOfAuthority.Name);
    }

    [Fact]
    public void Resolve_WhenCnameIsFollowed_UsesFinalRcodeAndFirstOwnerAuthority()
    {
        var zoneBuilder = CreateZoneBuilder("example.com");
        zoneBuilder.AddCnameRecord(600, "alias", "target.example.com");
        zoneBuilder.AddCnameRecord(600, "broken", "missing.example.com");
        zoneBuilder.AddARecord(600, "target", "192.0.2.1");
        var store = CreateStore(zoneBuilder);

        var answer = Execute(store, "alias.example.com", (ushort)RecordType.A);
        var nameError = Execute(store, "broken.example.com", (ushort)RecordType.A);

        Assert.Equal((ushort)0x8400, answer.Flags);
        Assert.Equal((ushort)2, answer.AnswerCount);
        Assert.Equal((ushort)0x8403, nameError.Flags);
        Assert.Equal((ushort)1, nameError.AnswerCount);
        Assert.Equal((ushort)1, nameError.AuthorityCount);
    }

    [Fact]
    public void Load_WhenCnameChainContainsCycle_RejectsSnapshot()
    {
        var zoneBuilder = CreateZoneBuilder("example.com");
        zoneBuilder.AddCnameRecord(600, "first", "second.example.com");
        zoneBuilder.AddCnameRecord(600, "second", "first.example.com");
        var zoneSetBuilder = new DnsZoneSetBuilder();
        zoneSetBuilder.Load(zoneBuilder);
        var store = new DnsZoneStore();

        var exception = Assert.Throws<InvalidOperationException>(() => store.Load(zoneSetBuilder.Build()));

        Assert.Contains("cycle", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Write_WhenMandatoryGlueDoesNotFit_SetsTruncatedAndOmitsIncompleteRrSet()
    {
        var parentBuilder = CreateZoneBuilder("example.com");
        parentBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "child",
            Ttl = 600,
            Records = [new NsRecord { NameServer = "ns1.child.example.com" }],
        });
        var addresses = new ARecord[40];
        for (var addressIndex = 0; addressIndex < addresses.Length; addressIndex++)
            addresses[addressIndex] = new ARecord { Address = $"192.0.2.{addressIndex + 1}" };
        parentBuilder.AddRecordSet(new ARecordSet { Name = "ns1.child", Ttl = 600, Records = addresses });
        var store = CreateStore(parentBuilder);

        var response = Execute(store, "www.child.example.com", (ushort)RecordType.A);

        Assert.NotEqual((ushort)0, (ushort)(response.Flags & 0x0200));
        Assert.Equal((ushort)1, response.AuthorityCount);
        Assert.Equal((ushort)0, response.AdditionalCount);
    }

    [Fact]
    public void Write_WhenOptionalSiblingGlueDoesNotFit_OmitsItWithoutSettingTruncated()
    {
        var parentBuilder = CreateZoneBuilder("example.com");
        parentBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "child",
            Ttl = 600,
            Records = [new NsRecord { NameServer = "ns1.sibling.example.com" }],
        });
        parentBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "sibling",
            Ttl = 600,
            Records = [new NsRecord { NameServer = "ns1.sibling.example.com" }],
        });
        var addresses = new ARecord[40];
        for (var addressIndex = 0; addressIndex < addresses.Length; addressIndex++)
            addresses[addressIndex] = new ARecord { Address = $"192.0.2.{addressIndex + 1}" };
        parentBuilder.AddRecordSet(new ARecordSet { Name = "ns1.sibling", Ttl = 600, Records = addresses });
        var store = CreateStore(parentBuilder);

        var response = Execute(store, "www.child.example.com", (ushort)RecordType.A);

        Assert.Equal((ushort)0, (ushort)(response.Flags & 0x0200));
        Assert.Equal((ushort)1, response.AuthorityCount);
        Assert.Equal((ushort)0, response.AdditionalCount);
    }

    [Fact]
    public void ResolveAndWrite_WhenPathsAreWarmed_DoesNotAllocate()
    {
        var zoneBuilder = CreateZoneBuilder("example.com");
        zoneBuilder.AddARecord(600, "www", "192.0.2.1");
        zoneBuilder.AddCnameRecord(600, "alias", "www.example.com");
        zoneBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "child",
            Ttl = 600,
            Records = [new NsRecord { NameServer = "ns1.child.example.com" }],
        });
        zoneBuilder.AddARecord(600, "ns1.child", "192.0.2.10");
        var store = CreateStore(zoneBuilder);
        byte[][] packets =
        [
            DnsTestPacket.CreateQuery("www.example.com"),
            DnsTestPacket.CreateQuery("www.example.com", (ushort)RecordType.Aaaa),
            DnsTestPacket.CreateQuery("missing.example.com"),
            DnsTestPacket.CreateQuery("www.example.com", (ushort)RecordType.All),
            DnsTestPacket.CreateQuery("alias.example.com"),
            DnsTestPacket.CreateQuery("www.child.example.com"),
            DnsTestPacket.CreateQuery("outside.example.net"),
        ];
        var queries = new DnsQueryContext[packets.Length];
        var resolutions = new DnsResolutionContext[packets.Length];
        var responses = new DnsResponseContext[packets.Length];
        var buffers = new byte[packets.Length][];
        for (var scenarioIndex = 0; scenarioIndex < packets.Length; scenarioIndex++)
        {
            queries[scenarioIndex] = new DnsQueryContext();
            resolutions[scenarioIndex] = new DnsResolutionContext();
            responses[scenarioIndex] = new DnsResponseContext();
            buffers[scenarioIndex] = new byte[512];
            ExecutePipeline(store, packets[scenarioIndex], buffers[scenarioIndex], queries[scenarioIndex], resolutions[scenarioIndex], responses[scenarioIndex]);
        }

        var allocatedBytesBefore = GC.GetAllocatedBytesForCurrentThread();
        for (var scenarioIndex = 0; scenarioIndex < packets.Length; scenarioIndex++)
            ExecutePipeline(store, packets[scenarioIndex], buffers[scenarioIndex], queries[scenarioIndex], resolutions[scenarioIndex], responses[scenarioIndex]);
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - allocatedBytesBefore;

        Assert.Equal(0, allocatedBytes);
    }

    private static ResponseCode AssertNegative(DnsPacketResponse response)
    {
        Assert.Equal((ushort)0x8400, (ushort)(response.Flags & 0xfff0));
        Assert.Equal((ushort)0, response.AnswerCount);
        Assert.Equal((ushort)1, response.AuthorityCount);
        Assert.Equal((ushort)0, response.AdditionalCount);
        var offset = response.QuestionEnd;
        var startOfAuthority = ReadRecord(response.Buffer, ref offset);
        Assert.Equal((ushort)RecordType.Soa, startOfAuthority.Type);
        Assert.Equal(300U, startOfAuthority.Ttl);
        Assert.Equal(response.Length, offset);

        return (ResponseCode)(response.Flags & 0x000f);
    }

    private static void AssertError(DnsPacketResponse response, ResponseCode responseCode)
    {
        Assert.Equal((ushort)(0x8000 | (ushort)responseCode), response.Flags);
        Assert.Equal((ushort)0, response.AnswerCount);
        Assert.Equal((ushort)0, response.AuthorityCount);
        Assert.Equal((ushort)0, response.AdditionalCount);
    }

    private static DnsPacketResponse Execute(DnsZoneStore store, string name, ushort type, ushort @class = (ushort)DnsClass.Internet)
    {
        var packet = DnsTestPacket.CreateQuery(name, type, @class);
        var buffer = new byte[512];
        packet.CopyTo(buffer, 0);
        var query = new DnsQueryContext();
        var readResult = DnsReader.Read(buffer.AsMemory(0, packet.Length), query);
        Assert.Equal(DnsReadOutcome.Query, readResult.Outcome);
        var resolution = new DnsResolutionContext();
        store.Resolve(query.Question, resolution);
        var response = new DnsResponseContext();
        response.Set(query, resolution);
        var length = DnsWriter.Write(buffer, response);

        return new DnsPacketResponse(buffer, length, packet.Length);
    }

    private static void ExecutePipeline(
        DnsZoneStore store,
        byte[] packet,
        byte[] buffer,
        DnsQueryContext query,
        DnsResolutionContext resolution,
        DnsResponseContext response)
    {
        packet.AsSpan().CopyTo(buffer);
        _ = DnsReader.Read(buffer.AsMemory(0, packet.Length), query);
        store.Resolve(query.Question, resolution);
        response.Set(query, resolution);
        _ = DnsWriter.Write(buffer, response);
    }

    private static ParsedRecord ReadRecord(byte[] packet, ref int offset)
    {
        var name = DnsTestPacket.ReadName(packet, ref offset);
        var type = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset));
        var @class = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 2));
        var ttl = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(offset + 4));
        var resourceDataLength = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 8));
        offset += 10 + resourceDataLength;

        return new ParsedRecord(name, type, @class, ttl);
    }

    private static DnsZoneBuilder CreateZoneBuilder(string apex, DnsClass dnsClass = DnsClass.Internet)
    {
        var zoneBuilder = new DnsZoneBuilder(apex, dnsClass);
        zoneBuilder.AddRecordSet(new SoaRecordSet
        {
            Name = "@",
            Ttl = 600,
            Record = new SoaRecord
            {
                PrimaryNameServer = $"ns1.{apex}",
                ResponsibleMailbox = $"hostmaster@{apex}",
                Serial = 1,
                Refresh = 3600,
                Retry = 600,
                Expire = 1_209_600,
                Minimum = 300,
            },
        });
        zoneBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "@",
            Ttl = 600,
            Records = [new NsRecord { NameServer = $"ns1.{apex}" }],
        });

        return zoneBuilder;
    }

    private static DnsZoneStore CreateStore(params DnsZoneBuilder[] zoneBuilders)
    {
        var zoneSetBuilder = new DnsZoneSetBuilder();
        foreach (var zoneBuilder in zoneBuilders)
            zoneSetBuilder.Load(zoneBuilder);

        var store = new DnsZoneStore();
        store.Load(zoneSetBuilder.Build());
        return store;
    }

    private readonly record struct ParsedRecord(string Name, ushort Type, ushort Class, uint Ttl);

    private readonly record struct DnsPacketResponse(byte[] Buffer, int Length, int QuestionEnd)
    {
        public ushort Flags => BinaryPrimitives.ReadUInt16BigEndian(Buffer.AsSpan(2));

        public ushort AnswerCount => BinaryPrimitives.ReadUInt16BigEndian(Buffer.AsSpan(6));

        public ushort AuthorityCount => BinaryPrimitives.ReadUInt16BigEndian(Buffer.AsSpan(8));

        public ushort AdditionalCount => BinaryPrimitives.ReadUInt16BigEndian(Buffer.AsSpan(10));
    }
}
