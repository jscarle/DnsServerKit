using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Parameters;
using DnsServerKit.Records;
using DnsServerKit.Zones;
using Xunit;

namespace DnsServerKit.Tests;

public sealed class DnsZoneSetTests
{
    [Fact]
    public void Build_WhenRecordSetHasMultipleValues_PreservesTypedRrSetMetadata()
    {
        var zoneBuilder = CreateZoneBuilder("example.com");
        zoneBuilder.AddRecordSet(new ARecordSet
        {
            Name = "@",
            Ttl = 300,
            Records =
            [
                new ARecord { Address = "192.0.2.1" },
                new ARecord { Address = "192.0.2.2" },
            ],
        });
        var zone = zoneBuilder.Build();
        var zoneSet = CreateZoneSet(zone);
        var store = LoadZoneSet(zoneSet);

        var found = store.TryGet(
            new DnsName("example.com"),
            (ushort)RecordType.A,
            (ushort)DnsClass.Internet,
            out var recordSet);

        Assert.True(found);
        var addressRecordSet = Assert.IsType<ARecordSet>(recordSet);
        var zoneSetZone = Assert.Single(zoneSet.Zones);
        Assert.Equal(3, zoneSetZone.RecordSets.Count);
        Assert.Equal(3, zone.RecordSets.Count);
        Assert.Equal(2, addressRecordSet.Count);
        Assert.Equal(300U, addressRecordSet.Ttl);
        Assert.Equal("@", addressRecordSet.Name);
    }

    [Fact]
    public void TryResolve_WhenQuestionCaseDiffers_PerformsAlternateWireLookup()
    {
        var zone = CreateZone("example.com", "@", "192.0.2.1");
        var store = CreateStore(zone);
        var packet = DnsTestPacket.CreateQuery("EXAMPLE.COM");
        var query = new DnsQueryContext();
        _ = DnsReader.Read(packet, query);

        var found = store.TryResolve(query.Question, out var recordSet);

        Assert.True(found);
        var addressRecordSet = Assert.IsType<ARecordSet>(recordSet);
        Assert.Equal("@", addressRecordSet.Name);
    }

    [Fact]
    public void Load_WhenZoneKeyAlreadyExists_ReplacesTheZone()
    {
        var firstZone = CreateZone("example.com", "@", "192.0.2.1");
        var replacementZone = CreateZone("example.com", "@", "192.0.2.2");
        var builder = new DnsZoneSetBuilder();
        builder.Load(firstZone);
        var firstZoneSet = builder.Build();
        var firstStore = LoadZoneSet(firstZoneSet);
        _ = firstStore.TryGet(new DnsName("example.com"), 1, 1, out var firstRecordSet);

        builder.Load(replacementZone);
        var replacementZoneSet = builder.Build();
        var replacementStore = LoadZoneSet(replacementZoneSet);
        _ = replacementStore.TryGet(new DnsName("example.com"), 1, 1, out var replacementRecordSet);

        Assert.Single(replacementZoneSet.Zones);
        Assert.NotNull(firstRecordSet);
        Assert.NotNull(replacementRecordSet);
        Assert.NotSame(firstRecordSet, replacementRecordSet);
    }

    [Fact]
    public void Load_WhenZoneUsesObjectInitializer_CompilesAnOwnedSnapshot()
    {
        var sourceZone = CreateZone("example.com", "@", "192.0.2.1");
        var recordSets = sourceZone.RecordSets.ToList();
        var zone = new DnsZone
        {
            Name = "example.com",
            Class = DnsClass.Internet,
            RecordSets = recordSets,
        };
        var builder = new DnsZoneSetBuilder();
        builder.Load(zone);

        recordSets.Clear();
        var zoneSet = builder.Build();
        var store = LoadZoneSet(zoneSet);

        Assert.True(store.TryGet(
            new DnsName("example.com"),
            (ushort)RecordType.A,
            (ushort)DnsClass.Internet,
            out var recordSet));
        Assert.IsType<ARecordSet>(recordSet);
        Assert.Equal(3, Assert.Single(zoneSet.Zones).RecordSets.Count);
    }

    [Fact]
    public void Load_WhenZoneBuilderIsProvided_DefersBuildingUntilZoneSetBuild()
    {
        var zoneBuilder = new DnsZoneBuilder("example.com");
        var builder = new DnsZoneSetBuilder();
        builder.Load(zoneBuilder);

        Assert.Throws<InvalidOperationException>(() => builder.Build());

        zoneBuilder.AddSoaRecord(
            300,
            "ns1.example.com",
            "hostmaster@example.com",
            1,
            3600,
            600,
            1_209_600,
            300);
        zoneBuilder.AddNsRecord(300, "ns1.example.com");

        var zoneSet = builder.Build();

        var zone = Assert.Single(zoneSet.Zones);
        Assert.Equal("example.com", zone.Name);
        Assert.Equal(2, zone.RecordSets.Count);
    }

    [Fact]
    public void Load_WhenZoneAndBuilderShareAKey_UsesTheMostRecentlyLoadedSource()
    {
        var zone = CreateZone("example.com", "@", "192.0.2.1");
        var zoneBuilder = CreateZoneBuilder("example.com");
        zoneBuilder.AddARecord(300, "@", "192.0.2.2");
        var builder = new DnsZoneSetBuilder();

        builder.Load(zone);
        builder.Load(zoneBuilder);
        var builderZoneSet = builder.Build();
        var builderStore = LoadZoneSet(builderZoneSet);
        _ = builderStore.TryGet(new DnsName("example.com"), 1, 1, out var builderRecordSet);

        builder.Load(zone);
        var modelZoneSet = builder.Build();
        var zoneStore = LoadZoneSet(modelZoneSet);
        _ = zoneStore.TryGet(new DnsName("example.com"), 1, 1, out var zoneRecordSet);

        var builderAddressRecordSet = Assert.IsType<ARecordSet>(builderRecordSet);
        var zoneAddressRecordSet = Assert.IsType<ARecordSet>(zoneRecordSet);
        Assert.Equal("192.0.2.2", Assert.Single(builderAddressRecordSet.Records).Address);
        Assert.Equal("192.0.2.1", Assert.Single(zoneAddressRecordSet.Records).Address);
    }

    [Fact]
    public void Build_WhenZoneBuilderChanges_CreatesIndependentZoneAndZoneSetSnapshots()
    {
        var zoneBuilder = CreateZoneBuilder("example.com");
        var firstZone = zoneBuilder.Build();
        var firstZoneSet = CreateZoneSet(firstZone);

        zoneBuilder.AddRecordSet(new ARecordSet
        {
            Name = "www",
            Ttl = 300,
            Records = [new ARecord { Address = "192.0.2.1" }],
        });
        var secondZone = zoneBuilder.Build();
        var secondZoneSet = CreateZoneSet(secondZone);
        var firstStore = LoadZoneSet(firstZoneSet);
        var secondStore = LoadZoneSet(secondZoneSet);

        Assert.False(firstStore.TryGet(new DnsName("www.example.com"), 1, 1, out _));
        Assert.True(secondStore.TryGet(new DnsName("www.example.com"), 1, 1, out _));
        Assert.Equal(2, firstZone.RecordSets.Count);
        Assert.Equal(3, secondZone.RecordSets.Count);
    }

    [Fact]
    public void TryResolve_WhenChildZoneMatches_DoesNotFallBackToParentZone()
    {
        var parentBuilder = CreateZoneBuilder("example.com");
        parentBuilder.AddRecordSet(new ARecordSet
        {
            Name = "www.child",
            Ttl = 300,
            Records = [new ARecord { Address = "192.0.2.1" }],
        });
        var childZone = CreateZoneBuilder("child.example.com").Build();
        var store = CreateStore(parentBuilder.Build(), childZone);
        var packet = DnsTestPacket.CreateQuery("www.child.example.com");
        var query = new DnsQueryContext();
        _ = DnsReader.Read(packet, query);

        var found = store.TryResolve(query.Question, out var recordSet);

        Assert.False(found);
        Assert.Null(recordSet);
    }

    [Fact]
    public void TryGet_WhenZonesShareApex_SelectsExactClass()
    {
        var internetZone = CreateZone("example.com", "@", "192.0.2.1");
        var chaosZone = CreateZone("example.com", "@", "192.0.2.2", DnsClass.Chaos);
        var store = CreateStore(internetZone, chaosZone);

        var foundInternet = store.TryGet(new DnsName("example.com"), 1, (ushort)DnsClass.Internet, out var internetRecordSet);
        var foundChaos = store.TryGet(new DnsName("example.com"), 1, (ushort)DnsClass.Chaos, out var chaosRecordSet);

        Assert.True(foundInternet);
        Assert.True(foundChaos);
        Assert.IsType<ARecordSet>(internetRecordSet);
        Assert.IsType<ARecordSet>(chaosRecordSet);
        Assert.Equal(DnsClass.Internet, internetZone.Class);
        Assert.Equal(DnsClass.Chaos, chaosZone.Class);
    }

    [Fact]
    public void Load_WhenReadersHoldPreviousSnapshot_PublishesNewSnapshotAtomically()
    {
        var first = CreateZoneSet(CreateZone("first.example", "@", "192.0.2.1"));
        var second = CreateZoneSet(CreateZone("second.example", "@", "192.0.2.2"));
        var store = new DnsZoneStore();

        Assert.Empty(store.Current.Zones);
        store.Load(first);

        var heldSnapshot = store.Current;
        store.Load(second);

        Assert.Same(first, heldSnapshot);
        Assert.Same(second, store.Current);
        Assert.Equal("first.example", Assert.Single(heldSnapshot.Zones).Name);
        Assert.Equal("second.example", Assert.Single(store.Current.Zones).Name);
        Assert.True(store.TryGet(new DnsName("second.example"), 1, 1, out _));
    }

    [Fact]
    public void Load_WhenPublicationFails_LeavesPreviousZoneSetAndIndexActive()
    {
        var zoneSet = CreateZoneSet(CreateZone("example.com", "@", "192.0.2.1"));
        var store = LoadZoneSet(zoneSet);

        Assert.Throws<ArgumentNullException>(() => store.Load(null!));

        Assert.Same(zoneSet, store.Current);
        Assert.True(store.TryGet(new DnsName("example.com"), 1, 1, out _));
    }

    [Fact]
    public async Task Load_WhileReadersRun_OnlyPublishesCompleteSnapshots()
    {
        var first = CreateZoneSet(CreateZone("first.example", "@", "192.0.2.1"));
        var second = CreateZoneSet(CreateZone("second.example", "@", "192.0.2.2"));
        var store = new DnsZoneStore();
        store.Load(first);
        var startSignal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var readers = new Task[Environment.ProcessorCount];

        for (var readerIndex = 0; readerIndex < readers.Length; readerIndex++)
        {
            readers[readerIndex] = Task.Run(async () =>
            {
                await startSignal.Task;
                for (var readIndex = 0; readIndex < 10_000; readIndex++)
                {
                    var snapshot = store.Current;
                    Assert.True(ReferenceEquals(snapshot, first) || ReferenceEquals(snapshot, second));
                }
            });
        }

        startSignal.SetResult();
        for (var replacementIndex = 0; replacementIndex < 10_000; replacementIndex++)
            store.Load((replacementIndex & 1) == 0 ? second : first);

        await Task.WhenAll(readers);
    }

    [Fact]
    public void TryResolve_WhenWarmed_DoesNotAllocate()
    {
        var store = CreateStore(CreateZone("example.com", "@", "192.0.2.1"));
        var packet = DnsTestPacket.CreateQuery("EXAMPLE.COM");
        var query = new DnsQueryContext();
        _ = DnsReader.Read(packet, query);
        _ = store.TryResolve(query.Question, out _);

        var allocatedBytesBefore = GC.GetAllocatedBytesForCurrentThread();
        var found = store.TryResolve(query.Question, out var recordSet);
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - allocatedBytesBefore;

        Assert.True(found);
        Assert.NotNull(recordSet);
        Assert.Equal(0, allocatedBytes);
    }

    private static DnsZoneBuilder CreateZoneBuilder(
        string apex,
        DnsClass dnsClass = DnsClass.Internet)
    {
        var builder = new DnsZoneBuilder(apex, dnsClass);
        builder.AddRecordSet(new SoaRecordSet
        {
            Name = "@",
            Ttl = 300,
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
        builder.AddRecordSet(new NsRecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new NsRecord { NameServer = $"ns1.{apex}" }],
        });

        return builder;
    }

    private static DnsZone CreateZone(
        string apex,
        string name,
        string address,
        DnsClass dnsClass = DnsClass.Internet)
    {
        var builder = CreateZoneBuilder(apex, dnsClass);
        builder.AddRecordSet(new ARecordSet
        {
            Name = name,
            Ttl = 300,
            Records = [new ARecord { Address = address }],
        });

        return builder.Build();
    }

    private static DnsZoneSet CreateZoneSet(params DnsZone[] zones)
    {
        var builder = new DnsZoneSetBuilder();
        foreach (var zone in zones)
            builder.Load(zone);

        return builder.Build();
    }

    private static DnsZoneStore CreateStore(params DnsZone[] zones)
    {
        var zoneSet = CreateZoneSet(zones);
        return LoadZoneSet(zoneSet);
    }

    private static DnsZoneStore LoadZoneSet(DnsZoneSet zoneSet)
    {
        var store = new DnsZoneStore();
        store.Load(zoneSet);

        return store;
    }
}
