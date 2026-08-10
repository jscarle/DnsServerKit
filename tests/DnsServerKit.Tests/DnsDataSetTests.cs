using System.Net;
using DnsServerKit.Data;
using DnsServerKit.Parameters;
using DnsServerKit.Queries;
using DnsServerKit.ResourceRecords;
using Xunit;

namespace DnsServerKit.Tests;

public sealed class DnsDataSetTests
{
    [Fact]
    public void Build_WhenRecordsShareAKey_CreatesOneManagedRecordSet()
    {
        var name = new DnsName("example.com");
        var builder = new DnsDataSetBuilder();
        builder.Add(new ARecord(name, IPAddress.Parse("192.0.2.1"), 300));
        builder.Add(new ARecord(name, IPAddress.Parse("192.0.2.2"), 300));

        var dataSet = builder.Build();
        var found = dataSet.TryGet(name, (ushort)RecordType.A, (ushort)DnsClass.Internet, out var recordSet);

        Assert.True(found);
        Assert.NotNull(recordSet);
        Assert.Equal(1, dataSet.RecordSetCount);
        Assert.Equal(2, recordSet.Records.Count);
        Assert.All(recordSet.Records, record => Assert.IsType<ARecord>(record));
    }

    [Fact]
    public void TryResolve_WhenQuestionCaseDiffers_PerformsAlternateWireLookup()
    {
        var builder = new DnsDataSetBuilder();
        var record = new ARecord(new DnsName("example.com"), IPAddress.Parse("192.0.2.1"));
        builder.Add(record);
        var dataSet = builder.Build();
        var packet = DnsTestPacket.CreateQuery("EXAMPLE.COM");
        var query = new DnsQueryContext();
        _ = DnsReader.Read(packet, query);

        var found = dataSet.TryResolve(query.Question, out var recordSet);

        Assert.True(found);
        Assert.NotNull(recordSet);
        Assert.Same(record, recordSet.Records[0]);
    }

    [Fact]
    public void Build_WhenRecordUsesUnknownTypeAndClass_PreservesRawValues()
    {
        const ushort type = 65400;
        const ushort @class = 65399;
        var builder = new DnsDataSetBuilder();
        var record = new RawResourceRecord(new DnsName("unknown.example"), type, @class, 60, [1, 2, 3]);
        builder.Add(record);
        var dataSet = builder.Build();
        var packet = DnsTestPacket.CreateQuery("unknown.example", type, @class);
        var query = new DnsQueryContext();
        _ = DnsReader.Read(packet, query);

        var found = dataSet.TryResolve(query.Question, out var recordSet);

        Assert.True(found);
        Assert.NotNull(recordSet);
        Assert.Equal(type, recordSet.Type);
        Assert.Equal(@class, recordSet.Class);
        Assert.Equal(new byte[] { 1, 2, 3 }, recordSet.Records[0].ResourceData.ToArray());
    }

    [Fact]
    public void Replace_WhenReadersHoldPreviousSnapshot_PublishesNewSnapshotAtomically()
    {
        var firstBuilder = new DnsDataSetBuilder();
        firstBuilder.Add(new ARecord(new DnsName("first.example"), IPAddress.Parse("192.0.2.1")));
        var first = firstBuilder.Build();

        var secondBuilder = new DnsDataSetBuilder();
        secondBuilder.Add(new ARecord(new DnsName("second.example"), IPAddress.Parse("192.0.2.2")));
        var second = secondBuilder.Build();
        var store = new DnsDataSetStore(first);

        var heldSnapshot = store.Current;
        store.Replace(second);

        Assert.Same(first, heldSnapshot);
        Assert.Same(second, store.Current);
        Assert.True(heldSnapshot.TryGet(new DnsName("first.example"), 1, 1, out _));
        Assert.True(store.Current.TryGet(new DnsName("second.example"), 1, 1, out _));
    }

    [Fact]
    public async Task Replace_WhileReadersRun_OnlyPublishesCompleteSnapshots()
    {
        var firstBuilder = new DnsDataSetBuilder();
        firstBuilder.Add(new ARecord(new DnsName("first.example"), IPAddress.Parse("192.0.2.1")));
        var first = firstBuilder.Build();

        var secondBuilder = new DnsDataSetBuilder();
        secondBuilder.Add(new ARecord(new DnsName("second.example"), IPAddress.Parse("192.0.2.2")));
        var second = secondBuilder.Build();
        var store = new DnsDataSetStore(first);
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
            store.Replace((replacementIndex & 1) == 0 ? second : first);

        await Task.WhenAll(readers);
    }

    [Fact]
    public void TryResolve_WhenWarmed_DoesNotAllocate()
    {
        var builder = new DnsDataSetBuilder();
        builder.Add(new ARecord(new DnsName("example.com"), IPAddress.Parse("192.0.2.1")));
        var dataSet = builder.Build();
        var packet = DnsTestPacket.CreateQuery("EXAMPLE.COM");
        var query = new DnsQueryContext();
        _ = DnsReader.Read(packet, query);
        _ = dataSet.TryResolve(query.Question, out _);

        var allocatedBytesBefore = GC.GetAllocatedBytesForCurrentThread();
        var found = dataSet.TryResolve(query.Question, out var recordSet);
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - allocatedBytesBefore;

        Assert.True(found);
        Assert.NotNull(recordSet);
        Assert.Equal(0, allocatedBytes);
    }
}
