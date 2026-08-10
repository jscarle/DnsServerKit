using System.Net;
using BenchmarkDotNet.Attributes;
using DnsServerKit.Data;
using DnsServerKit.ResourceRecords;

namespace DnsServerKit.Benchmarks;

// ReSharper disable UnusedAutoPropertyAccessor.Global
[MemoryDiagnoser]
public class DnsSnapshotBenchmarks
{
    private DnsResourceRecord[] _records = null!;

    [Params(1_000, 100_000, 1_000_000)]
    public int DataSetSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _records = new DnsResourceRecord[DataSetSize];
        var ipAddress = IPAddress.Parse("192.0.2.1");
        for (var recordIndex = 0; recordIndex < _records.Length; recordIndex++)
        {
            var name = new DnsName($"host{recordIndex}.example.com");
            _records[recordIndex] = new ARecord(name, ipAddress, 300);
        }
    }

    [Benchmark]
    public DnsDataSet RebuildSnapshot()
    {
        var builder = new DnsDataSetBuilder();
        foreach (var record in _records)
            builder.Add(record);

        return builder.Build();
    }
}
