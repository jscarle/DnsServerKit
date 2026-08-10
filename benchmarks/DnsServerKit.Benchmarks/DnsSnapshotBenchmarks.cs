using BenchmarkDotNet.Attributes;
using DnsServerKit.Records;
using DnsServerKit.Zones;

namespace DnsServerKit.Benchmarks;

// ReSharper disable UnusedAutoPropertyAccessor.Global
[MemoryDiagnoser]
public class DnsSnapshotBenchmarks
{
    private string[] _names = null!;

    [Params(1_000, 100_000, 1_000_000)]
    public int RecordSetCount { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _names = new string[RecordSetCount];
        for (var recordIndex = 0; recordIndex < _names.Length; recordIndex++)
            _names[recordIndex] = $"host{recordIndex}";
    }

    [Benchmark]
    public DnsZoneSet BuildAndLoadSnapshot()
    {
        var zoneBuilder = new DnsZoneBuilder("example.com");
        zoneBuilder.AddRecordSet(new SoaRecordSet
        {
            Name = "@",
            Ttl = 300,
            Record = new SoaRecord
            {
                PrimaryNameServer = "ns1.example.com",
                ResponsibleMailbox = "hostmaster@example.com",
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
            Ttl = 300,
            Records = [new NsRecord { NameServer = "ns1.example.com" }],
        });
        foreach (var name in _names)
        {
            zoneBuilder.AddRecordSet(new ARecordSet
            {
                Name = name,
                Ttl = 300,
                Records = [new ARecord { Address = "192.0.2.1" }],
            });
        }

        var zoneSetBuilder = new DnsZoneSetBuilder();
        zoneSetBuilder.Load(zoneBuilder);
        var zoneSet = zoneSetBuilder.Build();
        var store = new DnsZoneStore();
        store.Load(zoneSet);

        return store.Current;
    }
}
