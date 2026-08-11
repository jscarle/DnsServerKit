using System.Buffers.Binary;
using System.Text;
using BenchmarkDotNet.Attributes;
using DnsServerKit.Internal.Lookup;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Internal.Responses;
using DnsServerKit.Parameters;
using DnsServerKit.Records;
using DnsServerKit.Zones;

namespace DnsServerKit.Benchmarks;

// ReSharper disable UnusedAutoPropertyAccessor.Global
[MemoryDiagnoser]
public class DnsPipelineBenchmarks
{
    private readonly byte[] _buffer = new byte[512];
    private readonly DnsQueryContext _query = new();
    private readonly DnsResolutionContext _resolution = new();
    private readonly DnsResponseContext _response = new();
    private byte[] _anyQueryBytes = null!;
    private byte[] _cnameQueryBytes = null!;
    private byte[] _noDataQueryBytes = null!;
    private byte[] _nxDomainQueryBytes = null!;
    private byte[] _queryBytes = null!;
    private byte[] _referralQueryBytes = null!;
    private DnsZoneStore _store = null!;
    private Dictionary<string, int> _stringLookup = null!;

    [Params(1_000, 100_000, 1_000_000)]
    public int RecordSetCount { get; set; }

    [GlobalSetup]
    public void Setup()
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
        _stringLookup = new Dictionary<string, int>(RecordSetCount, StringComparer.Ordinal);
        DnsName? queriedName = null;

        for (var nameIndex = 0; nameIndex < RecordSetCount; nameIndex++)
        {
            var name = $"host{nameIndex}";
            var dnsName = new DnsName($"{name}.example.com");
            zoneBuilder.AddRecordSet(new ARecordSet
            {
                Name = name,
                Ttl = 300,
                Records = [new ARecord { Address = "192.0.2.1" }],
            });
            var stringKey = Encoding.Latin1.GetString(dnsName.WireBytes);
            _stringLookup.Add(stringKey, nameIndex);
            queriedName = dnsName;
        }

        var queryName = queriedName ?? throw new InvalidOperationException("The benchmark zone is empty.");
        zoneBuilder.AddCnameRecord(300, "alias", queryName.Value);
        zoneBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "child",
            Ttl = 300,
            Records = [new NsRecord { NameServer = "ns1.child.example.com" }],
        });
        zoneBuilder.AddARecord(300, "ns1.child", "192.0.2.2");

        var zoneSetBuilder = new DnsZoneSetBuilder();
        zoneSetBuilder.Load(zoneBuilder);
        var zoneSet = zoneSetBuilder.Build();
        _store = new DnsZoneStore();
        _store.Load(zoneSet);
        _queryBytes = CreateQuery(queryName, RecordType.A);
        _noDataQueryBytes = CreateQuery(queryName, RecordType.Aaaa);
        _nxDomainQueryBytes = CreateQuery(new DnsName("missing.example.com"), RecordType.A);
        _anyQueryBytes = CreateQuery(queryName, RecordType.All);
        _cnameQueryBytes = CreateQuery(new DnsName("alias.example.com"), RecordType.A);
        _referralQueryBytes = CreateQuery(new DnsName("www.child.example.com"), RecordType.A);
        _queryBytes.AsSpan().CopyTo(_buffer);
        _ = DnsReader.Read(_buffer.AsMemory(0, _queryBytes.Length), _query);
    }

    [Benchmark]
    public byte Parse()
    {
        _queryBytes.AsSpan().CopyTo(_buffer);
        return (byte)DnsReader.Read(_buffer.AsMemory(0, _queryBytes.Length), _query).Outcome;
    }

    [Benchmark]
    public bool StoreFrozenWireLookup() => _store.TryResolve(_query.Question, out _);

    [Benchmark]
    public bool AllocatingStringLookup()
    {
        var key = Encoding.Latin1.GetString(_query.Question.EncodedName);
        return _stringLookup.TryGetValue(key, out _);
    }

    [Benchmark(Baseline = true)]
    public int ParseLookupWrite()
    {
        _queryBytes.AsSpan().CopyTo(_buffer);
        _ = DnsReader.Read(_buffer.AsMemory(0, _queryBytes.Length), _query);
        _store.Resolve(_query.Question, _resolution);
        _response.Set(_query, _resolution);
        return DnsWriter.Write(_buffer, _response);
    }

    [Benchmark]
    public int ParseLookupWriteNoData() => ParseLookupWrite(_noDataQueryBytes);

    [Benchmark]
    public int ParseLookupWriteNxDomain() => ParseLookupWrite(_nxDomainQueryBytes);

    [Benchmark]
    public int ParseLookupWriteAny() => ParseLookupWrite(_anyQueryBytes);

    [Benchmark]
    public int ParseLookupWriteCname() => ParseLookupWrite(_cnameQueryBytes);

    [Benchmark]
    public int ParseLookupWriteReferral() => ParseLookupWrite(_referralQueryBytes);

    private int ParseLookupWrite(byte[] queryBytes)
    {
        queryBytes.AsSpan().CopyTo(_buffer);
        _ = DnsReader.Read(_buffer.AsMemory(0, queryBytes.Length), _query);
        _store.Resolve(_query.Question, _resolution);
        _response.Set(_query, _resolution);
        return DnsWriter.Write(_buffer, _response);
    }

    private static byte[] CreateQuery(DnsName name, RecordType type)
    {
        var wireName = name.WireBytes;
        var queryBytes = new byte[12 + wireName.Length + 4];
        BinaryPrimitives.WriteUInt16BigEndian(queryBytes, 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(queryBytes.AsSpan(4), 1);
        wireName.CopyTo(queryBytes.AsSpan(12));
        BinaryPrimitives.WriteUInt16BigEndian(queryBytes.AsSpan(12 + wireName.Length), (ushort)type);
        BinaryPrimitives.WriteUInt16BigEndian(queryBytes.AsSpan(14 + wireName.Length), (ushort)DnsClass.Internet);
        return queryBytes;
    }
}
