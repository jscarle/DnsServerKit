using System.Buffers.Binary;
using System.Net;
using System.Text;
using BenchmarkDotNet.Attributes;
using DnsServerKit.Data;
using DnsServerKit.Parameters;
using DnsServerKit.Queries;
using DnsServerKit.ResourceRecords;
using DnsServerKit.Responses;

namespace DnsServerKit.Benchmarks;

// ReSharper disable UnusedAutoPropertyAccessor.Global
[MemoryDiagnoser]
public class DnsPipelineBenchmarks
{
    private readonly byte[] _buffer = new byte[512];
    private readonly DnsQueryContext _query = new();
    private readonly DnsResponseContext _response = new();
    private byte[] _queryBytes = null!;
    private DnsDataSet _dataSet = null!;
    private Dictionary<string, int> _stringLookup = null!;

    [Params(1_000, 100_000, 1_000_000)]
    public int DataSetSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        var builder = new DnsDataSetBuilder();
        _stringLookup = new Dictionary<string, int>(DataSetSize, StringComparer.Ordinal);
        var ipAddress = IPAddress.Parse("192.0.2.1");
        DnsName? queriedName = null;

        for (var nameIndex = 0; nameIndex < DataSetSize; nameIndex++)
        {
            var name = new DnsName($"host{nameIndex}.example.com");
            builder.Add(new ARecord(name, ipAddress, 300));
            var stringKey = Encoding.Latin1.GetString(name.WireBytes);
            _stringLookup.Add(stringKey, nameIndex);
            queriedName = name;
        }

        _dataSet = builder.Build();
        var queryName = queriedName ?? throw new InvalidOperationException("The benchmark dataset is empty.");
        var wireName = queryName.WireBytes;
        _queryBytes = new byte[12 + wireName.Length + 4];
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes, 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes.AsSpan(4), 1);
        wireName.CopyTo(_queryBytes.AsSpan(12));
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes.AsSpan(12 + wireName.Length), (ushort)RecordType.A);
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes.AsSpan(14 + wireName.Length), (ushort)DnsClass.Internet);
        _queryBytes.AsSpan().CopyTo(_buffer);
        _ = DnsReader.Read(_buffer.AsMemory(0, _queryBytes.Length), _query);
    }

    [Benchmark]
    public DnsReadOutcome Parse()
    {
        _queryBytes.AsSpan().CopyTo(_buffer);
        return DnsReader.Read(_buffer.AsMemory(0, _queryBytes.Length), _query).Outcome;
    }

    [Benchmark]
    public bool FrozenWireLookup() => _dataSet.TryResolve(_query.Question, out _);

    [Benchmark]
    public bool AllocatingStringLookup()
    {
        var key = Encoding.Latin1.GetString(_query.Question.EncodedName);
        return _stringLookup.TryGetValue(key, out _);
    }

    [Benchmark]
    public int ParseLookupWrite()
    {
        _queryBytes.AsSpan().CopyTo(_buffer);
        _ = DnsReader.Read(_buffer.AsMemory(0, _queryBytes.Length), _query);
        _ = _dataSet.TryResolve(_query.Question, out var answerSet);
        _response.Set(_query, answerSet, ResponseCode.NoError, false, true);
        return DnsWriter.Write(_buffer, _response);
    }
}
