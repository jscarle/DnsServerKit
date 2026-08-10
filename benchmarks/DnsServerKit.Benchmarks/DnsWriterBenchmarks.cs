using System.Buffers.Binary;
using System.Text;
using BenchmarkDotNet.Attributes;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Internal.Responses;
using DnsServerKit.Parameters;
using DnsServerKit.Records;
using DnsServerKit.Zones;

namespace DnsServerKit.Benchmarks;

[MemoryDiagnoser]
public class DnsWriterBenchmarks
{
    private readonly byte[] _buffer = new byte[512];
    private readonly DnsQueryContext _query = new();
    private readonly DnsResponseContext _response = new();
    private byte[] _queryBytes = null!;
    private DnsResponse _materializedResponse = null!;
    private DnsName _answerName = null!;
    private byte[] _answerResourceData = null!;

    [GlobalSetup]
    public void Setup()
    {
        _answerName = new DnsName("benchmark.example.com");
        _answerResourceData = [192, 0, 2, 1];
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
        zoneBuilder.AddRecordSet(new ARecordSet
        {
            Name = "benchmark",
            Ttl = 300,
            Records = [new ARecord { Address = "192.0.2.1" }],
        });
        var zoneSetBuilder = new DnsZoneSetBuilder();
        zoneSetBuilder.Load(zoneBuilder);
        var zoneSet = zoneSetBuilder.Build();
        var store = new DnsZoneStore();
        store.Load(zoneSet);

        var wireName = _answerName.WireBytes;
        _queryBytes = new byte[12 + wireName.Length + 4];
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes, 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes.AsSpan(4), 1);
        wireName.CopyTo(_queryBytes.AsSpan(12));
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes.AsSpan(12 + wireName.Length), (ushort)RecordType.A);
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes.AsSpan(14 + wireName.Length), (ushort)DnsClass.Internet);
        _queryBytes.CopyTo(_buffer, 0);
        _ = DnsReader.Read(_buffer.AsMemory(0, _queryBytes.Length), _query);
        _ = store.TryResolve(_query.Question, out var answerSet);
        _response.Set(_query, answerSet, ResponseCode.NoError, false, true);
        _materializedResponse = _response.Materialize();
    }

    [Benchmark(Baseline = true)]
    public int LegacyManagedSerialization()
    {
        using var memoryStream = new MemoryStream(512);
        var namePositions = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var header = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, _materializedResponse.Query.TransactionId);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), 0x8080);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), 1);
        var answerCount = _materializedResponse.AnswerSet?.Count ?? 0;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6), (ushort)answerCount);
        memoryStream.Write(header);

        var question = _materializedResponse.Query.Question;
        var labels = question.Name.Value.Split('.', StringSplitOptions.RemoveEmptyEntries);
        for (var labelIndex = 0; labelIndex < labels.Length; labelIndex++)
        {
            var suffix = string.Join('.', labels, labelIndex, labels.Length - labelIndex);
            namePositions.Add(suffix, checked((int)memoryStream.Position));
            var labelBytes = Encoding.ASCII.GetBytes(labels[labelIndex]);
            memoryStream.WriteByte((byte)labelBytes.Length);
            memoryStream.Write(labelBytes);
        }

        memoryStream.WriteByte(0);
        var questionFields = new byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(questionFields, question.Type);
        BinaryPrimitives.WriteUInt16BigEndian(questionFields.AsSpan(2), question.Class);
        memoryStream.Write(questionFields);

        var answerLabels = _answerName.Value.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var answerName = string.Join('.', answerLabels);
        var answerHeader = new byte[12];
        var namePosition = namePositions[answerName];
        BinaryPrimitives.WriteUInt16BigEndian(answerHeader, checked((ushort)(0xC000 | namePosition)));
        BinaryPrimitives.WriteUInt16BigEndian(answerHeader.AsSpan(2), (ushort)RecordType.A);
        BinaryPrimitives.WriteUInt16BigEndian(answerHeader.AsSpan(4), (ushort)DnsClass.Internet);
        BinaryPrimitives.WriteUInt32BigEndian(answerHeader.AsSpan(6), 300);
        BinaryPrimitives.WriteUInt16BigEndian(answerHeader.AsSpan(10), checked((ushort)_answerResourceData.Length));
        memoryStream.Write(answerHeader);
        memoryStream.Write(_answerResourceData);

        return checked((int)memoryStream.Length);
    }

    [Benchmark]
    public int DirectSpanRecordSetSerialization()
    {
        _queryBytes.CopyTo(_buffer, 0);
        return DnsWriter.Write(_buffer, _response);
    }
}
