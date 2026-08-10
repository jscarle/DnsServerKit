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

[MemoryDiagnoser]
public class DnsWriterBenchmarks
{
    private readonly byte[] _buffer = new byte[512];
    private readonly DnsQueryContext _query = new();
    private readonly DnsResponseContext _response = new();
    private byte[] _queryBytes = null!;
    private DnsResponse _materializedResponse = null!;

    [GlobalSetup]
    public void Setup()
    {
        var name = new DnsName("benchmark.example.com");
        var builder = new DnsDataSetBuilder();
        builder.Add(new ARecord(name, IPAddress.Parse("192.0.2.1"), 300));
        var dataSet = builder.Build();

        var wireName = name.WireBytes;
        _queryBytes = new byte[12 + wireName.Length + 4];
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes, 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes.AsSpan(4), 1);
        wireName.CopyTo(_queryBytes.AsSpan(12));
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes.AsSpan(12 + wireName.Length), (ushort)RecordType.A);
        BinaryPrimitives.WriteUInt16BigEndian(_queryBytes.AsSpan(14 + wireName.Length), (ushort)DnsClass.Internet);
        _queryBytes.CopyTo(_buffer, 0);
        _ = DnsReader.Read(_buffer.AsMemory(0, _queryBytes.Length), _query);
        _ = dataSet.TryResolve(_query.Question, out var answerSet);
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
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6), (ushort)_materializedResponse.Answers.Count);
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

        foreach (var answer in _materializedResponse.Answers)
        {
            var answerLabels = answer.Name.Value.Split('.', StringSplitOptions.RemoveEmptyEntries);
            var answerName = string.Join('.', answerLabels);
            var answerHeader = new byte[12];
            var namePosition = namePositions[answerName];
            BinaryPrimitives.WriteUInt16BigEndian(answerHeader, checked((ushort)(0xC000 | namePosition)));
            BinaryPrimitives.WriteUInt16BigEndian(answerHeader.AsSpan(2), answer.Type);
            BinaryPrimitives.WriteUInt16BigEndian(answerHeader.AsSpan(4), answer.Class);
            BinaryPrimitives.WriteUInt32BigEndian(answerHeader.AsSpan(6), answer.Ttl);
            BinaryPrimitives.WriteUInt16BigEndian(answerHeader.AsSpan(10), checked((ushort)answer.ResourceData.Length));
            memoryStream.Write(answerHeader);
            memoryStream.Write(answer.ResourceData);
        }

        return checked((int)memoryStream.Length);
    }

    [Benchmark]
    public int PrecomputedRecordSetSerialization()
    {
        _queryBytes.CopyTo(_buffer, 0);
        return DnsWriter.Write(_buffer, _response);
    }
}
