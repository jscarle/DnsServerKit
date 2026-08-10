using System.Collections.Frozen;
using DnsServerKit.ResourceRecords;

namespace DnsServerKit.Data;

/// <summary>Builds immutable DNS dataset snapshots from managed resource records.</summary>
public sealed class DnsDataSetBuilder
{
    private readonly Dictionary<DnsRecordKey, List<DnsResourceRecord>> _records = new(DnsRecordKeyComparer.Instance);

    public int RecordSetCount => _records.Count;

    public void Add(DnsResourceRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        var key = new DnsRecordKey(record.Name, record.Type, record.Class);
        if (!_records.TryGetValue(key, out var records))
        {
            records = [];
            _records.Add(key, records);
        }

        records.Add(record);
    }

    public DnsDataSet Build()
    {
        var recordSets = new Dictionary<DnsRecordKey, DnsRecordSet>(_records.Count, DnsRecordKeyComparer.Instance);
        foreach (var entry in _records)
        {
            var records = entry.Value.ToArray();
            recordSets.Add(entry.Key, new DnsRecordSet(records));
        }

        var frozenRecordSets = recordSets.ToFrozenDictionary(DnsRecordKeyComparer.Instance);
        return new DnsDataSet(frozenRecordSets);
    }
}
