using System.Collections.Frozen;
using DnsServerKit.Queries;

namespace DnsServerKit.Data;

/// <summary>Represents an immutable, lookup-optimized DNS dataset snapshot.</summary>
public sealed class DnsDataSet
{
    private readonly FrozenDictionary<DnsRecordKey, DnsRecordSet> _recordSets;

    public int RecordSetCount => _recordSets.Count;

    internal DnsDataSet(FrozenDictionary<DnsRecordKey, DnsRecordSet> recordSets)
    {
        _recordSets = recordSets;
    }

    public bool TryGet(DnsName name, ushort type, ushort @class, out DnsRecordSet? recordSet)
    {
        ArgumentNullException.ThrowIfNull(name);

        var key = new DnsRecordKey(name, type, @class);
        return _recordSets.TryGetValue(key, out recordSet);
    }

    public bool TryResolve(DnsQuestionContext question, out DnsRecordSet? recordSet)
    {
        ArgumentNullException.ThrowIfNull(question);

        var alternateLookup = _recordSets.GetAlternateLookup<DnsQuestionLookup>();
        var questionLookup = new DnsQuestionLookup(question);
        return alternateLookup.TryGetValue(questionLookup, out recordSet);
    }
}
