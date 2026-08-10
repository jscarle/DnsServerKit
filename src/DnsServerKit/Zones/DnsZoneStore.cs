using System.Collections.Frozen;
using DnsServerKit.Internal.Lookup;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Records;
using DnsOwnerIndex =
    System.Collections.Frozen.FrozenDictionary<DnsServerKit.Internal.Protocol.DnsName,
        System.Collections.Frozen.FrozenDictionary<ushort, DnsServerKit.Records.RecordSet>>;

namespace DnsServerKit.Zones;

/// <summary>Publishes DNS zone-set snapshots and their lookup indexes to concurrent readers.</summary>
public sealed class DnsZoneStore
{
    public DnsZoneSet Current =>
        Volatile.Read(ref _state)
            .ZoneSet;

    private StoreState _state = CreateState(DnsZoneSet.Empty);

    public void Load(DnsZoneSet zoneSet)
    {
        ArgumentNullException.ThrowIfNull(zoneSet);

        var state = CreateState(zoneSet);
        Volatile.Write(ref _state, state);
    }

    internal bool TryGet(DnsName name, ushort type, ushort @class, out RecordSet? recordSet)
    {
        ArgumentNullException.ThrowIfNull(name);

        var state = Volatile.Read(ref _state);
        if (!TryFindZone(state, name.WireBytes, @class, out var ownerRecordSets) || !ownerRecordSets.TryGetValue(name, out var recordSets))
        {
            recordSet = null;
            return false;
        }

        return recordSets.TryGetValue(type, out recordSet);
    }

    internal bool TryResolve(DnsQuestionContext question, out RecordSet? recordSet)
    {
        ArgumentNullException.ThrowIfNull(question);

        var state = Volatile.Read(ref _state);
        if (!TryFindZone(state, question.EncodedName, question.Class, out var ownerRecordSets))
        {
            recordSet = null;
            return false;
        }

        var ownerLookup = new DnsNameLookup(question.EncodedName, question.NameHashCode);
        var alternateLookup = ownerRecordSets.GetAlternateLookup<DnsNameLookup>();
        if (!alternateLookup.TryGetValue(ownerLookup, out var recordSets))
        {
            recordSet = null;
            return false;
        }

        return recordSets.TryGetValue(question.Type, out recordSet);
    }

    private static StoreState CreateState(DnsZoneSet zoneSet)
    {
        var zoneIndexes = new Dictionary<DnsZoneKey, DnsOwnerIndex>(DnsZoneKeyComparer.Instance);

        foreach (var zone in zoneSet.Zones)
        {
            var apex = new DnsName(zone.Name);
            var mutableOwnerRecordSets = new Dictionary<DnsName, Dictionary<ushort, RecordSet>>(DnsNameComparer.Instance);

            foreach (var recordSet in zone.RecordSets)
            {
                var type = recordSet switch
                {
                    ARecordSet => (ushort)RecordType.A,
                    PtrRecordSet => (ushort)RecordType.Ptr,
                    NsRecordSet => (ushort)RecordType.Ns,
                    SoaRecordSet => (ushort)RecordType.Soa,
                    _ => throw new NotSupportedException($"The '{recordSet.GetType().Name}' DNS record set type is not supported."),
                };

                DnsName ownerName;
                if (recordSet.Name.Equals("@", StringComparison.Ordinal))
                {
                    ownerName = apex;
                }
                else
                {
                    var ownerNameValue = apex.Value.Equals(".", StringComparison.Ordinal) ? recordSet.Name : $"{recordSet.Name}.{apex.Value}";
                    ownerName = new DnsName(ownerNameValue);
                }

                if (!mutableOwnerRecordSets.TryGetValue(ownerName, out var recordSets))
                {
                    recordSets = new Dictionary<ushort, RecordSet>();
                    mutableOwnerRecordSets.Add(ownerName, recordSets);
                }

                recordSets.Add(type, recordSet);
            }

            var ownerRecordSets = new Dictionary<DnsName, FrozenDictionary<ushort, RecordSet>>(mutableOwnerRecordSets.Count, DnsNameComparer.Instance);
            foreach (var entry in mutableOwnerRecordSets)
                ownerRecordSets.Add(entry.Key, entry.Value.ToFrozenDictionary());

            var frozenOwnerRecordSets = ownerRecordSets.ToFrozenDictionary(DnsNameComparer.Instance);
            var zoneKey = new DnsZoneKey(apex, (ushort)zone.Class);
            zoneIndexes.Add(zoneKey, frozenOwnerRecordSets);
        }

        var frozenZoneIndexes = zoneIndexes.ToFrozenDictionary(DnsZoneKeyComparer.Instance);
        return new StoreState(zoneSet, frozenZoneIndexes);
    }

    private static bool TryFindZone(StoreState state, ReadOnlySpan<byte> encodedName, ushort @class, out DnsOwnerIndex ownerRecordSets)
    {
        var alternateLookup = state.ZoneIndexes.GetAlternateLookup<DnsZoneLookup>();
        var labelOffset = 0;

        while (true)
        {
            var encodedApex = encodedName[labelOffset..];
            var apexHashCode = DnsName.ComputeWireHash(encodedApex);
            var zoneLookup = new DnsZoneLookup(encodedApex, @class, apexHashCode);
            if (alternateLookup.TryGetValue(zoneLookup, out ownerRecordSets!))
                return true;

            var labelLength = encodedName[labelOffset];
            if (labelLength == 0)
            {
                ownerRecordSets = null!;
                return false;
            }

            labelOffset += labelLength + 1;
        }
    }

    private sealed class StoreState(DnsZoneSet zoneSet, FrozenDictionary<DnsZoneKey, DnsOwnerIndex> zoneIndexes)
    {
        public DnsZoneSet ZoneSet { get; } = zoneSet;

        public FrozenDictionary<DnsZoneKey, DnsOwnerIndex> ZoneIndexes { get; } = zoneIndexes;
    }
}
