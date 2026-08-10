using DnsServerKit.Internal.Lookup;
using DnsServerKit.Internal.Protocol;

namespace DnsServerKit.Zones;

/// <summary>Builds immutable DNS zone-set snapshots from DNS zone models.</summary>
public sealed class DnsZoneSetBuilder
{
    private readonly Dictionary<DnsZoneKey, DnsZone> _zones = new(DnsZoneKeyComparer.Instance);
    private readonly Dictionary<DnsZoneKey, DnsZoneBuilder> _zoneBuilders = new(DnsZoneKeyComparer.Instance);

    public void Load(DnsZone dnsZone)
    {
        ArgumentNullException.ThrowIfNull(dnsZone);

        var ownedZone = CreateOwnedZone(dnsZone);
        var key = new DnsZoneKey(new DnsName(ownedZone.Name), (ushort)ownedZone.Class);
        _zoneBuilders.Remove(key);
        _zones[key] = ownedZone;
    }

    public void Load(DnsZoneBuilder dnsZoneBuilder)
    {
        ArgumentNullException.ThrowIfNull(dnsZoneBuilder);

        var key = new DnsZoneKey(dnsZoneBuilder.CanonicalApex, (ushort)dnsZoneBuilder.Class);
        _zones.Remove(key);
        _zoneBuilders[key] = dnsZoneBuilder;
    }

    public DnsZoneSet Build()
    {
        var mergedZones = new Dictionary<DnsZoneKey, DnsZone>(_zones, DnsZoneKeyComparer.Instance);
        foreach (var entry in _zoneBuilders)
            mergedZones[entry.Key] = entry.Value.Build();

        var zones = Array.AsReadOnly(mergedZones.Values.ToArray());
        return new DnsZoneSet(zones);
    }

    private static DnsZone CreateOwnedZone(DnsZone dnsZone)
    {
        if (dnsZone.RecordSets is null)
            throw new ArgumentException("A DNS zone requires resource record sets.", nameof(dnsZone));

        var zoneBuilder = new DnsZoneBuilder(dnsZone.Name, dnsZone.Class);
        foreach (var recordSet in dnsZone.RecordSets)
            zoneBuilder.AddRecordSet(recordSet);

        return zoneBuilder.Build();
    }
}
