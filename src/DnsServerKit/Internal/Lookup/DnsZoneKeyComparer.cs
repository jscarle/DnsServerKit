using DnsServerKit.Internal.Protocol;

namespace DnsServerKit.Internal.Lookup;

internal sealed class DnsZoneKeyComparer : IEqualityComparer<DnsZoneKey>, IAlternateEqualityComparer<DnsZoneLookup, DnsZoneKey>
{
    public static DnsZoneKeyComparer Instance { get; } = new();

    private DnsZoneKeyComparer()
    {
    }

    public DnsZoneKey Create(DnsZoneLookup alternate)
    {
        var apex = DnsName.FromWire(alternate.EncodedApex);
        return new DnsZoneKey(apex, alternate.Class);
    }

    public bool Equals(DnsZoneLookup alternate, DnsZoneKey other)
    {
        return alternate.HashCode == other.HashCode && alternate.Class == other.Class && other.Apex.WireEquals(alternate.EncodedApex);
    }

    public int GetHashCode(DnsZoneLookup alternate)
    {
        return alternate.HashCode;
    }

    public bool Equals(DnsZoneKey? first, DnsZoneKey? second)
    {
        if (ReferenceEquals(first, second))
            return true;

        return first is not null && second is not null && first.HashCode == second.HashCode && first.Class == second.Class && first.Apex.Equals(second.Apex);
    }

    public int GetHashCode(DnsZoneKey key)
    {
        return key.HashCode;
    }
}
