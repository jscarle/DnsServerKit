namespace DnsServerKit.Zones;

/// <summary>Represents an immutable, passive snapshot of DNS zones.</summary>
public sealed class DnsZoneSet
{
    public IReadOnlyCollection<DnsZone> Zones { get; }
    internal static DnsZoneSet Empty { get; } = new(Array.AsReadOnly(Array.Empty<DnsZone>()));

    internal DnsZoneSet(IReadOnlyCollection<DnsZone> zones)
    {
        Zones = zones;
    }
}
