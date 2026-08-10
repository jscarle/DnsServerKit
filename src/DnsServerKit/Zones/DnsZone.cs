using DnsServerKit.Parameters;
using DnsServerKit.Records;

namespace DnsServerKit.Zones;

/// <summary>Represents a passive authoritative DNS zone as a flat collection of resource record sets.</summary>
public sealed class DnsZone
{
    public required string Name { get; init; }

    public required DnsClass Class { get; init; }

    public required IReadOnlyCollection<RecordSet> RecordSets { get; init; }
}
