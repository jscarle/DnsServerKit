namespace DnsServerKit.Records;

/// <summary>Represents a passive AAAA resource record set model.</summary>
public sealed class AaaaRecordSet : RecordSet
{
    public override required string Name { get; init; }

    public override required uint Ttl { get; init; }

    public required IReadOnlyCollection<AaaaRecord> Records { get; init; }

    public override int Count => Records.Count;
}
