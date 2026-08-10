namespace DnsServerKit.Records;

/// <summary>Represents a passive A resource record set model.</summary>
public sealed class ARecordSet : RecordSet
{
    public override required string Name { get; init; }

    public override required uint Ttl { get; init; }

    public required IReadOnlyCollection<ARecord> Records { get; init; }

    public override int Count => Records.Count;
}
