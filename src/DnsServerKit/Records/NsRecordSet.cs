namespace DnsServerKit.Records;

/// <summary>Represents a passive NS resource record set model.</summary>
public sealed class NsRecordSet : RecordSet
{
    public override required string Name { get; init; }

    public override required uint Ttl { get; init; }

    public required IReadOnlyCollection<NsRecord> Records { get; init; }

    public override int Count => Records.Count;
}
