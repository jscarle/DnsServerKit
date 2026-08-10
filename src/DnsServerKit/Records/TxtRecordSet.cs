namespace DnsServerKit.Records;

/// <summary>Represents a passive TXT resource record set model.</summary>
public sealed class TxtRecordSet : RecordSet
{
    public override required string Name { get; init; }

    public override required uint Ttl { get; init; }

    public required IReadOnlyCollection<TxtRecord> Records { get; init; }

    public override int Count => Records.Count;
}
