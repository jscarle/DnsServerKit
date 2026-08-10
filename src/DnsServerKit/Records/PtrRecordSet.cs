namespace DnsServerKit.Records;

/// <summary>Represents a passive PTR resource record set model.</summary>
public sealed class PtrRecordSet : RecordSet
{
    public override required string Name { get; init; }

    public override required uint Ttl { get; init; }

    public required IReadOnlyCollection<PtrRecord> Records { get; init; }

    public override int Count => Records.Count;
}
