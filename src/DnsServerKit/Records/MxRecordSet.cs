namespace DnsServerKit.Records;

/// <summary>Represents a passive MX resource record set model.</summary>
public sealed class MxRecordSet : RecordSet
{
    public override required string Name { get; init; }

    public override required uint Ttl { get; init; }

    public required IReadOnlyCollection<MxRecord> Records { get; init; }

    public override int Count => Records.Count;
}
