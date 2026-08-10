namespace DnsServerKit.Records;

/// <summary>Represents a passive SOA resource record set model.</summary>
public sealed class SoaRecordSet : RecordSet
{
    public override required string Name { get; init; }

    public override required uint Ttl { get; init; }

    public required SoaRecord Record { get; init; }

    public override int Count => 1;
}
