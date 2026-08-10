namespace DnsServerKit.Records;

/// <summary>Represents a passive CNAME resource record set model.</summary>
public sealed class CnameRecordSet : RecordSet
{
    public override required string Name { get; init; }

    public override required uint Ttl { get; init; }

    public required CnameRecord Record { get; init; }

    public override int Count => 1;
}
