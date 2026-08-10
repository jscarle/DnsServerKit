namespace DnsServerKit.Records;

/// <summary>Represents a passive model for a complete DNS resource record set.</summary>
public abstract class RecordSet
{
    public abstract string Name { get; init; }

    public abstract uint Ttl { get; init; }

    public abstract int Count { get; }
}
