namespace DnsServerKit.Records;

/// <summary>Represents a passive IPv6 address record model.</summary>
public sealed class AaaaRecord
{
    public required string Address { get; init; }
}
