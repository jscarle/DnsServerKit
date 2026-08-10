namespace DnsServerKit.Records;

/// <summary>Represents a passive IPv4 address record model.</summary>
public sealed class ARecord
{
    public required string Address { get; init; }
}
