namespace DnsServerKit.Records;

/// <summary>Represents a passive authoritative name-server record model.</summary>
public sealed class NsRecord
{
    public required string NameServer { get; init; }
}
