namespace DnsServerKit.Records;

/// <summary>Represents a passive canonical-name record model.</summary>
public sealed class CnameRecord
{
    public required string Target { get; init; }
}
