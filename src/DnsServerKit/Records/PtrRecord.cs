namespace DnsServerKit.Records;

/// <summary>Represents a passive domain-name pointer record model.</summary>
public sealed class PtrRecord
{
    public required string Target { get; init; }
}
