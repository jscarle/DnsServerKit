namespace DnsServerKit.Records;

/// <summary>Represents a passive text record model.</summary>
public sealed class TxtRecord
{
    public required string Text { get; init; }
}
