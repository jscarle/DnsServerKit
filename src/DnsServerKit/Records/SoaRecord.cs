namespace DnsServerKit.Records;

/// <summary>Represents a passive start-of-authority record model.</summary>
public sealed class SoaRecord
{
    public required string PrimaryNameServer { get; init; }

    public required string ResponsibleMailbox { get; init; }

    public required uint Serial { get; init; }

    public required uint Refresh { get; init; }

    public required uint Retry { get; init; }

    public required uint Expire { get; init; }

    public required uint Minimum { get; init; }
}
