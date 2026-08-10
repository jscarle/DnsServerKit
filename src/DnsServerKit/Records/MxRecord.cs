namespace DnsServerKit.Records;

/// <summary>Represents a passive mail-exchange record model.</summary>
public sealed class MxRecord
{
    public required ushort Preference { get; init; }

    public required string Exchange { get; init; }
}
