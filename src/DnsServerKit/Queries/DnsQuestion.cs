using DnsServerKit.Parameters;

namespace DnsServerKit.Queries;

/// <summary>Represents a DNS question.</summary>
public sealed record DnsQuestion
{
    /// <summary>Gets the name that is the subject of the DNS query.</summary>
    public required string Name { get; init; }

    /// <summary>Gets the type of DNS record being queried.</summary>
    public required RecordType Type { get; init; }

    /// <summary>Gets the class of the DNS query.</summary>
    public required DnsClass Class { get; init; }
}
