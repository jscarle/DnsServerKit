using System.Net;
using DnsServerKit.Parameters;

namespace DnsServerKit.ResourceRecords;

public sealed record PtrRecord : IResourceRecord
{
    /// <inheritdoc/>
    public required string Name { get; init; }
    
    /// <inheritdoc/>
    public RecordType Type => RecordType.A;
    
    /// <inheritdoc/>
    public DnsClass Class => DnsClass.Internet;
    
    /// <inheritdoc/>
    public uint Ttl { get; init; }
}
