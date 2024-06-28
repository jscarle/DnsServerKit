using System.Buffers.Binary;
using System.Net;
using DnsServerKit.Parameters;

namespace DnsServerKit.ResourceRecords;

public sealed record ARecord : IResourceRecord
{
    /// <inheritdoc/>
    public required string Name { get; init; }
    
    /// <inheritdoc/>
    public RecordType Type => RecordType.A;
    
    /// <inheritdoc/>
    public DnsClass Class => DnsClass.Internet;
    
    /// <inheritdoc/>
    public uint Ttl { get; init; }

    /// <summary>
    /// Gets the IP address for the resource record.
    /// </summary>
    public required IPAddress IpAddress { get; init; }
}
