using System.Net;
using System.Net.Sockets;
using DnsServerKit.Parameters;

namespace DnsServerKit.ResourceRecords;

public sealed record ARecord : IResourceRecord
{
    private IPAddress _ipAddress = null!;

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
    public required IPAddress IpAddress
    {
        get => _ipAddress;
        init
        {
            ArgumentNullException.ThrowIfNull(value, nameof(IpAddress));
            if (value.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("An A record requires an IPv4 address.", nameof(IpAddress));

            _ipAddress = value;
        }
    }
}
