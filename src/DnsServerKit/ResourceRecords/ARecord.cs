using System.Net;
using System.Net.Sockets;
using DnsServerKit.Parameters;

namespace DnsServerKit.ResourceRecords;

/// <summary>Represents an immutable IPv4 address record.</summary>
public sealed class ARecord : DnsResourceRecord
{
    public IPAddress IpAddress { get; }

    public ARecord(DnsName name, IPAddress ipAddress, uint ttl = 0, ushort @class = (ushort)DnsClass.Internet)
        : base(
            name,
            (ushort)RecordType.A,
            @class,
            ttl,
            (ipAddress ?? throw new ArgumentNullException(nameof(ipAddress))).AddressFamily == AddressFamily.InterNetwork
                ? ipAddress.GetAddressBytes()
                : throw new ArgumentException("An A record requires an IPv4 address.", nameof(ipAddress)))
    {
        IpAddress = ipAddress;
    }
}
