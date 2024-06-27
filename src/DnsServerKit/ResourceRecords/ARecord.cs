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
    public int Ttl { get; init; }

    /// <summary>
    /// Gets the IP address for the resource record.
    /// </summary>
    public required IPAddress IpAddress { get; init; }
    
    /// <inheritdoc/>
    public ReadOnlyMemory<byte> ResourceData
    {
        get
        {
            // Encode the DNS name
            var nameBytes = NameHelper.EncodeDnsName(Name);

            // Encode the IP address
            var ipAddressBytes = IpAddress.GetAddressBytes();

            // Create the resource record data array with space for the name, type, class, ttl, and data
            var rrData = new byte[nameBytes.Length + ipAddressBytes.Length + 10]; // 10 bytes for type, class, ttl, data length

            // Copy the encoded name into the resource record data array
            Buffer.BlockCopy(nameBytes, 0, rrData, 0, nameBytes.Length);

            // Encode Type
            BinaryPrimitives.WriteUInt16BigEndian(rrData.AsSpan(nameBytes.Length, 2), (ushort)Type);

            // Encode Class
            BinaryPrimitives.WriteUInt16BigEndian(rrData.AsSpan(nameBytes.Length + 2, 2), (ushort)Class);

            // Encode TTL (Time to Live)
            BinaryPrimitives.WriteInt32BigEndian(rrData.AsSpan(nameBytes.Length + 4, 4), Ttl);

            // Encode data length
            BinaryPrimitives.WriteUInt16BigEndian(rrData.AsSpan(nameBytes.Length + 8, 2), (ushort)ipAddressBytes.Length);

            // Copy the encoded IP address into the resource record data array
            Buffer.BlockCopy(ipAddressBytes, 0, rrData, nameBytes.Length + 10, ipAddressBytes.Length);

            return new ReadOnlyMemory<byte>(rrData);
        }
    }
}
