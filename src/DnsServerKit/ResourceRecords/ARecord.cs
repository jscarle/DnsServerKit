using System.Net;

namespace DnsServerKit.ResourceRecords;

public sealed class ARecord : ResourceRecord
{
    public string Name { get; }
    public RRType Type { get; }
    public DnsClass Class { get; }
    public int TTL { get; }
    public IPAddress IpAddress { get; }

    public ARecord(string name, RRType type, DnsClass @class, int ttl, IPAddress ipAddress)
    {
        Name = name;
        Type = type;
        Class = @class;
        TTL = ttl;
        IpAddress = ipAddress;
    }

    public override ReadOnlyMemory<byte> ToBytes()
    {
        var dnsName = DnsEncodeName(Name);
        var type = BitConverter.GetBytes((ushort)Type);
        var @class = BitConverter.GetBytes((ushort)Class);
        var ttl = BitConverter.GetBytes(TTL);
        var size = BitConverter.GetBytes(4);
        var ipAddress = IpAddress.GetAddressBytes();

        var length = dnsName.Length + type.Length + @class.Length + ttl.Length + size.Length + ipAddress.Length;

        var bytes = new byte[length];

        var offset = 0;
        
        Buffer.BlockCopy(dnsName, 0, bytes, offset, dnsName.Length);
        offset += dnsName.Length;

        Buffer.BlockCopy(type, 0, bytes, offset, type.Length);
        offset += type.Length;

        Buffer.BlockCopy(@class, 0, bytes, offset, @class.Length);
        offset += @class.Length;

        Buffer.BlockCopy(ttl, 0, bytes, offset, ttl.Length);
        offset += ttl.Length;

        Buffer.BlockCopy(size, 0, bytes, offset, size.Length);
        offset += size.Length;

        Buffer.BlockCopy(ipAddress, 0, bytes, offset, ipAddress.Length);

        return new ReadOnlyMemory<byte>(bytes);
    }
}
