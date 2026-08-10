namespace DnsServerKit.ResourceRecords;

/// <summary>Represents an immutable resource record containing caller-supplied wire-format RDATA.</summary>
public sealed class RawResourceRecord : DnsResourceRecord
{
    public RawResourceRecord(DnsName name, ushort type, ushort @class, uint ttl, ReadOnlySpan<byte> resourceData)
        : base(name, type, @class, ttl, resourceData)
    {
    }
}
