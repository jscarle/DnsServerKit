using DnsServerKit.Internal.Protocol;

namespace DnsServerKit.Internal.Lookup;

internal sealed class DnsZoneKey
{
    public DnsName Apex { get; }

    public ushort Class { get; }

    public int HashCode { get; }

    public DnsZoneKey(DnsName apex, ushort @class)
    {
        Apex = apex;
        Class = @class;
        HashCode = DnsName.ComputeZoneHash(apex.WireHashCode, @class);
    }
}
