using DnsServerKit.Internal.Protocol;

namespace DnsServerKit.Internal.Lookup;

internal readonly ref struct DnsZoneLookup
{
    public ReadOnlySpan<byte> EncodedApex { get; }

    public ushort Class { get; }

    public int HashCode { get; }

    public DnsZoneLookup(ReadOnlySpan<byte> encodedApex, ushort @class, int apexHashCode)
    {
        EncodedApex = encodedApex;
        Class = @class;
        HashCode = DnsName.ComputeZoneHash(apexHashCode, @class);
    }
}
