using DnsServerKit.Internal.Protocol;

namespace DnsServerKit.Internal.Lookup;

internal sealed class DnsNameComparer : IEqualityComparer<DnsName>, IAlternateEqualityComparer<DnsNameLookup, DnsName>
{
    public static DnsNameComparer Instance { get; } = new();

    private DnsNameComparer()
    {
    }

    public DnsName Create(DnsNameLookup alternate)
    {
        return DnsName.FromWire(alternate.EncodedName);
    }

    public bool Equals(DnsNameLookup alternate, DnsName other)
    {
        return alternate.HashCode == other.WireHashCode && other.WireEquals(alternate.EncodedName);
    }

    public int GetHashCode(DnsNameLookup alternate)
    {
        return alternate.HashCode;
    }

    public bool Equals(DnsName? first, DnsName? second)
    {
        if (ReferenceEquals(first, second))
            return true;

        return first is not null && first.Equals(second);
    }

    public int GetHashCode(DnsName name)
    {
        return name.WireHashCode;
    }
}
