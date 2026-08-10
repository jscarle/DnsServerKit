namespace DnsServerKit.Internal.Lookup;

internal readonly ref struct DnsNameLookup(ReadOnlySpan<byte> encodedName, int hashCode)
{
    public ReadOnlySpan<byte> EncodedName { get; } = encodedName;

    public int HashCode { get; } = hashCode;
}
