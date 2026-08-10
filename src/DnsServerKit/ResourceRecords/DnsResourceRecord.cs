namespace DnsServerKit.ResourceRecords;

/// <summary>Represents an immutable DNS resource record stored in a dataset.</summary>
public abstract class DnsResourceRecord
{
    private readonly byte[] _resourceData;

    public DnsName Name { get; }

    public ushort Type { get; }

    public ushort Class { get; }

    public uint Ttl { get; }

    public ReadOnlySpan<byte> ResourceData => _resourceData;

    protected DnsResourceRecord(DnsName name, ushort type, ushort @class, uint ttl, ReadOnlySpan<byte> resourceData)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (resourceData.Length > ushort.MaxValue)
            throw new ArgumentException("DNS resource data cannot exceed 65,535 octets.", nameof(resourceData));

        Name = name;
        Type = type;
        Class = @class;
        Ttl = ttl;
        _resourceData = resourceData.ToArray();
    }
}
