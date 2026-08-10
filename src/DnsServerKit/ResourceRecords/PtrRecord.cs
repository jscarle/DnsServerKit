using DnsServerKit.Parameters;

namespace DnsServerKit.ResourceRecords;

public sealed record PtrRecord : IResourceRecord
{
    /// <inheritdoc/>
    public required string Name { get; init; }
    
    /// <inheritdoc/>
    public RecordType Type => RecordType.Ptr;
    
    /// <inheritdoc/>
    public DnsClass Class => DnsClass.Internet;
    
    /// <inheritdoc/>
    public uint Ttl { get; init; }

    /// <summary>
    /// Gets the target domain name for the resource record.
    /// </summary>
    public required string TargetName { get; init; }
}
