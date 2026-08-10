using DnsServerKit.Parameters;

namespace DnsServerKit.ResourceRecords;

/// <summary>Represents an immutable domain-name pointer record.</summary>
public sealed class PtrRecord : DnsResourceRecord
{
    public DnsName TargetName { get; }

    public PtrRecord(DnsName name, DnsName targetName, uint ttl = 0, ushort @class = (ushort)DnsClass.Internet)
        : base(
            name,
            (ushort)RecordType.Ptr,
            @class,
            ttl,
            (targetName ?? throw new ArgumentNullException(nameof(targetName))).WireBytes)
    {
        TargetName = targetName;
    }
}
