namespace DnsServerKit.Internal.Queries;

/// <summary>Represents an immutable, retainable DNS query.</summary>
internal sealed class DnsQuery
{
    public ushort TransactionId { get; }

    public ushort RawFlags { get; }

    public byte Operation { get; }

    public bool IsTruncated => (RawFlags & 0x0200) != 0;

    public bool RecursionDesired => (RawFlags & 0x0100) != 0;

    public bool AuthenticData => (RawFlags & 0x0020) != 0;

    public bool CheckingDisabled => (RawFlags & 0x0010) != 0;

    public DnsQuestion Question { get; }

    public DnsQuery(ushort transactionId, ushort rawFlags, byte operation, DnsQuestion question)
    {
        ArgumentNullException.ThrowIfNull(question);
        TransactionId = transactionId;
        RawFlags = rawFlags;
        Operation = operation;
        Question = question;
    }
}
