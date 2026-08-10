namespace DnsServerKit.Internal.Queries;

/// <summary>Provides a reusable managed view of a DNS query in worker-owned memory.</summary>
/// <remarks>
/// The context remains valid until it is reused by <see cref="DnsReader.Read"/>. Its scalar fields and question bytes remain valid while a response is written over the same worker buffer, but <see cref="Datagram"/> must not be
/// treated as the original request after writing begins.
/// </remarks>
internal sealed class DnsQueryContext
{
    public ushort TransactionId { get; private set; }

    public ushort RawFlags { get; private set; }

    public byte Operation { get; private set; }

    public bool IsTruncated => (RawFlags & 0x0200) != 0;

    public bool RecursionDesired => (RawFlags & 0x0100) != 0;

    public bool AuthenticData => (RawFlags & 0x0020) != 0;

    public bool CheckingDisabled => (RawFlags & 0x0010) != 0;

    public DnsQuestionContext Question { get; }

    public ReadOnlyMemory<byte> Datagram { get; private set; }

    internal int QuestionEndOffset { get; private set; }

    public DnsQueryContext()
    {
        Question = new DnsQuestionContext(this);
    }

    public DnsQuery Materialize()
    {
        var question = Question.Materialize();
        return new DnsQuery(TransactionId, RawFlags, Operation, question);
    }

    internal void Set(
        ReadOnlyMemory<byte> datagram,
        ushort transactionId,
        ushort rawFlags,
        byte operation,
        int nameOffset,
        int nameLength,
        ushort type,
        ushort @class,
        int nameHashCode,
        int questionEndOffset
    )
    {
        Datagram = datagram;
        TransactionId = transactionId;
        RawFlags = rawFlags;
        Operation = operation;
        QuestionEndOffset = questionEndOffset;
        Question.Set(nameOffset, nameLength, type, @class, nameHashCode);
    }

    internal void Clear()
    {
        Datagram = default;
        TransactionId = 0;
        RawFlags = 0;
        Operation = 0;
        QuestionEndOffset = 0;
        Question.Clear();
    }
}
