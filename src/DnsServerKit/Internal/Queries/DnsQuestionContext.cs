using DnsServerKit.Internal.Protocol;

namespace DnsServerKit.Internal.Queries;

/// <summary>Provides a reusable managed view of a DNS question in worker-owned memory.</summary>
internal sealed class DnsQuestionContext
{
    public ushort Type { get; private set; }

    public ushort Class { get; private set; }

    public ReadOnlySpan<byte> EncodedName => _query.Datagram.Span.Slice(_nameOffset, _nameLength);

    internal int NameHashCode { get; private set; }
    private readonly DnsQueryContext _query;
    private int _nameOffset;
    private int _nameLength;

    internal DnsQuestionContext(DnsQueryContext query)
    {
        _query = query;
    }

    public DnsName MaterializeName()
    {
        return DnsName.FromWire(EncodedName);
    }

    public DnsQuestion Materialize()
    {
        var name = MaterializeName();
        return new DnsQuestion(name, Type, Class);
    }

    internal void Set(int nameOffset, int nameLength, ushort type, ushort @class, int nameHashCode)
    {
        _nameOffset = nameOffset;
        _nameLength = nameLength;
        Type = type;
        Class = @class;
        NameHashCode = nameHashCode;
    }

    internal void Clear()
    {
        _nameOffset = 0;
        _nameLength = 0;
        Type = 0;
        Class = 0;
        NameHashCode = 0;
    }
}
