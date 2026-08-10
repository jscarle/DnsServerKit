namespace DnsServerKit.Queries;

/// <summary>Provides a reusable managed view of a DNS question in worker-owned memory.</summary>
public sealed class DnsQuestionContext
{
    private readonly DnsQueryContext _query;
    private int _nameOffset;
    private int _nameLength;

    public ushort Type { get; private set; }

    public ushort Class { get; private set; }

    public ReadOnlySpan<byte> EncodedName => _query.Datagram.Span.Slice(_nameOffset, _nameLength);

    internal int LookupHashCode { get; private set; }

    internal DnsQuestionContext(DnsQueryContext query)
    {
        _query = query;
    }

    public DnsName MaterializeName() => DnsName.FromWire(EncodedName);

    public DnsQuestion Materialize()
    {
        var name = MaterializeName();
        return new DnsQuestion(name, Type, Class);
    }

    internal void Set(int nameOffset, int nameLength, ushort type, ushort @class, int lookupHashCode)
    {
        _nameOffset = nameOffset;
        _nameLength = nameLength;
        Type = type;
        Class = @class;
        LookupHashCode = lookupHashCode;
    }

    internal void Clear()
    {
        _nameOffset = 0;
        _nameLength = 0;
        Type = 0;
        Class = 0;
        LookupHashCode = 0;
    }
}
