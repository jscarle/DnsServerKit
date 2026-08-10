using DnsServerKit.Queries;

namespace DnsServerKit.Data;

internal sealed class DnsRecordKey
{
    public DnsName Name { get; }

    public ushort Type { get; }

    public ushort Class { get; }

    public int HashCode { get; }

    public DnsRecordKey(DnsName name, ushort type, ushort @class)
    {
        Name = name;
        Type = type;
        Class = @class;
        HashCode = DnsName.ComputeQuestionHash(name.WireHashCode, type, @class);
    }
}

internal readonly ref struct DnsQuestionLookup
{
    public ReadOnlySpan<byte> EncodedName { get; }

    public ushort Type { get; }

    public ushort Class { get; }

    public int HashCode { get; }

    public DnsQuestionLookup(DnsQuestionContext question)
    {
        EncodedName = question.EncodedName;
        Type = question.Type;
        Class = question.Class;
        HashCode = question.LookupHashCode;
    }
}

internal sealed class DnsRecordKeyComparer :
    IEqualityComparer<DnsRecordKey>,
    IAlternateEqualityComparer<DnsQuestionLookup, DnsRecordKey>
{
    public static DnsRecordKeyComparer Instance { get; } = new();

    private DnsRecordKeyComparer()
    {
    }

    public DnsRecordKey Create(DnsQuestionLookup alternate)
    {
        var name = DnsName.FromWire(alternate.EncodedName);
        return new DnsRecordKey(name, alternate.Type, alternate.Class);
    }

    public bool Equals(DnsQuestionLookup alternate, DnsRecordKey other)
    {
        return alternate.HashCode == other.HashCode
               && alternate.Type == other.Type
               && alternate.Class == other.Class
               && other.Name.WireEquals(alternate.EncodedName);
    }

    public int GetHashCode(DnsQuestionLookup alternate) => alternate.HashCode;

    public bool Equals(DnsRecordKey? first, DnsRecordKey? second)
    {
        if (ReferenceEquals(first, second))
            return true;

        return first is not null
               && second is not null
               && first.HashCode == second.HashCode
               && first.Type == second.Type
               && first.Class == second.Class
               && first.Name.Equals(second.Name);
    }

    public int GetHashCode(DnsRecordKey key) => key.HashCode;
}
