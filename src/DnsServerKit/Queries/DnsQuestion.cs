namespace DnsServerKit.Queries;

/// <summary>Represents an immutable, retainable DNS question.</summary>
public sealed class DnsQuestion
{
    public DnsName Name { get; }

    public ushort Type { get; }

    public ushort Class { get; }

    public DnsQuestion(DnsName name, ushort type, ushort @class)
    {
        ArgumentNullException.ThrowIfNull(name);
        Name = name;
        Type = type;
        Class = @class;
    }
}
