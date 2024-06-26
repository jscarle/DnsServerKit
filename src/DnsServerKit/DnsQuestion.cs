namespace DnsServerKit;

/// <summary>Represents a DNS question.</summary>
public sealed record DnsQuestion
{
    /// <summary>Gets the name that is the subject of the DNS query.</summary>
    public string Name { get; }

    /// <summary>Gets the type of DNS record being queried.</summary>
    public RRType Type { get; }

    /// <summary>Gets the class of the DNS query.</summary>
    public DnsClass Class { get; }
    
    /// <summary>Initializes a new instance of the <see cref="DnsQuestion"/> class with the specified name, type, and class.</summary>
    /// <param name="name">The name that is the subject of the DNS query.</param>
    /// <param name="type">The type of DNS record being queried.</param>
    /// <param name="class">The class of the DNS query.</param>
    public DnsQuestion(string name, RRType type, DnsClass @class)
    {
        Name = name;
        Type = type;
        Class = @class;
    }
}
