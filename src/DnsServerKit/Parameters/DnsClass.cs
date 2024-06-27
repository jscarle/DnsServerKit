namespace DnsServerKit.Parameters;

/// <summary><c>DNS CLASSes</c> Represents classes for DNS messages.</summary>
public enum DnsClass : ushort
{
    Internet = 1,
    None = 254,
    Any = 255,
}
