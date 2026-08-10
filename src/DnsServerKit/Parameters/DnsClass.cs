namespace DnsServerKit.Parameters;

/// <summary>Provides registered <c>DNS CLASS</c> values for DNS messages.</summary>
/// <remarks>DNS CLASS values are extensible. Values not listed here remain valid wire values and must be preserved.</remarks>
public enum DnsClass : ushort
{
    Reserved = 0,
    Internet = 1,
    Chaos = 3,
    Hesiod = 4,
    None = 254,
    Any = 255,
}
