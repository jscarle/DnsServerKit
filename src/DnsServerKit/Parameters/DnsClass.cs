namespace DnsServerKit.Parameters;

/// <summary>Provides registered <c>DNS CLASS</c> values for DNS messages.</summary>
/// <remarks>DNS CLASS values are extensible. Values not listed here remain valid wire values and must be preserved.</remarks>
public enum DnsClass : ushort
{
    Internet = 1,
    None = 254,
    Any = 255,
}
