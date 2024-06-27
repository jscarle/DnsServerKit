namespace DnsServerKit.Parameters;

/// <summary><c>DNS OpCodes</c> Represents the operational codes for DNS messages.</summary>
public enum DnsOperation : byte
{
    /// <summary><c>Query</c> Represents a standard query.</summary>
    Query = 0,

    /// <summary><c>IQuery</c> Represents an inverse query (obsolete).</summary>
    InverseQuery = 1,

    /// <summary><c>Status</c> Represents a status request.</summary>
    Status = 2,

    /// <summary><c>Notify</c> Represents a notification of zone change.</summary>
    Notify = 4,

    /// <summary><c>Update</c> Represents a dynamic update request.</summary>
    Update = 5,

    /// <summary><c>DNS Stateful Operations (DSO)</c> Represents DNS stateful operations.</summary>
    DnsStatefulOperations = 6,
}
