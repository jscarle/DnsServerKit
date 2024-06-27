namespace DnsServerKit.Parameters;

/// <summary><c>DNS RCODEs</c> Represents the response codes for DNS messages.</summary>
public enum ResponseCode : byte
{
    /// <summary><c>NoError</c> Represents a no error response.</summary>
    NoError = 0,

    /// <summary><c>FormErr</c> Represents a format error response.</summary>
    FormatError = 1,

    /// <summary><c>ServFail</c> Represents a server failure response.</summary>
    ServerFailure = 2,

    /// <summary><c>NXDomain</c> Represents a non-existent domain response.</summary>
    NxDomain = 3,

    /// <summary><c>NotImp</c> Represents a not implemented response.</summary>
    NotImplemented = 4,

    /// <summary><c>Refused</c> Represents a query refused response.</summary>
    Refused = 5,

    /// <summary><c>YXDomain</c> Represents a name exists when it should not response.</summary>
    YxDomain = 6,

    /// <summary><c>YXRRSet</c> Represents a resource record set exists when it should not response.</summary>
    YxRrSet = 7,

    /// <summary><c>NXRRSet</c> Represents a resource record set that should exist does not response.</summary>
    NxRrSet = 8,

    /// <summary><c>NotAuth</c> Represents a server not authoritative for zone response.</summary>
    NotAuthoritative = 9,

    /// <summary><c>NotAuth</c> Represents a not authorized response.</summary>
    NotAuthorized = 9,

    /// <summary><c>NotZone</c> Represents a name not contained in zone response.</summary>
    NotZone = 10,

    /// <summary><c>DSOTYPENI</c> Represents a DSO type not implemented response.</summary>
    DsoTypeNi = 11,

    /// <summary><c>BADVERS</c> Represents a bad OPT version response.</summary>
    BadVers = 16,

    /// <summary><c>BADSIG</c> Represents a TSIG signature failure response.</summary>
    BadSig = 16,

    /// <summary><c>BADKEY</c> Represents a key not recognized response.</summary>
    BadKey = 17,

    /// <summary><c>BADTIME</c> Represents a signature out of time window response.</summary>
    BadTime = 18,

    /// <summary><c>BADMODE</c> Represents a bad TKEY mode response.</summary>
    BadMode = 19,

    /// <summary><c>BADNAME</c> Represents duplicate key name response.</summary>
    BadName = 20,

    /// <summary><c>BADALG</c> Represents an algorithm not supported response.</summary>
    BadAlg = 21,

    /// <summary><c>BADTRUNC</c> Represents a bad truncation response.</summary>
    BadTrunc = 22,

    /// <summary><c>BADCOOKIE</c> Represents a bad or missing server cookie response.</summary>
    BadCookie = 23,
}
