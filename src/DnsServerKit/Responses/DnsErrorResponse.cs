using DnsServerKit.Parameters;

namespace DnsServerKit.Responses;

/// <summary>Describes trusted header values required to write a minimal DNS error response.</summary>
public readonly record struct DnsErrorResponse(
    ushort TransactionId,
    byte Operation,
    bool RecursionDesired,
    ResponseCode ResponseCode);
