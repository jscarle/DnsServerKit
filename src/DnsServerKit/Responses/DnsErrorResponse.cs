using DnsServerKit.Parameters;

namespace DnsServerKit.Responses;

/// <summary>Describes the trusted header values required to write a minimal DNS error response.</summary>
public readonly record struct DnsErrorResponse(
    ushort TransactionId,
    DnsOperation Operation,
    bool RecursionDesired,
    ResponseCode ResponseCode);
