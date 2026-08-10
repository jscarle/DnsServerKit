using DnsServerKit.Internal.Protocol;

namespace DnsServerKit.Internal.Responses;

/// <summary>Describes trusted header values required to write a minimal DNS error response.</summary>
internal readonly record struct DnsErrorResponse(ushort TransactionId, byte Operation, bool RecursionDesired, ResponseCode ResponseCode);
