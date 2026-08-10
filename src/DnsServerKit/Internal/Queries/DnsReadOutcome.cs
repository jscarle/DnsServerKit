namespace DnsServerKit.Internal.Queries;

internal enum DnsReadOutcome : byte
{
    Drop,
    Query,
    ErrorResponse,
}
