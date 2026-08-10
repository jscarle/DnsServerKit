namespace DnsServerKit.Internal.Queries;

internal enum DnsReadFailure : byte
{
    None,
    TruncatedHeader,
    InboundResponse,
    UnsupportedOperation,
    InvalidHeader,
    InvalidName,
    TruncatedQuestion,
    TrailingData,
    UnexpectedException,
}
