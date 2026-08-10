using DnsServerKit.Responses;

namespace DnsServerKit;

public enum DnsReadOutcome : byte
{
    Drop,
    Query,
    ErrorResponse,
}

public enum DnsReadFailure : byte
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

/// <summary>Describes the allocation-free outcome of reading a DNS datagram.</summary>
public readonly struct DnsReadResult
{
    public DnsReadOutcome Outcome { get; }

    public DnsReadFailure Failure { get; }

    public DnsErrorResponse ErrorResponse { get; }

    public Exception? Exception { get; }

    internal DnsReadResult(
        DnsReadOutcome outcome,
        DnsReadFailure failure = DnsReadFailure.None,
        DnsErrorResponse errorResponse = default,
        Exception? exception = null)
    {
        Outcome = outcome;
        Failure = failure;
        ErrorResponse = errorResponse;
        Exception = exception;
    }
}
