using DnsServerKit.Responses;
using LightResults;

namespace DnsServerKit;

/// <summary>Represents a failure to read a DNS query and, when safe, the response that should be returned.</summary>
public sealed class DnsReadError : Error
{
    /// <summary>Gets the minimal error response to send, or <see langword="null"/> when the packet must be dropped.</summary>
    public DnsErrorResponse? Response { get; }

    public DnsReadError(string message, DnsErrorResponse? response = null)
        : base(message)
    {
        Response = response;
    }

    public DnsReadError(string message, Exception exception, DnsErrorResponse? response = null)
        : base(message, exception)
    {
        Response = response;
    }
}
