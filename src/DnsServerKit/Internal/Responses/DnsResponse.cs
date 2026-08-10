using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Records;

namespace DnsServerKit.Internal.Responses;

/// <summary>Represents an immutable, retainable DNS response.</summary>
internal sealed class DnsResponse
{
    public DnsQuery Query { get; }

    public bool AuthoritativeAnswer { get; }

    public bool RecursionAvailable { get; }

    public ResponseCode ResponseCode { get; }

    public RecordSet? AnswerSet { get; }

    public DnsResponse(DnsQuery query, bool authoritativeAnswer, bool recursionAvailable, ResponseCode responseCode, RecordSet? answerSet)
    {
        ArgumentNullException.ThrowIfNull(query);
        Query = query;
        AuthoritativeAnswer = authoritativeAnswer;
        RecursionAvailable = recursionAvailable;
        ResponseCode = responseCode;
        AnswerSet = answerSet;
    }
}
