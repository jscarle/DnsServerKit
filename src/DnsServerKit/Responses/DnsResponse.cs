using DnsServerKit.Data;
using DnsServerKit.Parameters;
using DnsServerKit.Queries;
using DnsServerKit.ResourceRecords;

namespace DnsServerKit.Responses;

/// <summary>Represents an immutable, retainable DNS response.</summary>
public sealed class DnsResponse
{
    private static readonly DnsResourceRecord[] EmptyAnswers = [];

    public DnsQuery Query { get; }

    public bool AuthoritativeAnswer { get; }

    public bool RecursionAvailable { get; }

    public ResponseCode ResponseCode { get; }

    public DnsRecordSet? AnswerSet { get; }

    public IReadOnlyList<DnsResourceRecord> Answers => AnswerSet is null ? EmptyAnswers : AnswerSet.Records;

    public DnsResponse(
        DnsQuery query,
        bool authoritativeAnswer,
        bool recursionAvailable,
        ResponseCode responseCode,
        DnsRecordSet? answerSet)
    {
        ArgumentNullException.ThrowIfNull(query);
        Query = query;
        AuthoritativeAnswer = authoritativeAnswer;
        RecursionAvailable = recursionAvailable;
        ResponseCode = responseCode;
        AnswerSet = answerSet;
    }
}
