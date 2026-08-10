using DnsServerKit.Data;
using DnsServerKit.Parameters;
using DnsServerKit.Queries;

namespace DnsServerKit.Responses;

/// <summary>Provides a reusable managed DNS response associated with a worker-scoped query.</summary>
public sealed class DnsResponseContext
{
    public DnsQueryContext Query { get; private set; } = null!;

    public bool AuthoritativeAnswer { get; private set; }

    public bool RecursionAvailable { get; private set; }

    public ResponseCode ResponseCode { get; private set; }

    public DnsRecordSet? AnswerSet { get; private set; }

    public void Set(
        DnsQueryContext query,
        DnsRecordSet? answerSet,
        ResponseCode responseCode,
        bool authoritativeAnswer,
        bool recursionAvailable)
    {
        ArgumentNullException.ThrowIfNull(query);
        if ((byte)responseCode > 0x0F)
            throw new NotSupportedException("Extended DNS response codes require an OPT record and are not supported.");

        Query = query;
        AnswerSet = answerSet;
        ResponseCode = responseCode;
        AuthoritativeAnswer = authoritativeAnswer;
        RecursionAvailable = recursionAvailable;
    }

    public DnsResponse Materialize()
    {
        var query = Query.Materialize();
        return new DnsResponse(query, AuthoritativeAnswer, RecursionAvailable, ResponseCode, AnswerSet);
    }
}
