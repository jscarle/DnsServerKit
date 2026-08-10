using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Records;

namespace DnsServerKit.Internal.Responses;

/// <summary>Provides a reusable managed DNS response associated with a worker-scoped query.</summary>
internal sealed class DnsResponseContext
{
    public DnsQueryContext Query { get; private set; } = null!;

    public bool AuthoritativeAnswer { get; private set; }

    public bool RecursionAvailable { get; private set; }

    public ResponseCode ResponseCode { get; private set; }

    public RecordSet? AnswerSet { get; private set; }

    public void Set(DnsQueryContext query, RecordSet? answerSet, ResponseCode responseCode, bool authoritativeAnswer, bool recursionAvailable)
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
