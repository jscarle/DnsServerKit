using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Internal.Lookup;
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

    public DnsResolutionContext? Resolution { get; private set; }

    public void Set(DnsQueryContext query, RecordSet? answerSet, ResponseCode responseCode, bool authoritativeAnswer, bool recursionAvailable)
    {
        ArgumentNullException.ThrowIfNull(query);
        if ((ushort)responseCode > 0x0F)
            throw new NotSupportedException("Extended DNS response codes require an OPT record and are not supported.");

        Query = query;
        AnswerSet = answerSet;
        ResponseCode = responseCode;
        AuthoritativeAnswer = authoritativeAnswer;
        RecursionAvailable = recursionAvailable;
        Resolution = null;
    }

    public void Set(DnsQueryContext query, DnsResolutionContext resolution)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(resolution);

        Query = query;
        AnswerSet = resolution.AnswerSetCount == 1 ? resolution.GetAnswerSet(0).RecordSet : null;
        ResponseCode = resolution.ResponseCode;
        AuthoritativeAnswer = resolution.AuthoritativeAnswer;
        RecursionAvailable = false;
        Resolution = resolution;
    }

    public DnsResponse Materialize()
    {
        var query = Query.Materialize();
        return new DnsResponse(query, AuthoritativeAnswer, RecursionAvailable, ResponseCode, AnswerSet);
    }
}
