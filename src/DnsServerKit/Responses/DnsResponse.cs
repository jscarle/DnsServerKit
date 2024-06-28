using DnsServerKit.Parameters;
using DnsServerKit.Queries;
using DnsServerKit.ResourceRecords;

namespace DnsServerKit.Responses;

/// <summary>Represents a DNS response.</summary>
public sealed record DnsResponse
{
    /// <summary>Gets the transaction ID of the DNS query.</summary>
    /// <remarks>
    /// The transaction ID is a 16-bit identifier assigned by the program that generates any kind of query. This identifier is copied in the corresponding
    /// response and can be used by the requester to match responses to outstanding queries.
    /// </remarks>
    public ushort ID { get; }

    /// <summary>Gets a value indicating whether this message is a query or a response.</summary>
    /// <remarks>The QR flag is a single bit indicating whether the message is a query (0) or a response (1).</remarks>
    public bool QR { get; }

    /// <summary>Gets the operation code of the DNS query.</summary>
    /// <remarks>The OpCode field is a 4-bit field that specifies the kind of query in this message.</remarks>
    public DnsOperation OpCode { get; }

    /// <summary>Gets a value indicating whether this is an authoritative answer.</summary>
    /// <remarks>The AA flag is a single bit that is valid in responses, and specifies that the responding name server is an authority for the domain name in question.</remarks>
    public bool AA { get; }

    /// <summary>Gets a value indicating whether this message is truncated.</summary>
    /// <remarks>The TC flag is a single bit indicating that this message was truncated due to length greater than that permitted on the transmission channel.</remarks>
    public bool TC { get; }

    /// <summary>Gets a value indicating whether recursion is desired.</summary>
    /// <remarks>The RD flag is a single bit that directs the name server to pursue the query recursively. Recursive query support is optional.</remarks>
    public bool RD { get; }

    /// <summary>Gets a value indicating whether recursion is available.</summary>
    /// <remarks>The RA flag is a single bit that is set or cleared in a response, and denotes whether recursive query support is available in the name server.</remarks>
    public bool RA { get; }

    /// <summary>Gets the reserved field, must be zero.</summary>
    /// <remarks>The Z field is a 3-bit field reserved for future use. It must be zero in all queries and responses.</remarks>
    public byte Z { get; }

    /// <summary>Gets the response code of the DNS query.</summary>
    /// <remarks>The RCode field is a 4-bit field that specifies the response code of the DNS query.</remarks>
    public ResponseCode RCode { get; }

    /// <summary>Gets the number of entries in the question section of the DNS query.</summary>
    /// <remarks>The QDCount field specifies the number of entries in the question section of the message.</remarks>
    public ushort QDCount { get; }

    /// <summary>Gets the number of resource records in the answer section of the DNS query.</summary>
    /// <remarks>The ANCount field specifies the number of resource records in the answer section of the message.</remarks>
    public ushort ANCount { get; }

    /// <summary>Gets the number of name server resource records in the authority records section of the DNS query.</summary>
    /// <remarks>The NSCount field specifies the number of name server resource records in the authority records section of the message.</remarks>
    public ushort NSCount { get; }

    /// <summary>Gets the number of resource records in the additional records section of the DNS query.</summary>
    /// <remarks>The ARCount field specifies the number of resource records in the additional records section of the message.</remarks>
    public ushort ARCount { get; }

    /// <summary>Gets the questions of the DNS query.</summary>
    public List<DnsQuestion> Questions { get; }

    /// <summary>Gets the answers of the DNS query.</summary>
    public List<IResourceRecord> Answers { get; }

    public DnsResponse(DnsQuery query, bool aa, bool ra, List<IResourceRecord> answers)
    {
        ID = query.ID;
        QR = true;
        OpCode = query.OpCode;
        AA = aa;
        TC = false;
        RD = query.RD;
        RA = ra;
        Z = 0;
        RCode = ResponseCode.NoError;
        QDCount = query.QDCount;
        ANCount = (ushort)answers.Count;
        NSCount = 0;
        ARCount = 0;
        Questions = query.Questions;
        Answers = answers;
    }

    public DnsResponse(DnsQuery query, bool aa, bool ra, ResponseCode rCode)
    {
        ID = query.ID;
        QR = true;
        OpCode = query.OpCode;
        AA = aa;
        TC = false;
        RD = query.RD;
        RA = ra;
        Z = 0;
        RCode = rCode;
        QDCount = query.QDCount;
        ANCount = 0;
        NSCount = 0;
        ARCount = 0;
        Questions = query.Questions;
        Answers = new List<IResourceRecord>();
    }
}
