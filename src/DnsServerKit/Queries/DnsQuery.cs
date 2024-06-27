using DnsServerKit.Parameters;
using LightResults;

namespace DnsServerKit.Queries;

/// <summary>Represents a DNS query.</summary>
public sealed record DnsQuery
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

    private DnsQuery(ushort id, bool qr, DnsOperation opCode, bool aa, bool tc, bool rd, bool ra, byte z, ResponseCode rCode,
        ushort qdCount, ushort anCount, ushort nsCount, ushort arCount, List<DnsQuestion> questions)
    {
        ID = id;
        QR = qr;
        OpCode = opCode;
        AA = aa;
        TC = tc;
        RD = rd;
        RA = ra;
        Z = z;
        RCode = rCode;
        QDCount = qdCount;
        ANCount = anCount;
        NSCount = nsCount;
        ARCount = arCount;
        Questions = questions;
    }
    
    /// <summary>Attempts to create a new instance of the <see cref="DnsQuery"/> class from the specified memory buffer.</summary>
    /// <param name="memory">The memory buffer containing the bytes of the DNS query.</param>
    /// <returns>Returns a result containing the created <see cref="DnsQuery"/> if the creation succeeded, or an error if it failed.</returns>
    public static Result<DnsQuery> TryParse(Memory<byte> memory)
    {
        if (memory.Length < 16)
        {
            Result.Fail<DnsQuery>("Could not process the DNS query. Received less than 16 bytes of data.");
        }

        try
        {
            var span = memory.Span;

            var id = (ushort)((span[0] << 8) | span[1]);

            var qr = (span[2] & 0x80) != 0;
            if (qr)
                Result.Fail<DnsQuery>("Could not process the DNS query. Invalid QR.");

            var opCode = (byte)((span[2] & 0x78) >> 3);
            if (!Enum.IsDefined(typeof(DnsOperation), opCode))
                Result.Fail<DnsQuery>("Could not process the DNS query. Invalid OpCode.");

            var aa = (span[2] & 0x04) != 0;
            if (aa)
                Result.Fail<DnsQuery>("Could not process the DNS query. Invalid AA.");

            var tc = (span[2] & 0x02) != 0;

            var rd = (span[2] & 0x01) != 0;
            
            var ra = (span[3] & 0x80) != 0;
            if (ra)
                Result.Fail<DnsQuery>("Could not process the DNS query. Invalid RA.");
            
            var z = (byte)((span[3] & 0x70) >> 4);
            if (z > 0)
                Result.Fail<DnsQuery>("Could not process the DNS query. Invalid Z.");

            var rCode = (byte)(span[3] & 0x0F);
            if (rCode > 0)
                Result.Fail<DnsQuery>("Could not process the DNS query. Invalid RCode.");

            var qdCount = (ushort)((span[4] << 8) | span[5]);
            if (qdCount == 0)
                Result.Fail<DnsQuery>("Could not process the DNS query. QDCount is 0.");

            var anCount = (ushort)((span[6] << 8) | span[7]);
            if (anCount > 0)
                Result.Fail<DnsQuery>("Could not process the DNS query. Invalid ANCount.");

            var nsCount = (ushort)((span[8] << 8) | span[9]);
            if (nsCount > 0)
                Result.Fail<DnsQuery>("Could not process the DNS query. Invalid NSCount.");
            
            var arCount = (ushort)((span[10] << 8) | span[11]);
            if (arCount > 0)
                Result.Fail<DnsQuery>("Could not process the DNS query. Invalid ARCount.");

            
            var questions = new List<DnsQuestion>(qdCount);
            var offset = 12;
            for (var i = 0; i < qdCount; i++)
            {
                var name = NameHelper.DecodeDnsName(span, ref offset);
                if (offset + 4 > span.Length)
                {
                    Result.Fail<DnsQuery>("Could not process the DNS query. Data was truncated.");
                }

                var type = (ushort)((span[offset] << 8) | span[offset + 1]);
                var @class = (ushort)((span[offset + 2] << 8) | span[offset + 3]);

                if (!Enum.IsDefined(typeof(RecordType), type))
                    Result.Fail<DnsQuery>("Could not process the DNS query. Invalid RRType.");
                if (!Enum.IsDefined(typeof(DnsClass), @class))
                    Result.Fail<DnsQuery>("Could not process the DNS query. Invalid Class.");

                var question = new DnsQuestion
                {
                    Name = name,
                    Type = (RecordType)type,
                    Class = (DnsClass)@class,
                };
                questions.Add(question);

                offset += 4;
            }

            var dnsQuery = new DnsQuery(id, qr, (DnsOperation)opCode, aa, tc, rd, ra, z, (ResponseCode)rCode, qdCount, anCount, nsCount, arCount, questions);

            return Result.Ok(dnsQuery);
        }
        catch (Exception ex)
        {
            return Result.Fail<DnsQuery>("Could not process the DNS query. An exception occured.", ("Exception", ex));
        }
    }
}
