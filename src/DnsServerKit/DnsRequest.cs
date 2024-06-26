using System.Diagnostics.CodeAnalysis;
using System.Text;
using LightResults;

namespace DnsServerKit;

/// <summary>Represents a DNS request.</summary>
public sealed record DnsRequest
{
    /// <summary>Gets the transaction ID of the DNS request.</summary>
    /// <remarks>
    /// The transaction ID is a 16-bit identifier assigned by the program that generates any kind of query. This identifier is copied in the corresponding
    /// response and can be used by the requester to match responses to outstanding queries.
    /// </remarks>
    public ushort ID { get; }

    /// <summary>Gets a value indicating whether this message is a query or a response.</summary>
    /// <remarks>The QR flag is a single bit indicating whether the message is a query (0) or a response (1).</remarks>
    public bool QR { get; }

    /// <summary>Gets the operation code of the DNS request.</summary>
    /// <remarks>The OpCode field is a 4-bit field that specifies the kind of query in this message.</remarks>
    public OpCode OpCode { get; }

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

    /// <summary>Gets the response code of the DNS request.</summary>
    /// <remarks>The RCode field is a 4-bit field that specifies the response code of the DNS request.</remarks>
    public RCode RCode { get; }

    /// <summary>Gets the number of entries in the question section of the DNS request.</summary>
    /// <remarks>The QDCount field specifies the number of entries in the question section of the message.</remarks>
    public ushort QDCount { get; }

    /// <summary>Gets the number of resource records in the answer section of the DNS request.</summary>
    /// <remarks>The ANCount field specifies the number of resource records in the answer section of the message.</remarks>
    public ushort ANCount { get; }

    /// <summary>Gets the number of name server resource records in the authority records section of the DNS request.</summary>
    /// <remarks>The NSCount field specifies the number of name server resource records in the authority records section of the message.</remarks>
    public ushort NSCount { get; }

    /// <summary>Gets the number of resource records in the additional records section of the DNS request.</summary>
    /// <remarks>The ARCount field specifies the number of resource records in the additional records section of the message.</remarks>
    public ushort ARCount { get; }

    /// <summary>Gets the questions of the DNS request.</summary>
    public List<DnsQuestion> Questions { get; }

    private DnsRequest(ushort id, bool qr, byte opCode, bool aa, bool tc, bool rd, bool ra, byte z, byte rCode,
        ushort qdCount, ushort anCount, ushort nsCount, ushort arCount, List<DnsQuestion> questions)
    {
        ID = id;
        QR = qr;
        OpCode = (OpCode)opCode;
        AA = aa;
        TC = tc;
        RD = rd;
        RA = ra;
        Z = z;
        RCode = (RCode)rCode;
        QDCount = qdCount;
        ANCount = anCount;
        NSCount = nsCount;
        ARCount = arCount;
        Questions = questions;
    }

    /// <summary>Attempts to create a new instance of the <see cref="DnsRequest"/> class from the specified memory buffer.</summary>
    /// <param name="memory">The memory buffer containing the bytes of the DNS request.</param>
    /// <returns>Returns a result containing the created <see cref="DnsRequest"/> if the creation succeeded, or an error if it failed.</returns>
    public static Result<DnsRequest> TryCreate(ReadOnlyMemory<byte> memory)
    {
        if (memory.Length < 16)
        {
            Result.Fail<DnsRequest>("Could not process the request. The data was less than 16 bytes.");
        }

        try
        {
            var span = memory.Span;

            // Parse header
            var id = (ushort)((span[0] << 8) | span[1]);
            var qr = (span[2] & 0x80) != 0;
            var opCode = (byte)((span[2] & 0x78) >> 3);
            var aa = (span[2] & 0x04) != 0;
            var tc = (span[2] & 0x02) != 0;
            var rd = (span[2] & 0x01) != 0;
            var ra = (span[3] & 0x80) != 0;
            var z = (byte)((span[3] & 0x70) >> 4);
            var rCode = (byte)(span[3] & 0x0F);
            var qdCount = (ushort)((span[4] << 8) | span[5]);
            var anCount = (ushort)((span[6] << 8) | span[7]);
            var nsCount = (ushort)((span[8] << 8) | span[9]);
            var arCount = (ushort)((span[10] << 8) | span[11]);

            if (!Enum.IsDefined(typeof(OpCode), opCode))
                Result.Fail<DnsRequest>("Could not process the request. Invalid OpCode.");
            if (!Enum.IsDefined(typeof(RCode), rCode))
                Result.Fail<DnsRequest>("Could not process the request. Invalid RCode.");
            if (qdCount == 0)
                Result.Fail<DnsRequest>("Could not process the request. QDCount is 0.");
            
            var questions = new List<DnsQuestion>(qdCount);
            var offset = 12;
            for (var i = 0; i < qdCount; i++)
            {
                var name = DecodeDnsName(span, ref offset);
                if (offset + 4 > span.Length)
                {
                    Result.Fail<DnsRequest>("Could not process the request. The data was truncated.");
                }

                var type = (ushort)((span[offset] << 8) | span[offset + 1]);
                var @class = (ushort)((span[offset + 2] << 8) | span[offset + 3]);

                if (!Enum.IsDefined(typeof(RRType), type))
                    Result.Fail<DnsRequest>("Could not process the request. Invalid Class.");
                if (!Enum.IsDefined(typeof(DnsClass), @class))
                    Result.Fail<DnsRequest>("Could not process the request. Invalid Class.");

                questions.Add(new DnsQuestion(name, (RRType)type, (DnsClass)@class));

                offset += 4;
            }

            return new DnsRequest(id, qr, opCode, aa, tc, rd, ra, z, rCode, qdCount, anCount, nsCount, arCount, questions);
        }
        catch (Exception ex)
        {
            return Result.Fail<DnsRequest>("Could not process the request. An exception occured.", ("Exception", ex));
        }
    }

    private static string DecodeDnsName(ReadOnlySpan<byte> span, ref int offset)
    {
        var nameBuilder = new StringBuilder();

        while (offset < span.Length)
        {
            var length = span[offset];

            // If length is zero, we've reached the end of the name
            if (length == 0)
            {
                offset++;
                break;
            }

            // Check for pointers (compression)
            if ((length & 0xC0) == 0xC0)
            {
                // The next byte is part of the pointer
                var pointer = ((length & 0x3F) << 8) | span[offset + 1];
                offset += 2;
                var pointerOffset = pointer; // Save the current pointer
                DecodeDnsName(span, ref pointerOffset);
                break;
            }

            // Move to the next label part
            offset++;
            if (nameBuilder.Length > 0)
            {
                nameBuilder.Append('.');
            }

            var slice = span.Slice(offset, length);
            var str = Encoding.ASCII.GetString(slice);
            nameBuilder.Append(str);
            offset += length;
        }

        return nameBuilder.ToString();
    }
}
