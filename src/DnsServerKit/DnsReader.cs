using DnsServerKit.Parameters;
using DnsServerKit.Queries;
using LightResults;

namespace DnsServerKit;

public sealed class DnsReader
{
    /// <summary>Attempts to create a new instance of the <see cref="DnsQuery"/> class from the specified memory buffer.</summary>
    /// <param name="memory">The memory buffer containing the bytes of the DNS query.</param>
    /// <returns>Returns a result containing the created <see cref="DnsQuery"/> if the creation succeeded, or an error if it failed.</returns>
    public static Result<DnsQuery> TryReadBytes(Memory<byte> memory)
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
