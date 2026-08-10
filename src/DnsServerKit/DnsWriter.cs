using System.Buffers.Binary;
using DnsServerKit.Responses;

namespace DnsServerKit;

public static class DnsWriter
{
    private const int HeaderLength = 12;
    private const int MaximumUdpMessageLength = 512;

    /// <summary>Writes a response from reusable managed query and response contexts.</summary>
    public static int Write(Span<byte> destination, DnsResponseContext response)
    {
        ArgumentNullException.ThrowIfNull(response);
        var query = response.Query;
        ArgumentNullException.ThrowIfNull(query);

        var maximumLength = Math.Min(destination.Length, MaximumUdpMessageLength);
        if (maximumLength < query.QuestionEndOffset)
            throw new ArgumentException("The destination cannot contain the DNS question.", nameof(destination));

        var queryDatagram = query.Datagram.Span;
        if (!queryDatagram.Overlaps(destination, out var overlapOffset) || overlapOffset != 0)
            queryDatagram[HeaderLength..query.QuestionEndOffset].CopyTo(destination[HeaderLength..]);

        var responseFlags = (ushort)(0x8000
                                     | (query.Operation << 11)
                                     | (response.AuthoritativeAnswer ? 0x0400 : 0)
                                     | (query.RecursionDesired ? 0x0100 : 0)
                                     | (response.RecursionAvailable ? 0x0080 : 0)
                                     | (byte)response.ResponseCode);

        var position = query.QuestionEndOffset;
        ushort answerCount = 0;
        var truncated = false;
        var answerSet = response.AnswerSet;
        if (answerSet is not null)
        {
            var availableLength = maximumLength - position;
            var copyLength = 0;
            var recordEndOffsets = answerSet.RecordEndOffsets;
            for (var recordIndex = 0; recordIndex < recordEndOffsets.Length; recordIndex++)
            {
                var recordEndOffset = recordEndOffsets[recordIndex];
                if (recordEndOffset > availableLength)
                {
                    truncated = true;
                    break;
                }

                copyLength = recordEndOffset;
                answerCount++;
            }

            answerSet.EncodedAnswers[..copyLength].CopyTo(destination[position..]);
            position += copyLength;
            truncated |= answerCount != answerSet.Records.Count;
        }

        if (truncated)
            responseFlags |= 0x0200;

        destination[..HeaderLength].Clear();
        BinaryPrimitives.WriteUInt16BigEndian(destination, query.TransactionId);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], responseFlags);
        BinaryPrimitives.WriteUInt16BigEndian(destination[4..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(destination[6..], answerCount);

        return position;
    }

    /// <summary>Writes a minimal DNS error response into the specified destination.</summary>
    public static int WriteErrorResponse(
        Span<byte> destination,
        DnsErrorResponse errorResponse,
        bool recursionAvailable)
    {
        if (destination.Length < HeaderLength)
            throw new ArgumentException("The destination must contain at least 12 bytes.", nameof(destination));
        if (errorResponse.Operation > 0x0F)
            throw new ArgumentOutOfRangeException(nameof(errorResponse), "The DNS operation must fit in the four-bit OpCode field.");
        if ((byte)errorResponse.ResponseCode > 0x0F)
            throw new NotSupportedException("Extended DNS response codes require an OPT record and are not supported.");

        destination[..HeaderLength].Clear();
        BinaryPrimitives.WriteUInt16BigEndian(destination, errorResponse.TransactionId);

        var flags = (ushort)(0x8000
                             | (errorResponse.Operation << 11)
                             | (errorResponse.RecursionDesired ? 0x0100 : 0)
                             | (recursionAvailable ? 0x0080 : 0)
                             | (byte)errorResponse.ResponseCode);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], flags);

        return HeaderLength;
    }
}
