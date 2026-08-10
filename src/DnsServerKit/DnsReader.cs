using System.Buffers.Binary;
using DnsServerKit.Parameters;
using DnsServerKit.Queries;
using DnsServerKit.Responses;

namespace DnsServerKit;

public static class DnsReader
{
    private const int HeaderLength = 12;

    /// <summary>Reads a DNS datagram into a reusable managed query context.</summary>
    public static DnsReadResult Read(ReadOnlyMemory<byte> datagram, DnsQueryContext queryContext)
    {
        ArgumentNullException.ThrowIfNull(queryContext);
        queryContext.Clear();

        if (datagram.Length < HeaderLength)
            return new DnsReadResult(DnsReadOutcome.Drop, DnsReadFailure.TruncatedHeader);

        var span = datagram.Span;
        var transactionId = BinaryPrimitives.ReadUInt16BigEndian(span);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(span[2..]);
        var operation = (byte)((flags & 0x7800) >> 11);
        var recursionDesired = (flags & 0x0100) != 0;

        if ((flags & 0x8000) != 0)
            return new DnsReadResult(DnsReadOutcome.Drop, DnsReadFailure.InboundResponse);

        if (operation != (byte)DnsOperation.Query)
        {
            var notImplementedResponse = new DnsErrorResponse(
                transactionId,
                operation,
                recursionDesired,
                ResponseCode.NotImplemented);

            return new DnsReadResult(
                DnsReadOutcome.ErrorResponse,
                DnsReadFailure.UnsupportedOperation,
                notImplementedResponse);
        }

        var formatErrorResponse = new DnsErrorResponse(
            transactionId,
            operation,
            recursionDesired,
            ResponseCode.FormatError);

        try
        {
            if ((flags & 0x04C0) != 0 || (flags & 0x000F) != 0)
            {
                return new DnsReadResult(
                    DnsReadOutcome.ErrorResponse,
                    DnsReadFailure.InvalidHeader,
                    formatErrorResponse);
            }

            var questionCount = BinaryPrimitives.ReadUInt16BigEndian(span[4..]);
            var answerCount = BinaryPrimitives.ReadUInt16BigEndian(span[6..]);
            var authorityCount = BinaryPrimitives.ReadUInt16BigEndian(span[8..]);
            var additionalCount = BinaryPrimitives.ReadUInt16BigEndian(span[10..]);
            if (questionCount != 1 || answerCount != 0 || authorityCount != 0 || additionalCount != 0)
            {
                return new DnsReadResult(
                    DnsReadOutcome.ErrorResponse,
                    DnsReadFailure.InvalidHeader,
                    formatErrorResponse);
            }

            const int nameOffset = HeaderLength;
            var offset = nameOffset;
            var nameHashCode = DnsName.StartWireHash();

            while (true)
            {
                if ((uint)offset >= (uint)span.Length)
                {
                    return new DnsReadResult(
                        DnsReadOutcome.ErrorResponse,
                        DnsReadFailure.InvalidName,
                        formatErrorResponse);
                }

                var labelLength = span[offset++];
                nameHashCode = DnsName.AppendWireHash(nameHashCode, labelLength);
                if (labelLength == 0)
                    break;

                if ((labelLength & 0xC0) != 0
                    || labelLength > span.Length - offset
                    || offset + labelLength - nameOffset + 1 > 255)
                {
                    return new DnsReadResult(
                        DnsReadOutcome.ErrorResponse,
                        DnsReadFailure.InvalidName,
                        formatErrorResponse);
                }

                var labelEndOffset = offset + labelLength;
                while (offset < labelEndOffset)
                {
                    nameHashCode = DnsName.AppendWireHash(nameHashCode, span[offset]);
                    offset++;
                }
            }

            var nameLength = offset - nameOffset;
            if (nameLength > 255)
            {
                return new DnsReadResult(
                    DnsReadOutcome.ErrorResponse,
                    DnsReadFailure.InvalidName,
                    formatErrorResponse);
            }

            if (span.Length - offset < 4)
            {
                return new DnsReadResult(
                    DnsReadOutcome.ErrorResponse,
                    DnsReadFailure.TruncatedQuestion,
                    formatErrorResponse);
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(span[offset..]);
            var @class = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 2)..]);
            offset += 4;

            if (offset != span.Length)
            {
                return new DnsReadResult(
                    DnsReadOutcome.ErrorResponse,
                    DnsReadFailure.TrailingData,
                    formatErrorResponse);
            }

            var lookupHashCode = DnsName.ComputeQuestionHash(nameHashCode, type, @class);
            queryContext.Set(
                datagram,
                transactionId,
                flags,
                operation,
                nameOffset,
                nameLength,
                type,
                @class,
                lookupHashCode,
                offset);

            return new DnsReadResult(DnsReadOutcome.Query);
        }
        catch (Exception exception)
        {
            var serverFailureResponse = new DnsErrorResponse(
                transactionId,
                operation,
                recursionDesired,
                ResponseCode.ServerFailure);

            return new DnsReadResult(
                DnsReadOutcome.ErrorResponse,
                DnsReadFailure.UnexpectedException,
                serverFailureResponse,
                exception);
        }
    }
}
