using System.Buffers.Binary;
using DnsServerKit.Parameters;
using DnsServerKit.Queries;
using DnsServerKit.Responses;
using LightResults;

namespace DnsServerKit;

public sealed class DnsReader
{
    /// <summary>Attempts to create a new instance of the <see cref="DnsQuery"/> class from the specified memory buffer.</summary>
    /// <param name="memory">The memory buffer containing the bytes of the DNS query.</param>
    /// <returns>Returns a result containing the created <see cref="DnsQuery"/> if the creation succeeded, or an error if it failed.</returns>
    public static Result<DnsQuery> TryReadBytes(Memory<byte> memory)
    {
        const int headerLength = 12;
        if (memory.Length < headerLength)
        {
            var error = new DnsReadError("Could not process the DNS query. The DNS header is truncated.");
            return Result.Failure<DnsQuery>(error);
        }

        var span = memory.Span;
        var transactionId = BinaryPrimitives.ReadUInt16BigEndian(span);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(span[2..]);
        var operation = (DnsOperation)((flags & 0x7800) >> 11);
        var recursionDesired = (flags & 0x0100) != 0;

        if ((flags & 0x8000) != 0)
        {
            var error = new DnsReadError("Could not process the DNS query. The message is a response.");
            return Result.Failure<DnsQuery>(error);
        }

        if (operation != DnsOperation.Query)
        {
            var response = new DnsErrorResponse(
                transactionId,
                operation,
                recursionDesired,
                ResponseCode.NotImplemented);
            var error = new DnsReadError("Could not process the DNS query. The operation is not implemented.", response);

            return Result.Failure<DnsQuery>(error);
        }

        var formatErrorResponse = new DnsErrorResponse(
            transactionId,
            operation,
            recursionDesired,
            ResponseCode.FormatError);

        var authoritativeAnswer = (flags & 0x0400) != 0;
        if (authoritativeAnswer)
        {
            var error = new DnsReadError("Could not process the DNS query. The AA flag is invalid in a query.", formatErrorResponse);
            return Result.Failure<DnsQuery>(error);
        }

        var recursionAvailable = (flags & 0x0080) != 0;
        if (recursionAvailable)
        {
            var error = new DnsReadError("Could not process the DNS query. The RA flag is invalid in a query.", formatErrorResponse);
            return Result.Failure<DnsQuery>(error);
        }

        var reservedFlag = (flags & 0x0040) != 0;
        if (reservedFlag)
        {
            var error = new DnsReadError("Could not process the DNS query. The reserved Z flag is not zero.", formatErrorResponse);
            return Result.Failure<DnsQuery>(error);
        }

        var responseCode = (byte)(flags & 0x000F);
        if (responseCode != 0)
        {
            var error = new DnsReadError("Could not process the DNS query. The response code is not zero.", formatErrorResponse);
            return Result.Failure<DnsQuery>(error);
        }

        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(span[4..]);
        if (questionCount != 1)
        {
            var error = new DnsReadError("Could not process the DNS query. QDCOUNT must be one.", formatErrorResponse);
            return Result.Failure<DnsQuery>(error);
        }

        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(span[6..]);
        if (answerCount != 0)
        {
            var error = new DnsReadError("Could not process the DNS query. ANCOUNT must be zero.", formatErrorResponse);
            return Result.Failure<DnsQuery>(error);
        }

        var authorityCount = BinaryPrimitives.ReadUInt16BigEndian(span[8..]);
        if (authorityCount != 0)
        {
            var error = new DnsReadError("Could not process the DNS query. NSCOUNT must be zero.", formatErrorResponse);
            return Result.Failure<DnsQuery>(error);
        }

        var additionalCount = BinaryPrimitives.ReadUInt16BigEndian(span[10..]);
        if (additionalCount != 0)
        {
            var error = new DnsReadError("Could not process the DNS query. ARCOUNT must be zero.", formatErrorResponse);
            return Result.Failure<DnsQuery>(error);
        }

        try
        {
            var questions = new List<DnsQuestion>(1);
            var offset = headerLength;
            var name = NameHelper.DecodeDnsName(span, ref offset);
            if (span.Length - offset < 4)
            {
                var error = new DnsReadError("Could not process the DNS query. The question is truncated.", formatErrorResponse);
                return Result.Failure<DnsQuery>(error);
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(span[offset..]);
            var @class = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 2)..]);
            offset += 4;

            if (offset != span.Length)
            {
                var error = new DnsReadError("Could not process the DNS query. The message contains uncounted trailing data.", formatErrorResponse);
                return Result.Failure<DnsQuery>(error);
            }

            var question = new DnsQuestion
            {
                Name = name,
                Type = (RecordType)type,
                Class = (DnsClass)@class,
            };
            questions.Add(question);

            var truncated = (flags & 0x0200) != 0;
            var dnsQuery = new DnsQuery(
                transactionId,
                false,
                operation,
                false,
                truncated,
                recursionDesired,
                false,
                0,
                ResponseCode.NoError,
                questionCount,
                answerCount,
                authorityCount,
                additionalCount,
                questions);

            return Result.Success(dnsQuery);
        }
        catch (FormatException exception)
        {
            var error = new DnsReadError(
                "Could not process the DNS query. The question format is invalid.",
                exception,
                formatErrorResponse);

            return Result.Failure<DnsQuery>(error);
        }
        catch (Exception exception)
        {
            var serverFailureResponse = new DnsErrorResponse(
                transactionId,
                operation,
                recursionDesired,
                ResponseCode.ServerFailure);
            var error = new DnsReadError(
                "Could not process the DNS query because of an unexpected error.",
                exception,
                serverFailureResponse);

            return Result.Failure<DnsQuery>(error);
        }
    }
}
