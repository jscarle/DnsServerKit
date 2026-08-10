using System.Buffers.Binary;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Records;

namespace DnsServerKit.Internal.Responses;

internal static class DnsWriter
{
    private const int HeaderLength = 12;
    private const int ResourceRecordHeaderLength = 12;
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
            queryDatagram[HeaderLength..query.QuestionEndOffset]
                .CopyTo(destination[HeaderLength..]);

        var responseFlags = (ushort)(0x8000
                                     | (query.Operation << 11)
                                     | (response.AuthoritativeAnswer ? 0x0400 : 0)
                                     | (query.RecursionDesired ? 0x0100 : 0)
                                     | (response.RecursionAvailable ? 0x0080 : 0)
                                     | (byte)response.ResponseCode);

        var position = query.QuestionEndOffset;
        ushort answerCount = 0;
        var answerSet = response.AnswerSet;
        if (answerSet is not null)
            switch (answerSet)
            {
                case ARecordSet addressRecordSet:
                {
                    if (addressRecordSet.Records is not IReadOnlyList<ARecord> records)
                        throw new InvalidOperationException("The A record set has not been prepared for DNS writing.");

                    for (var recordIndex = 0; recordIndex < records.Count; recordIndex++)
                    {
                        var record = records[recordIndex];
                        const int resourceDataLength = 4;
                        var recordLength = ResourceRecordHeaderLength + resourceDataLength;
                        if (position + recordLength > maximumLength)
                            break;

                        WriteResourceRecordHeader(destination[position..], (ushort)RecordType.A, query.Question.Class, addressRecordSet.Ttl, resourceDataLength
                        );
                        WriteIpv4Address(record.Address.AsSpan(), destination[(position + ResourceRecordHeaderLength)..]);
                        position += recordLength;
                        answerCount++;
                    }

                    break;
                }

                case PtrRecordSet pointerRecordSet:
                {
                    if (pointerRecordSet.Records is not IReadOnlyList<PtrRecord> records)
                        throw new InvalidOperationException("The PTR record set has not been prepared for DNS writing.");

                    Span<byte> encodedTarget = stackalloc byte[255];
                    for (var recordIndex = 0; recordIndex < records.Count; recordIndex++)
                    {
                        var record = records[recordIndex];
                        var resourceDataLength = DnsName.Encode(record.Target.AsSpan(), encodedTarget);
                        var recordLength = ResourceRecordHeaderLength + resourceDataLength;
                        if (position + recordLength > maximumLength)
                            break;

                        WriteResourceRecordHeader(destination[position..], (ushort)RecordType.Ptr, query.Question.Class, pointerRecordSet.Ttl,
                            resourceDataLength
                        );
                        encodedTarget[..resourceDataLength]
                            .CopyTo(destination[(position + ResourceRecordHeaderLength)..]);
                        position += recordLength;
                        answerCount++;
                    }

                    break;
                }

                case NsRecordSet nameServerRecordSet:
                {
                    if (nameServerRecordSet.Records is not IReadOnlyList<NsRecord> records)
                        throw new InvalidOperationException("The NS record set has not been prepared for DNS writing.");

                    Span<byte> encodedNameServer = stackalloc byte[255];
                    for (var recordIndex = 0; recordIndex < records.Count; recordIndex++)
                    {
                        var record = records[recordIndex];
                        var resourceDataLength = DnsName.Encode(record.NameServer.AsSpan(), encodedNameServer);
                        var recordLength = ResourceRecordHeaderLength + resourceDataLength;
                        if (position + recordLength > maximumLength)
                            break;

                        WriteResourceRecordHeader(destination[position..], (ushort)RecordType.Ns, query.Question.Class, nameServerRecordSet.Ttl,
                            resourceDataLength
                        );
                        encodedNameServer[..resourceDataLength]
                            .CopyTo(destination[(position + ResourceRecordHeaderLength)..]);
                        position += recordLength;
                        answerCount++;
                    }

                    break;
                }

                case SoaRecordSet startOfAuthorityRecordSet:
                {
                    Span<byte> encodedPrimaryNameServer = stackalloc byte[255];
                    Span<byte> encodedResponsibleMailbox = stackalloc byte[255];
                    var record = startOfAuthorityRecordSet.Record;
                    var primaryNameServerLength = DnsName.Encode(record.PrimaryNameServer.AsSpan(), encodedPrimaryNameServer);
                    var responsibleMailboxLength = EncodeResponsibleMailbox(record.ResponsibleMailbox.AsSpan(), encodedResponsibleMailbox);
                    var resourceDataLength = primaryNameServerLength + responsibleMailboxLength + 20;
                    var recordLength = ResourceRecordHeaderLength + resourceDataLength;

                    if (position + recordLength <= maximumLength)
                    {
                        WriteResourceRecordHeader(destination[position..], (ushort)RecordType.Soa, query.Question.Class, startOfAuthorityRecordSet.Ttl,
                            resourceDataLength
                        );

                        var resourceData = destination[(position + ResourceRecordHeaderLength)..];
                        encodedPrimaryNameServer[..primaryNameServerLength]
                            .CopyTo(resourceData);
                        encodedResponsibleMailbox[..responsibleMailboxLength]
                            .CopyTo(resourceData[primaryNameServerLength..]);
                        var numericFields = resourceData[(primaryNameServerLength + responsibleMailboxLength)..];
                        BinaryPrimitives.WriteUInt32BigEndian(numericFields, record.Serial);
                        BinaryPrimitives.WriteUInt32BigEndian(numericFields[4..], record.Refresh);
                        BinaryPrimitives.WriteUInt32BigEndian(numericFields[8..], record.Retry);
                        BinaryPrimitives.WriteUInt32BigEndian(numericFields[12..], record.Expire);
                        BinaryPrimitives.WriteUInt32BigEndian(numericFields[16..], record.Minimum);

                        position += recordLength;
                        answerCount++;
                    }

                    break;
                }

                default:
                    throw new NotSupportedException($"The '{answerSet.GetType().Name}' DNS record set type is not supported.");
            }

        if (answerSet is not null && answerCount != answerSet.Count)
            responseFlags |= 0x0200;

        destination[..HeaderLength]
            .Clear();
        BinaryPrimitives.WriteUInt16BigEndian(destination, query.TransactionId);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], responseFlags);
        BinaryPrimitives.WriteUInt16BigEndian(destination[4..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(destination[6..], answerCount);

        return position;
    }

    /// <summary>Writes a minimal DNS error response into the specified destination.</summary>
    public static int WriteErrorResponse(Span<byte> destination, DnsErrorResponse errorResponse, bool recursionAvailable)
    {
        if (destination.Length < HeaderLength)
            throw new ArgumentException("The destination must contain at least 12 bytes.", nameof(destination));
        if (errorResponse.Operation > 0x0F)
            throw new ArgumentOutOfRangeException(nameof(errorResponse), "The DNS operation must fit in the four-bit OpCode field.");
        if ((byte)errorResponse.ResponseCode > 0x0F)
            throw new NotSupportedException("Extended DNS response codes require an OPT record and are not supported.");

        destination[..HeaderLength]
            .Clear();
        BinaryPrimitives.WriteUInt16BigEndian(destination, errorResponse.TransactionId);

        var flags = (ushort)(0x8000
                             | (errorResponse.Operation << 11)
                             | (errorResponse.RecursionDesired ? 0x0100 : 0)
                             | (recursionAvailable ? 0x0080 : 0)
                             | (byte)errorResponse.ResponseCode);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], flags);

        return HeaderLength;
    }

    private static void WriteResourceRecordHeader(Span<byte> destination, ushort type, ushort @class, uint ttl, int resourceDataLength)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, 0xC00C);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], type);
        BinaryPrimitives.WriteUInt16BigEndian(destination[4..], @class);
        BinaryPrimitives.WriteUInt32BigEndian(destination[6..], ttl);
        BinaryPrimitives.WriteUInt16BigEndian(destination[10..], (ushort)resourceDataLength);
    }

    private static void WriteIpv4Address(ReadOnlySpan<char> address, Span<byte> destination)
    {
        var addressOffset = 0;
        for (var octetIndex = 0; octetIndex < 4; octetIndex++)
        {
            var octet = 0;
            var digitCount = 0;
            while (addressOffset < address.Length && address[addressOffset] != '.')
            {
                var character = address[addressOffset++];
                if (character is < '0' or > '9')
                    throw new FormatException("An A record address must use dotted-decimal IPv4 notation.");

                octet = octet * 10 + (character - '0');
                digitCount++;
                if (digitCount > 3 || octet > byte.MaxValue)
                    throw new FormatException("An A record address must use dotted-decimal IPv4 notation.");
            }

            if (digitCount == 0)
                throw new FormatException("An A record address must use dotted-decimal IPv4 notation.");

            destination[octetIndex] = (byte)octet;
            if (octetIndex < 3)
            {
                if (addressOffset >= address.Length || address[addressOffset] != '.')
                    throw new FormatException("An A record address must use dotted-decimal IPv4 notation.");

                addressOffset++;
            }
        }

        if (addressOffset != address.Length)
            throw new FormatException("An A record address must use dotted-decimal IPv4 notation.");
    }

    private static int EncodeResponsibleMailbox(ReadOnlySpan<char> responsibleMailbox, Span<byte> destination)
    {
        var separatorIndex = responsibleMailbox.LastIndexOf('@');
        if (separatorIndex <= 0 || separatorIndex == responsibleMailbox.Length - 1 || separatorIndex > 63)
            throw new FormatException("An SOA responsible mailbox must use canonical user@host form.");

        destination[0] = (byte)separatorIndex;
        for (var characterIndex = 0; characterIndex < separatorIndex; characterIndex++)
        {
            var character = responsibleMailbox[characterIndex];
            if (character > byte.MaxValue)
                throw new FormatException("An SOA responsible mailbox local part must contain one-octet characters.");

            destination[characterIndex + 1] = DnsName.ToLowerAscii((byte)character);
        }

        var host = responsibleMailbox[(separatorIndex + 1)..];
        var hostLength = DnsName.Encode(host, destination[(separatorIndex + 1)..]);
        return separatorIndex + 1 + hostLength;
    }
}
