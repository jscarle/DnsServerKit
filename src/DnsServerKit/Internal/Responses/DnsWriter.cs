using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using DnsServerKit.Internal.Lookup;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Records;

namespace DnsServerKit.Internal.Responses;

internal static class DnsWriter
{
    private const int HeaderLength = 12;
    private const int ResourceRecordFieldsLength = 10;
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
                                     | (ushort)response.ResponseCode);

        var position = query.QuestionEndOffset;
        ushort answerCount = 0;
        ushort authorityCount = 0;
        ushort additionalCount = 0;
        var truncated = false;
        var resolution = response.Resolution;

        if (resolution is null)
        {
            var answerSet = response.AnswerSet;
            if (answerSet is not null)
            {
                var type = GetRecordType(answerSet);
                var requiredLength = checked(answerSet.Count * 12 + GetResourceDataLength(answerSet));
                if (TryWriteRecordSet(destination, maximumLength, ref position, query, null, type, query.Question.Class, answerSet, answerSet.Ttl,
                        requiredLength, null))
                    answerCount = checked((ushort)answerSet.Count);
                else
                    truncated = true;
            }
        }
        else
        {
            if (resolution.HasDirectAnswer)
            {
                var indexedRecordSet = resolution.GetAnswerSet(0);
                if (indexedRecordSet.RecordSet is ARecordSet addressRecordSet)
                {
                    if (addressRecordSet.Records is not IReadOnlyList<ARecord> records)
                        throw new InvalidOperationException("The A record set has not been prepared for DNS writing.");

                    if (position + indexedRecordSet.CompressedWireLength <= maximumLength)
                    {
                        for (var recordIndex = 0; recordIndex < records.Count; recordIndex++)
                        {
                            const int resourceDataLength = 4;
                            var headerLength = WriteResourceRecordHeader(destination[position..], null, query.Question, indexedRecordSet.Type,
                                indexedRecordSet.Class, addressRecordSet.Ttl, resourceDataLength);
                            WriteIpv4Address(records[recordIndex].Address, destination[(position + headerLength)..]);
                            position += headerLength + resourceDataLength;
                        }

                        answerCount = checked((ushort)records.Count);
                    }
                    else
                    {
                        truncated = true;
                    }
                }
                else
                {
                    if (TryWriteRecordSet(destination, maximumLength, ref position, query, null, indexedRecordSet.Type,
                            indexedRecordSet.Class, indexedRecordSet.RecordSet, indexedRecordSet.RecordSet.Ttl, indexedRecordSet.CompressedWireLength,
                            indexedRecordSet))
                    {
                        answerCount = checked((ushort)indexedRecordSet.RecordSet.Count);
                    }
                    else
                    {
                        truncated = true;
                    }
                }
            }
            else
            {
                for (var answerSetIndex = 0; answerSetIndex < resolution.AnswerSetCount; answerSetIndex++)
                {
                    var indexedRecordSet = resolution.GetAnswerSet(answerSetIndex);
                    var owner = indexedRecordSet.Owner.WireEquals(query.Question.EncodedName) ? null : indexedRecordSet.Owner;
                    var requiredLength = owner is null ? indexedRecordSet.CompressedWireLength : indexedRecordSet.UncompressedWireLength;
                    if (!TryWriteRecordSet(destination, maximumLength, ref position, query, owner, indexedRecordSet.Type,
                            indexedRecordSet.Class, indexedRecordSet.RecordSet, indexedRecordSet.RecordSet.Ttl, requiredLength, indexedRecordSet))
                    {
                        truncated = true;
                        break;
                    }

                    answerCount = checked((ushort)(answerCount + indexedRecordSet.RecordSet.Count));
                }

                if (!truncated && resolution.HasAuthoritySet)
                {
                    var authoritySet = resolution.AuthoritySet;
                    var owner = authoritySet.Owner.WireEquals(query.Question.EncodedName) ? null : authoritySet.Owner;
                    var requiredLength = owner is null ? authoritySet.CompressedWireLength : authoritySet.UncompressedWireLength;
                    if (TryWriteRecordSet(destination, maximumLength, ref position, query, owner, authoritySet.Type, authoritySet.Class,
                            authoritySet.RecordSet, resolution.AuthorityTtl, requiredLength, authoritySet))
                    {
                        authorityCount = checked((ushort)authoritySet.RecordSet.Count);
                    }
                    else
                    {
                        truncated = true;
                    }
                }

                if (!truncated)
                {
                    var requiredAdditionalSets = resolution.RequiredAdditionalSets;
                    for (var setIndex = 0; setIndex < requiredAdditionalSets.Length; setIndex++)
                    {
                        var additionalSet = requiredAdditionalSets[setIndex];
                        var owner = additionalSet.Owner.WireEquals(query.Question.EncodedName) ? null : additionalSet.Owner;
                        var requiredLength = owner is null ? additionalSet.CompressedWireLength : additionalSet.UncompressedWireLength;
                        if (!TryWriteRecordSet(destination, maximumLength, ref position, query, owner, additionalSet.Type, additionalSet.Class,
                                additionalSet.RecordSet, additionalSet.RecordSet.Ttl, requiredLength, additionalSet))
                        {
                            truncated = true;
                            break;
                        }

                        additionalCount = checked((ushort)(additionalCount + additionalSet.RecordSet.Count));
                    }
                }

                if (!truncated)
                {
                    var optionalAdditionalSets = resolution.OptionalAdditionalSets;
                    for (var setIndex = 0; setIndex < optionalAdditionalSets.Length; setIndex++)
                    {
                        var additionalSet = optionalAdditionalSets[setIndex];
                        var owner = additionalSet.Owner.WireEquals(query.Question.EncodedName) ? null : additionalSet.Owner;
                        var requiredLength = owner is null ? additionalSet.CompressedWireLength : additionalSet.UncompressedWireLength;
                        if (!TryWriteRecordSet(destination, maximumLength, ref position, query, owner, additionalSet.Type, additionalSet.Class,
                                additionalSet.RecordSet, additionalSet.RecordSet.Ttl, requiredLength, additionalSet))
                        {
                            continue;
                        }

                        additionalCount = checked((ushort)(additionalCount + additionalSet.RecordSet.Count));
                    }
                }
            }
        }

        if (truncated)
            responseFlags |= 0x0200;

        destination[..HeaderLength]
            .Clear();
        BinaryPrimitives.WriteUInt16BigEndian(destination, query.TransactionId);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], responseFlags);
        BinaryPrimitives.WriteUInt16BigEndian(destination[4..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(destination[6..], answerCount);
        BinaryPrimitives.WriteUInt16BigEndian(destination[8..], authorityCount);
        BinaryPrimitives.WriteUInt16BigEndian(destination[10..], additionalCount);

        return position;
    }

    private static bool TryWriteRecordSet(
        Span<byte> destination,
        int maximumLength,
        ref int position,
        DnsQueryContext query,
        DnsName? owner,
        ushort type,
        ushort @class,
        RecordSet recordSet,
        uint ttl,
        int requiredLength,
        DnsIndexedRecordSet? compiledRecordSet)
    {
        if (position + requiredLength > maximumLength)
            return false;

        switch (recordSet)
        {
            case ARecordSet addressRecordSet:
                if (addressRecordSet.Records is not IReadOnlyList<ARecord> ipv4Records)
                    throw new InvalidOperationException("The A record set has not been prepared for DNS writing.");
                for (var recordIndex = 0; recordIndex < ipv4Records.Count; recordIndex++)
                {
                    var record = ipv4Records[recordIndex];
                    const int resourceDataLength = 4;
                    var headerLength = WriteResourceRecordHeader(destination[position..], owner, query.Question, type, @class, ttl, resourceDataLength);
                    WriteIpv4Address(record.Address, destination[(position + headerLength)..]);
                    position += headerLength + resourceDataLength;
                }

                break;

            case AaaaRecordSet addressRecordSet:
                if (addressRecordSet.Records is not IReadOnlyList<AaaaRecord> ipv6Records)
                    throw new InvalidOperationException("The AAAA record set has not been prepared for DNS writing.");
                for (var recordIndex = 0; recordIndex < ipv6Records.Count; recordIndex++)
                {
                    var record = ipv6Records[recordIndex];
                    const int resourceDataLength = 16;
                    var headerLength = WriteResourceRecordHeader(destination[position..], owner, query.Question, type, @class, ttl, resourceDataLength);
                    WriteIpv6Address(record.Address, destination[(position + headerLength)..]);
                    position += headerLength + resourceDataLength;
                }

                break;

            case CnameRecordSet canonicalNameRecordSet:
                {
                    Span<byte> encodedTargetBuffer = stackalloc byte[255];
                    scoped ReadOnlySpan<byte> encodedTarget;
                    if (compiledRecordSet is null)
                    {
                        var encodedTargetLength = DnsName.Encode(canonicalNameRecordSet.Record.Target, encodedTargetBuffer);
                        encodedTarget = encodedTargetBuffer[..encodedTargetLength];
                    }
                    else
                    {
                        encodedTarget = compiledRecordSet.CompiledNames!.ResourceNames[0].WireBytes;
                    }

                    var resourceDataLength = encodedTarget.Length;
                    var headerLength = WriteResourceRecordHeader(destination[position..], owner, query.Question, type, @class, ttl, resourceDataLength);
                    encodedTarget.CopyTo(destination[(position + headerLength)..]);
                    position += headerLength + resourceDataLength;
                    break;
                }

            case MxRecordSet mailExchangeRecordSet:
                {
                    if (mailExchangeRecordSet.Records is not IReadOnlyList<MxRecord> records)
                        throw new InvalidOperationException("The MX record set has not been prepared for DNS writing.");
                    Span<byte> encodedExchange = stackalloc byte[255];
                    for (var recordIndex = 0; recordIndex < records.Count; recordIndex++)
                    {
                        var record = records[recordIndex];
                        scoped ReadOnlySpan<byte> exchange;
                        if (compiledRecordSet is null)
                        {
                            var exchangeLength = DnsName.Encode(record.Exchange, encodedExchange);
                            exchange = encodedExchange[..exchangeLength];
                        }
                        else
                        {
                            exchange = compiledRecordSet.CompiledNames!.ResourceNames[recordIndex].WireBytes;
                        }

                        var resourceDataLength = 2 + exchange.Length;
                        var headerLength = WriteResourceRecordHeader(destination[position..], owner, query.Question, type, @class, ttl, resourceDataLength);
                        var resourceData = destination[(position + headerLength)..];
                        BinaryPrimitives.WriteUInt16BigEndian(resourceData, record.Preference);
                        exchange.CopyTo(resourceData[2..]);
                        position += headerLength + resourceDataLength;
                    }

                    break;
                }

            case TxtRecordSet textRecordSet:
                if (textRecordSet.Records is not IReadOnlyList<TxtRecord> textRecords)
                    throw new InvalidOperationException("The TXT record set has not been prepared for DNS writing.");
                for (var recordIndex = 0; recordIndex < textRecords.Count; recordIndex++)
                {
                    var record = textRecords[recordIndex];
                    var resourceDataLength = GetTxtResourceDataLength(record.Text);
                    var headerLength = WriteResourceRecordHeader(destination[position..], owner, query.Question, type, @class, ttl, resourceDataLength);
                    WriteTxtResourceData(record.Text, destination[(position + headerLength)..]);
                    position += headerLength + resourceDataLength;
                }

                break;

            case PtrRecordSet pointerRecordSet:
                {
                    if (pointerRecordSet.Records is not IReadOnlyList<PtrRecord> records)
                        throw new InvalidOperationException("The PTR record set has not been prepared for DNS writing.");
                    Span<byte> encodedTarget = stackalloc byte[255];
                    for (var recordIndex = 0; recordIndex < records.Count; recordIndex++)
                    {
                        var record = records[recordIndex];
                        scoped ReadOnlySpan<byte> target;
                        if (compiledRecordSet is null)
                        {
                            var targetLength = DnsName.Encode(record.Target, encodedTarget);
                            target = encodedTarget[..targetLength];
                        }
                        else
                        {
                            target = compiledRecordSet.CompiledNames!.ResourceNames[recordIndex].WireBytes;
                        }

                        var resourceDataLength = target.Length;
                        var headerLength = WriteResourceRecordHeader(destination[position..], owner, query.Question, type, @class, ttl, resourceDataLength);
                        target.CopyTo(destination[(position + headerLength)..]);
                        position += headerLength + resourceDataLength;
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
                        scoped ReadOnlySpan<byte> nameServer;
                        if (compiledRecordSet is null)
                        {
                            var nameServerLength = DnsName.Encode(record.NameServer, encodedNameServer);
                            nameServer = encodedNameServer[..nameServerLength];
                        }
                        else
                        {
                            nameServer = compiledRecordSet.CompiledNames!.ResourceNames[recordIndex].WireBytes;
                        }

                        var resourceDataLength = nameServer.Length;
                        var headerLength = WriteResourceRecordHeader(destination[position..], owner, query.Question, type, @class, ttl, resourceDataLength);
                        nameServer.CopyTo(destination[(position + headerLength)..]);
                        position += headerLength + resourceDataLength;
                    }

                    break;
                }

            case SoaRecordSet startOfAuthorityRecordSet:
                {
                    Span<byte> encodedPrimaryNameServer = stackalloc byte[255];
                    Span<byte> encodedResponsibleMailbox = stackalloc byte[255];
                    var record = startOfAuthorityRecordSet.Record;
                    scoped ReadOnlySpan<byte> primaryNameServer;
                    scoped ReadOnlySpan<byte> responsibleMailbox;
                    if (compiledRecordSet is null)
                    {
                        var encodedPrimaryNameServerLength = DnsName.Encode(record.PrimaryNameServer, encodedPrimaryNameServer);
                        primaryNameServer = encodedPrimaryNameServer[..encodedPrimaryNameServerLength];
                        var encodedResponsibleMailboxLength = EncodeResponsibleMailbox(record.ResponsibleMailbox, encodedResponsibleMailbox);
                        responsibleMailbox = encodedResponsibleMailbox[..encodedResponsibleMailboxLength];
                    }
                    else
                    {
                        primaryNameServer = compiledRecordSet.CompiledNames!.ResourceNames[0].WireBytes;
                        responsibleMailbox = compiledRecordSet.CompiledNames.ResponsibleMailboxWireName;
                    }

                    var primaryNameServerLength = primaryNameServer.Length;
                    var responsibleMailboxLength = responsibleMailbox.Length;
                    var resourceDataLength = primaryNameServerLength + responsibleMailboxLength + 20;
                    var headerLength = WriteResourceRecordHeader(destination[position..], owner, query.Question, type, @class, ttl, resourceDataLength);
                    var resourceData = destination[(position + headerLength)..];
                    primaryNameServer.CopyTo(resourceData);
                    responsibleMailbox.CopyTo(resourceData[primaryNameServerLength..]);
                    var numericFields = resourceData[(primaryNameServerLength + responsibleMailboxLength)..];
                    BinaryPrimitives.WriteUInt32BigEndian(numericFields, record.Serial);
                    BinaryPrimitives.WriteUInt32BigEndian(numericFields[4..], record.Refresh);
                    BinaryPrimitives.WriteUInt32BigEndian(numericFields[8..], record.Retry);
                    BinaryPrimitives.WriteUInt32BigEndian(numericFields[12..], record.Expire);
                    BinaryPrimitives.WriteUInt32BigEndian(numericFields[16..], record.Minimum);
                    position += headerLength + resourceDataLength;
                    break;
                }

            default:
                throw new NotSupportedException($"The '{recordSet.GetType().Name}' DNS record set type is not supported.");
        }

        return true;
    }

    private static int GetResourceDataLength(RecordSet recordSet)
    {
        Span<byte> encodedName = stackalloc byte[255];
        var length = 0;

        switch (recordSet)
        {
            case ARecordSet addressRecordSet:
                return addressRecordSet.Count * 4;
            case AaaaRecordSet addressRecordSet:
                return addressRecordSet.Count * 16;
            case CnameRecordSet canonicalNameRecordSet:
                return DnsName.Encode(canonicalNameRecordSet.Record.Target, encodedName);
            case MxRecordSet mailExchangeRecordSet:
                if (mailExchangeRecordSet.Records is not IReadOnlyList<MxRecord> mailExchangeRecords)
                    throw new InvalidOperationException("The MX record set has not been prepared for DNS writing.");
                for (var recordIndex = 0; recordIndex < mailExchangeRecords.Count; recordIndex++)
                    length += 2 + DnsName.Encode(mailExchangeRecords[recordIndex].Exchange, encodedName);
                return length;
            case TxtRecordSet textRecordSet:
                if (textRecordSet.Records is not IReadOnlyList<TxtRecord> textRecords)
                    throw new InvalidOperationException("The TXT record set has not been prepared for DNS writing.");
                for (var recordIndex = 0; recordIndex < textRecords.Count; recordIndex++)
                    length += GetTxtResourceDataLength(textRecords[recordIndex].Text);
                return length;
            case PtrRecordSet pointerRecordSet:
                if (pointerRecordSet.Records is not IReadOnlyList<PtrRecord> pointerRecords)
                    throw new InvalidOperationException("The PTR record set has not been prepared for DNS writing.");
                for (var recordIndex = 0; recordIndex < pointerRecords.Count; recordIndex++)
                    length += DnsName.Encode(pointerRecords[recordIndex].Target, encodedName);
                return length;
            case NsRecordSet nameServerRecordSet:
                if (nameServerRecordSet.Records is not IReadOnlyList<NsRecord> nameServerRecords)
                    throw new InvalidOperationException("The NS record set has not been prepared for DNS writing.");
                for (var recordIndex = 0; recordIndex < nameServerRecords.Count; recordIndex++)
                    length += DnsName.Encode(nameServerRecords[recordIndex].NameServer, encodedName);
                return length;
            case SoaRecordSet startOfAuthorityRecordSet:
                var startOfAuthorityRecord = startOfAuthorityRecordSet.Record;
                var primaryNameServerLength = DnsName.Encode(startOfAuthorityRecord.PrimaryNameServer, encodedName);
                var responsibleMailboxLength = EncodeResponsibleMailbox(startOfAuthorityRecord.ResponsibleMailbox, encodedName);
                return primaryNameServerLength + responsibleMailboxLength + 20;
            default:
                throw new NotSupportedException($"The '{recordSet.GetType().Name}' DNS record set type is not supported.");
        }
    }

    private static int GetTxtResourceDataLength(string value)
    {
        var resourceDataLength = 1;
        var characterStringLength = 0;
        var text = value.AsSpan();
        while (!text.IsEmpty)
        {
            var status = Rune.DecodeFromUtf16(text, out var rune, out var charactersConsumed);
            if (status != OperationStatus.Done)
                throw new FormatException("A TXT record must contain valid Unicode text.");

            if (characterStringLength + rune.Utf8SequenceLength > byte.MaxValue)
            {
                resourceDataLength++;
                characterStringLength = 0;
            }

            resourceDataLength += rune.Utf8SequenceLength;
            characterStringLength += rune.Utf8SequenceLength;
            text = text[charactersConsumed..];
        }

        return resourceDataLength;
    }

    private static void WriteTxtResourceData(string value, Span<byte> resourceData)
    {
        var lengthOffset = 0;
        var resourceDataOffset = 1;
        var characterStringLength = 0;
        var text = value.AsSpan();
        while (!text.IsEmpty)
        {
            var status = Rune.DecodeFromUtf16(text, out var rune, out var charactersConsumed);
            if (status != OperationStatus.Done)
                throw new FormatException("A TXT record must contain valid Unicode text.");

            if (characterStringLength + rune.Utf8SequenceLength > byte.MaxValue)
            {
                resourceData[lengthOffset] = (byte)characterStringLength;
                lengthOffset = resourceDataOffset++;
                characterStringLength = 0;
            }

            var bytesWritten = rune.EncodeToUtf8(resourceData[resourceDataOffset..]);
            resourceDataOffset += bytesWritten;
            characterStringLength += bytesWritten;
            text = text[charactersConsumed..];
        }

        resourceData[lengthOffset] = (byte)characterStringLength;
    }

    /// <summary>Writes a minimal DNS error response into the specified destination.</summary>
    public static int WriteErrorResponse(Span<byte> destination, DnsErrorResponse errorResponse)
    {
        if (destination.Length < HeaderLength)
            throw new ArgumentException("The destination must contain at least 12 bytes.", nameof(destination));
        if (errorResponse.Operation > 0x0F)
            throw new ArgumentOutOfRangeException(nameof(errorResponse), "The DNS operation must fit in the four-bit OpCode field.");
        if ((ushort)errorResponse.ResponseCode > 0x0F)
            throw new NotSupportedException("Extended DNS response codes require an OPT record and are not supported.");

        destination[..HeaderLength]
            .Clear();
        BinaryPrimitives.WriteUInt16BigEndian(destination, errorResponse.TransactionId);

        var flags = (ushort)(0x8000
                             | (errorResponse.Operation << 11)
                             | (errorResponse.RecursionDesired ? 0x0100 : 0)
                             | (ushort)errorResponse.ResponseCode);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], flags);

        return HeaderLength;
    }

    private static int WriteResourceRecordHeader(
        Span<byte> destination,
        DnsName? owner,
        DnsQuestionContext question,
        ushort type,
        ushort @class,
        uint ttl,
        int resourceDataLength)
    {
        int ownerLength;
        if (owner is null || owner.WireEquals(question.EncodedName))
        {
            BinaryPrimitives.WriteUInt16BigEndian(destination, 0xC00C);
            ownerLength = 2;
        }
        else
        {
            owner.WireBytes.CopyTo(destination);
            ownerLength = owner.WireBytes.Length;
        }

        var fields = destination[ownerLength..];
        BinaryPrimitives.WriteUInt16BigEndian(fields, type);
        BinaryPrimitives.WriteUInt16BigEndian(fields[2..], @class);
        BinaryPrimitives.WriteUInt32BigEndian(fields[4..], ttl);
        BinaryPrimitives.WriteUInt16BigEndian(fields[8..], (ushort)resourceDataLength);

        return ownerLength + ResourceRecordFieldsLength;
    }

    private static ushort GetRecordType(RecordSet recordSet)
    {
        return recordSet switch
        {
            ARecordSet => (ushort)RecordType.A,
            AaaaRecordSet => (ushort)RecordType.Aaaa,
            CnameRecordSet => (ushort)RecordType.CName,
            MxRecordSet => (ushort)RecordType.Mx,
            PtrRecordSet => (ushort)RecordType.Ptr,
            NsRecordSet => (ushort)RecordType.Ns,
            SoaRecordSet => (ushort)RecordType.Soa,
            TxtRecordSet => (ushort)RecordType.Txt,
            _ => throw new NotSupportedException($"The '{recordSet.GetType().Name}' DNS record set type is not supported."),
        };
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

    private static void WriteIpv6Address(ReadOnlySpan<char> address, Span<byte> destination)
    {
        if (address.Length != 39)
            throw new FormatException("An AAAA record address must use normalized IPv6 notation.");

        var addressOffset = 0;
        for (var byteIndex = 0; byteIndex < 16; byteIndex++)
        {
            if (byteIndex > 0 && (byteIndex & 1) == 0 && address[addressOffset++] != ':')
                throw new FormatException("An AAAA record address must use normalized IPv6 notation.");

            var highCharacter = address[addressOffset++];
            var highValue = highCharacter switch
            {
                >= '0' and <= '9' => highCharacter - '0',
                >= 'a' and <= 'f' => highCharacter - 'a' + 10,
                _ => throw new FormatException("An AAAA record address must use normalized IPv6 notation."),
            };
            var lowCharacter = address[addressOffset++];
            var lowValue = lowCharacter switch
            {
                >= '0' and <= '9' => lowCharacter - '0',
                >= 'a' and <= 'f' => lowCharacter - 'a' + 10,
                _ => throw new FormatException("An AAAA record address must use normalized IPv6 notation."),
            };
            destination[byteIndex] = (byte)((highValue << 4) | lowValue);
        }
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
