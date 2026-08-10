using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using DnsServerKit.Queries;
using DnsServerKit.ResourceRecords;
using DnsServerKit.Responses;
using JetBrains.Annotations;

namespace DnsServerKit;

[MustDisposeResource]
public sealed class DnsWriter(DnsResponse dnsResponse) : IDisposable
{
    private const int MaximumUdpMessageLength = 512;
    private readonly Dictionary<string, int> _namePositions = new(StringComparer.Ordinal);
    private byte[]? _bytes;
    private int _length;
    private bool _disposed;

    public ReadOnlyMemory<byte> GetBytes()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(DnsWriter));

        if (_bytes is not null)
            return new ReadOnlyMemory<byte>(_bytes, 0, _length);

        if ((byte)dnsResponse.RCode > 0x0F)
            throw new NotSupportedException("Extended DNS response codes require an OPT record and are not supported by this writer.");

        _namePositions.Clear();
        using var memoryStream = new MemoryStream(MaximumUdpMessageLength);

        WriteHeader(memoryStream, dnsResponse, dnsResponse.TC, dnsResponse.QDCount, dnsResponse.ANCount);

        ushort writtenQuestionCount = 0;
        var isTruncated = false;
        foreach (var question in dnsResponse.Questions)
        {
            var questionStartPosition = memoryStream.Position;
            WriteName(memoryStream, question.Name);
            WriteQuestion(memoryStream, question);

            if (memoryStream.Position > MaximumUdpMessageLength)
            {
                memoryStream.SetLength(questionStartPosition);
                memoryStream.Position = questionStartPosition;
                isTruncated = true;
                break;
            }

            writtenQuestionCount++;
        }

        ushort writtenAnswerCount = 0;
        if (!isTruncated)
        {
            foreach (var answer in dnsResponse.Answers)
            {
                var answerStartPosition = memoryStream.Position;
                WriteName(memoryStream, answer.Name);
                WriteAnswer(memoryStream, answer);
                WriteAnswerData(memoryStream, answer);

                if (memoryStream.Position > MaximumUdpMessageLength)
                {
                    memoryStream.SetLength(answerStartPosition);
                    memoryStream.Position = answerStartPosition;
                    isTruncated = true;
                    break;
                }

                writtenAnswerCount++;
            }
        }

        var messageEndPosition = memoryStream.Position;
        memoryStream.Position = 0;
        WriteHeader(
            memoryStream,
            dnsResponse,
            dnsResponse.TC || isTruncated,
            writtenQuestionCount,
            writtenAnswerCount);
        memoryStream.Position = messageEndPosition;

        var memory = ToReadOnlyMemory(memoryStream);
        return memory;
    }

    /// <summary>Writes a minimal DNS error response into the specified destination.</summary>
    /// <param name="destination">The destination that receives the 12-byte DNS response header.</param>
    /// <param name="errorResponse">The trusted request header values and response code.</param>
    /// <param name="recursionAvailable">Whether the responding server supports recursive queries.</param>
    /// <returns>The number of bytes written.</returns>
    public static int WriteErrorResponse(
        Span<byte> destination,
        DnsErrorResponse errorResponse,
        bool recursionAvailable)
    {
        const int headerLength = 12;
        if (destination.Length < headerLength)
            throw new ArgumentException("The destination must contain at least 12 bytes.", nameof(destination));

        var operation = (byte)errorResponse.Operation;
        if (operation > 0x0F)
            throw new ArgumentOutOfRangeException(nameof(errorResponse), "The DNS operation must fit in the four-bit OpCode field.");

        var responseCode = (byte)errorResponse.ResponseCode;
        if (responseCode > 0x0F)
            throw new NotSupportedException("Extended DNS response codes require an OPT record and are not supported by this writer.");

        destination[..headerLength].Clear();
        BinaryPrimitives.WriteUInt16BigEndian(destination, errorResponse.TransactionId);

        var flags = (ushort)(0x8000
                             | (operation << 11)
                             | (errorResponse.RecursionDesired ? 0x0100 : 0)
                             | (recursionAvailable ? 0x0080 : 0)
                             | responseCode);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], flags);

        return headerLength;
    }

    private static void WriteHeader(
        MemoryStream memoryStream,
        DnsResponse dnsResponse,
        bool isTruncated,
        ushort questionCount,
        ushort answerCount)
    {
        var bytes = ArrayPool<byte>.Shared.Rent(12);

        // Transaction ID
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0, 2), dnsResponse.ID);

        // Flags
        var flags = (ushort)((dnsResponse.QR ? 0x8000 : 0)
                             | ((ushort)dnsResponse.OpCode << 11)
                             | (dnsResponse.AA ? 0x0400 : 0)
                             | (isTruncated ? 0x0200 : 0)
                             | (dnsResponse.RD ? 0x0100 : 0)
                             | (dnsResponse.RA ? 0x0080 : 0)
                             | (dnsResponse.Z << 4)
                             | (ushort)dnsResponse.RCode);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2, 2), flags);

        // Question Count
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4, 2), questionCount);

        // Answer Record Count
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6, 2), answerCount);

        // Authority Record Count
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8, 2), dnsResponse.NSCount);

        // Additional Record Count
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10, 2), dnsResponse.ARCount);

        // Write header
        memoryStream.Write(bytes, 0, 12);
        
        ArrayPool<byte>.Shared.Return(bytes);
    }

    private static void WriteQuestion(MemoryStream memoryStream, DnsQuestion question)
    {
        var bytes = ArrayPool<byte>.Shared.Rent(4);

        // Encode Type
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0, 2), (ushort)question.Type);

        // Encode Class
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2, 2), (ushort)question.Class);

        // Write question
        memoryStream.Write(bytes, 0, 4);
        
        ArrayPool<byte>.Shared.Return(bytes);
    }

    private static void WriteAnswer(MemoryStream memoryStream, IResourceRecord resourceRecord)
    {
        var bytes = ArrayPool<byte>.Shared.Rent(8);

        // Encode Type
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0, 2), (ushort)resourceRecord.Type);

        // Encode Class
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2, 2), (ushort)resourceRecord.Class);

        // Encode TTL
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4, 4), resourceRecord.Ttl);

        // Write answer
        memoryStream.Write(bytes, 0, 8);
        
        ArrayPool<byte>.Shared.Return(bytes);
    }

    private void WriteAnswerData(MemoryStream memoryStream, IResourceRecord answer)
    {
        if (answer is ARecord aRecord)
            WriteARecord(memoryStream, aRecord);

        if (answer is PtrRecord ptrRecord)
        {
            var resourceDataLengthPosition = memoryStream.Position;
            WriteLength(memoryStream, 0);

            var resourceDataStartPosition = memoryStream.Position;
            WriteName(memoryStream, ptrRecord.TargetName);
            var resourceDataEndPosition = memoryStream.Position;
            var resourceDataLength = checked((ushort)(resourceDataEndPosition - resourceDataStartPosition));

            memoryStream.Position = resourceDataLengthPosition;
            WriteLength(memoryStream, resourceDataLength);
            memoryStream.Position = resourceDataEndPosition;
        }
    }

    private static void WriteARecord(MemoryStream memoryStream, ARecord aRecord)
    {
        // Encode IP address
        var ipAddressBytes = aRecord.IpAddress.GetAddressBytes();
        
        // Calculate total length
        var length = (ushort)ipAddressBytes.Length;

        // Write record
        WriteLength(memoryStream, length);
        memoryStream.Write(ipAddressBytes, 0, ipAddressBytes.Length);
    }

    private static void WriteLength(MemoryStream memoryStream, ushort length)
    {
        var bytes = ArrayPool<byte>.Shared.Rent(2);

        // Encode data length
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0, 2), length);

        memoryStream.Write(bytes, 0, 2);
        
        ArrayPool<byte>.Shared.Return(bytes);
    }

    private void WriteName(MemoryStream memoryStream, string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        if (name.Length == 0 || name.Equals(".", StringComparison.Ordinal))
        {
            memoryStream.WriteByte(0);
            return;
        }

        var labels = new List<byte[]>();
        var currentLabelBytes = new List<byte>(Math.Min(name.Length, 63));
        var characterIndex = 0;
        while (characterIndex < name.Length)
        {
            var character = name[characterIndex];
            if (character == '.')
            {
                if (currentLabelBytes.Count == 0)
                    throw new FormatException("A DNS name cannot contain an empty label.");

                labels.Add(currentLabelBytes.ToArray());
                currentLabelBytes.Clear();
                characterIndex++;
                continue;
            }

            byte labelByte;
            if (character == '\\')
            {
                characterIndex++;
                if (characterIndex >= name.Length)
                    throw new FormatException("A DNS name cannot end with an incomplete escape sequence.");

                var escapedCharacter = name[characterIndex];
                if (escapedCharacter is >= '0' and <= '9')
                {
                    if (characterIndex + 2 >= name.Length
                        || name[characterIndex + 1] is < '0' or > '9'
                        || name[characterIndex + 2] is < '0' or > '9')
                    {
                        throw new FormatException("A numeric DNS name escape must contain exactly three decimal digits.");
                    }

                    var escapedOctet = ((escapedCharacter - '0') * 100)
                                       + ((name[characterIndex + 1] - '0') * 10)
                                       + (name[characterIndex + 2] - '0');
                    if (escapedOctet > byte.MaxValue)
                        throw new FormatException("A numeric DNS name escape cannot exceed 255.");

                    labelByte = (byte)escapedOctet;
                    characterIndex += 3;
                }
                else
                {
                    if (escapedCharacter > byte.MaxValue)
                        throw new FormatException("A DNS label character cannot exceed one octet.");

                    labelByte = (byte)escapedCharacter;
                    characterIndex++;
                }
            }
            else
            {
                if (character > byte.MaxValue)
                    throw new FormatException("A DNS label character cannot exceed one octet.");

                labelByte = (byte)character;
                characterIndex++;
            }

            currentLabelBytes.Add(labelByte);
            if (currentLabelBytes.Count > 63)
                throw new FormatException("A DNS label cannot exceed 63 octets.");
        }

        if (currentLabelBytes.Count > 0)
            labels.Add(currentLabelBytes.ToArray());

        var uncompressedNameLength = 1;
        foreach (var labelBytes in labels)
        {
            uncompressedNameLength += labelBytes.Length + 1;
            if (uncompressedNameLength > 255)
                throw new FormatException("A DNS name cannot exceed 255 octets.");
        }

        for (var i = 0; i < labels.Count; i++)
        {
            var suffixKeyBuilder = new StringBuilder();
            for (var suffixIndex = i; suffixIndex < labels.Count; suffixIndex++)
            {
                var suffixLabelBytes = labels[suffixIndex];
                suffixKeyBuilder.Append((char)suffixLabelBytes.Length);
                foreach (var suffixLabelByte in suffixLabelBytes)
                    suffixKeyBuilder.Append((char)suffixLabelByte);
            }

            var suffixKey = suffixKeyBuilder.ToString();
            if (_namePositions.TryGetValue(suffixKey, out var position) && position <= 0x3FFF)
            {
                // Write pointer to the existing label
                var pointer = (ushort)(0xC000 | position);
                var pointerBytes = ArrayPool<byte>.Shared.Rent(2);
                BinaryPrimitives.WriteUInt16BigEndian(pointerBytes.AsSpan(0, 2), pointer);
                memoryStream.Write(pointerBytes, 0, 2);
                ArrayPool<byte>.Shared.Return(pointerBytes);
                return;
            }

            // Write the label length and content
            var labelBytes = labels[i];
            memoryStream.WriteByte((byte)labelBytes.Length);
            memoryStream.Write(labelBytes);
            // Store position of this label
            _namePositions[suffixKey] = (int)memoryStream.Position - labelBytes.Length - 1;
        }
        // Write the final zero byte
        memoryStream.WriteByte(0);
    }

    private ReadOnlyMemory<byte> ToReadOnlyMemory(MemoryStream memoryStream)
    {
        var length = (int)memoryStream.Position;
        
        _bytes = ArrayPool<byte>.Shared.Rent(length);
        _length = length;
        
        memoryStream.Position = 0;
        memoryStream.ReadExactly(_bytes, 0, length);
        
        var memory = new ReadOnlyMemory<byte>(_bytes, 0, length);
        
        return memory;
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        if (_bytes is not null)
        {
            ArrayPool<byte>.Shared.Return(_bytes);
            _bytes = null;
        }
    }
}
