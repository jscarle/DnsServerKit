using System.Buffers.Binary;
using DnsServerKit.Parameters;

namespace DnsServerKit.Queries;

/// <summary>Represents a DNS question.</summary>
public sealed record DnsQuestion
{
    /// <summary>Gets the name that is the subject of the DNS query.</summary>
    public required string Name { get; init; }

    /// <summary>Gets the type of DNS record being queried.</summary>
    public required RecordType Type { get; init; }

    /// <summary>Gets the class of the DNS query.</summary>
    public required DnsClass Class { get; init; }
    
    /// <summary>Gets the byte array representing the DNS question.</summary>
    public ReadOnlyMemory<byte> QuestionData
    {
        get
        {
            // Encode the DNS name
            var nameBytes = NameHelper.EncodeDnsName(Name);

            // Create the question data array with space for the name, type, and class
            var questionData = new byte[nameBytes.Length + 4];

            // Copy the encoded name into the question data array
            nameBytes.CopyTo(questionData, 0);

            // Encode Type
            BinaryPrimitives.WriteUInt16BigEndian(questionData.AsSpan(nameBytes.Length, 2), (ushort)Type);

            // Encode Class
            BinaryPrimitives.WriteUInt16BigEndian(questionData.AsSpan(nameBytes.Length + 2, 2), (ushort)Class);

            return new ReadOnlyMemory<byte>(questionData);
        }
    }
}
