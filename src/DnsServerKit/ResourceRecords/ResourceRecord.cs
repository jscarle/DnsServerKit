using System.Text;

namespace DnsServerKit.ResourceRecords;

public abstract class ResourceRecord
{
    /// <summary>Encodes a DNS name into the wire format used in DNS messages.</summary>
    /// <param name="name">The DNS name to encode.</param>
    /// <returns>Returns the encoded DNS name as a byte array.</returns>
    protected static byte[] DnsEncodeName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return [0];
        }

        var labels = name.Split('.');
        var result = new List<byte>();

        foreach (var label in labels)
        {
            if (label.Length > 63)
            {
                throw new ArgumentException("Each label in the DNS name must be 63 characters or less.", nameof(name));
            }

            var length = (byte)label.Length;
            result.Add(length);
            var bytes = Encoding.ASCII.GetBytes(label);
            result.AddRange(bytes);
        }

        // Add the terminating zero byte
        result.Add(0);

        return result.ToArray();
    }

    public abstract ReadOnlyMemory<byte> ToBytes();
}
