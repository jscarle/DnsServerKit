using DnsServerKit.Parameters;

namespace DnsServerKit.ResourceRecords;

public interface IResourceRecord
{
    string Name { get; }
    
    RecordType Type { get; }
    
    DnsClass Class { get; }
    
    int Ttl { get; }
    
    ReadOnlyMemory<byte> ResourceData { get; }
}
