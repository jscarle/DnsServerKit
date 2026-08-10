using System.Buffers.Binary;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Text;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Parameters;
using DnsServerKit.Records;

namespace DnsServerKit.Zones;

/// <summary>Builds immutable authoritative DNS zones from passive resource record set models.</summary>
public sealed class DnsZoneBuilder
{
    internal DnsName CanonicalApex { get; }

    internal DnsClass Class { get; }

    private readonly OrderedDictionary<(DnsName Owner, ushort Type), RecordSet> _recordSets = [];

    public DnsZoneBuilder(string name, DnsClass dnsClass = DnsClass.Internet)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("A DNS zone name is required.", nameof(name));

        try
        {
            CanonicalApex = new DnsName(name);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The DNS zone name is invalid.", nameof(name), exception);
        }

        Class = dnsClass;
    }

    public void AddARecord(uint ttl, string name, params IReadOnlyCollection<string> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        var records = new ARecord[addresses.Count];
        var recordIndex = 0;
        foreach (var address in addresses)
            records[recordIndex++] = new ARecord { Address = address };

        var recordSet = new ARecordSet { Name = name, Ttl = ttl, Records = records };
        AddRecordSet(recordSet);
    }

    public void AddPtrRecord(uint ttl, string name, params IReadOnlyCollection<string> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);

        var records = new PtrRecord[targets.Count];
        var recordIndex = 0;
        foreach (var target in targets)
            records[recordIndex++] = new PtrRecord { Target = target };

        var recordSet = new PtrRecordSet { Name = name, Ttl = ttl, Records = records };
        AddRecordSet(recordSet);
    }

    public void AddNsRecord(uint ttl, params IReadOnlyCollection<string> nameServers)
    {
        ArgumentNullException.ThrowIfNull(nameServers);

        var records = new NsRecord[nameServers.Count];
        var recordIndex = 0;
        foreach (var nameServer in nameServers)
            records[recordIndex++] = new NsRecord { NameServer = nameServer };

        var recordSet = new NsRecordSet { Name = "@", Ttl = ttl, Records = records };
        AddRecordSet(recordSet);
    }

    public void AddSoaRecord(uint ttl, string primaryNameServer, string responsibleMailbox, uint serial, uint refresh, uint retry, uint expire, uint minimum)
    {
        var recordSet = new SoaRecordSet
        {
            Name = "@",
            Ttl = ttl,
            Record = new SoaRecord
            {
                PrimaryNameServer = primaryNameServer,
                ResponsibleMailbox = responsibleMailbox,
                Serial = serial,
                Refresh = refresh,
                Retry = retry,
                Expire = expire,
                Minimum = minimum,
            },
        };
        AddRecordSet(recordSet);
    }

    public void AddRecordSet(RecordSet recordSet)
    {
        ArgumentNullException.ThrowIfNull(recordSet);

        DnsName ownerName;
        RecordSet ownedRecordSet;
        ushort recordType;
        switch (recordSet)
        {
            case ARecordSet addressRecordSet:
            {
                recordType = (ushort)RecordType.A;
                ownerName = CreateOwnerName(addressRecordSet.Name);
                if (addressRecordSet.Records is null)
                    throw new ArgumentException("An A record set requires records.", nameof(recordSet));
                if (addressRecordSet.Records.Count == 0)
                    throw new ArgumentException("An A record set requires at least one record.", nameof(recordSet));
                if (addressRecordSet.Records.Count > ushort.MaxValue)
                    throw new ArgumentException("A DNS record set cannot contain more than 65,535 records.", nameof(recordSet));

                var records = new ARecord[addressRecordSet.Records.Count];
                var uniqueAddresses = new HashSet<uint>();
                var recordIndex = 0;
                foreach (var record in addressRecordSet.Records)
                {
                    if (record is null)
                        throw new ArgumentException("An A record set cannot contain null records.", nameof(recordSet));
                    if (string.IsNullOrWhiteSpace(record.Address)
                        || !IPAddress.TryParse(record.Address, out var parsedAddress)
                        || parsedAddress.AddressFamily != AddressFamily.InterNetwork)
                        throw new ArgumentException("Every A record must contain a valid IPv4 address.", nameof(recordSet));

                    var addressValue = BinaryPrimitives.ReadUInt32BigEndian(parsedAddress.GetAddressBytes());
                    if (!uniqueAddresses.Add(addressValue))
                        throw new ArgumentException("An A record set cannot contain duplicate IPv4 addresses.", nameof(recordSet));

                    records[recordIndex++] = new ARecord { Address = parsedAddress.ToString() };
                }

                var copiedRecordSet = new ARecordSet { Name = addressRecordSet.Name, Ttl = addressRecordSet.Ttl, Records = Array.AsReadOnly(records) };
                ownedRecordSet = copiedRecordSet;
                break;
            }

            case PtrRecordSet pointerRecordSet:
            {
                recordType = (ushort)RecordType.Ptr;
                ownerName = CreateOwnerName(pointerRecordSet.Name);
                if (pointerRecordSet.Records is null)
                    throw new ArgumentException("A PTR record set requires records.", nameof(recordSet));
                if (pointerRecordSet.Records.Count == 0)
                    throw new ArgumentException("A PTR record set requires at least one record.", nameof(recordSet));
                if (pointerRecordSet.Records.Count > ushort.MaxValue)
                    throw new ArgumentException("A DNS record set cannot contain more than 65,535 records.", nameof(recordSet));

                var records = new PtrRecord[pointerRecordSet.Records.Count];
                var uniqueTargets = new HashSet<DnsName>();
                var recordIndex = 0;
                foreach (var record in pointerRecordSet.Records)
                {
                    if (record is null)
                        throw new ArgumentException("A PTR record set cannot contain null records.", nameof(recordSet));
                    if (string.IsNullOrWhiteSpace(record.Target))
                        throw new ArgumentException("Every PTR record must contain a complete DNS target name.", nameof(recordSet));

                    DnsName target;
                    try
                    {
                        target = new DnsName(record.Target);
                    }
                    catch (FormatException exception)
                    {
                        throw new ArgumentException("Every PTR record must contain a valid DNS target name.", nameof(recordSet), exception);
                    }

                    if (!uniqueTargets.Add(target))
                        throw new ArgumentException("A PTR record set cannot contain duplicate target names.", nameof(recordSet));

                    records[recordIndex++] = new PtrRecord { Target = record.Target };
                }

                var copiedRecordSet = new PtrRecordSet { Name = pointerRecordSet.Name, Ttl = pointerRecordSet.Ttl, Records = Array.AsReadOnly(records) };
                ownedRecordSet = copiedRecordSet;
                break;
            }

            case NsRecordSet nameServerRecordSet:
            {
                recordType = (ushort)RecordType.Ns;
                ownerName = CreateOwnerName(nameServerRecordSet.Name);
                if (!nameServerRecordSet.Name.Equals("@", StringComparison.Ordinal))
                    throw new ArgumentException("Only apex NS record sets are currently supported.", nameof(recordSet));
                if (nameServerRecordSet.Records is null)
                    throw new ArgumentException("An NS record set requires records.", nameof(recordSet));
                if (nameServerRecordSet.Records.Count == 0)
                    throw new ArgumentException("An NS record set requires at least one record.", nameof(recordSet));
                if (nameServerRecordSet.Records.Count > ushort.MaxValue)
                    throw new ArgumentException("A DNS record set cannot contain more than 65,535 records.", nameof(recordSet));

                var records = new NsRecord[nameServerRecordSet.Records.Count];
                var uniqueNameServers = new HashSet<DnsName>();
                var recordIndex = 0;
                foreach (var record in nameServerRecordSet.Records)
                {
                    if (record is null)
                        throw new ArgumentException("An NS record set cannot contain null records.", nameof(recordSet));
                    if (string.IsNullOrWhiteSpace(record.NameServer))
                        throw new ArgumentException("Every NS record must contain a complete DNS name.", nameof(recordSet));

                    DnsName nameServer;
                    try
                    {
                        nameServer = new DnsName(record.NameServer);
                    }
                    catch (FormatException exception)
                    {
                        throw new ArgumentException("Every NS record must contain a valid DNS name.", nameof(recordSet), exception);
                    }

                    if (!uniqueNameServers.Add(nameServer))
                        throw new ArgumentException("An NS record set cannot contain duplicate name servers.", nameof(recordSet));

                    records[recordIndex++] = new NsRecord { NameServer = record.NameServer };
                }

                var copiedRecordSet = new NsRecordSet { Name = nameServerRecordSet.Name, Ttl = nameServerRecordSet.Ttl, Records = Array.AsReadOnly(records) };
                ownedRecordSet = copiedRecordSet;
                break;
            }

            case SoaRecordSet startOfAuthorityRecordSet:
            {
                recordType = (ushort)RecordType.Soa;
                ownerName = CreateOwnerName(startOfAuthorityRecordSet.Name);
                if (!startOfAuthorityRecordSet.Name.Equals("@", StringComparison.Ordinal))
                    throw new ArgumentException("An SOA record set must belong to the zone apex.", nameof(recordSet));
                if (startOfAuthorityRecordSet.Record is null)
                    throw new ArgumentException("An SOA record set requires one record.", nameof(recordSet));

                var record = startOfAuthorityRecordSet.Record;
                if (string.IsNullOrWhiteSpace(record.PrimaryNameServer))
                    throw new ArgumentException("An SOA record requires a primary name server.", nameof(recordSet));
                if (string.IsNullOrWhiteSpace(record.ResponsibleMailbox))
                    throw new ArgumentException("An SOA record requires a responsible mailbox email address.", nameof(recordSet));

                try
                {
                    _ = new DnsName(record.PrimaryNameServer);
                }
                catch (FormatException exception)
                {
                    throw new ArgumentException("The SOA primary name server is invalid.", nameof(recordSet), exception);
                }

                MailAddress responsibleMailbox;
                try
                {
                    responsibleMailbox = new MailAddress(record.ResponsibleMailbox);

                    var mailboxName = new StringBuilder(responsibleMailbox.User.Length + responsibleMailbox.Host.Length + 1);
                    foreach (var character in responsibleMailbox.User)
                    {
                        if (character is '.' or '\\')
                            mailboxName.Append('\\');

                        mailboxName.Append(character);
                    }

                    mailboxName.Append('.');
                    mailboxName.Append(responsibleMailbox.Host);
                    _ = new DnsName(mailboxName.ToString());
                }
                catch (FormatException exception)
                {
                    throw new ArgumentException("The SOA responsible mailbox email address is invalid.", nameof(recordSet), exception);
                }

                var copiedRecord = new SoaRecord
                {
                    PrimaryNameServer = record.PrimaryNameServer,
                    ResponsibleMailbox = $"{responsibleMailbox.User}@{responsibleMailbox.Host.ToLowerInvariant()}",
                    Serial = record.Serial,
                    Refresh = record.Refresh,
                    Retry = record.Retry,
                    Expire = record.Expire,
                    Minimum = record.Minimum,
                };
                var copiedRecordSet = new SoaRecordSet { Name = startOfAuthorityRecordSet.Name, Ttl = startOfAuthorityRecordSet.Ttl, Record = copiedRecord };
                ownedRecordSet = copiedRecordSet;
                break;
            }

            default:
                throw new NotSupportedException($"The '{recordSet.GetType().Name}' DNS record set type is not supported.");
        }

        var recordSetKey = (Owner: ownerName, Type: recordType);
        if (!_recordSets.TryAdd(recordSetKey, ownedRecordSet))
            throw new InvalidOperationException($"The '{ownerName}' owner already contains a type {recordType} record set.");
    }

    public DnsZone Build()
    {
        var startOfAuthorityRecordSetKey = (Owner: CanonicalApex, Type: (ushort)RecordType.Soa);
        if (!_recordSets.ContainsKey(startOfAuthorityRecordSetKey))
            throw new InvalidOperationException("A DNS zone must contain one SOA record set at its apex.");

        var nameServerRecordSetKey = (Owner: CanonicalApex, Type: (ushort)RecordType.Ns);
        if (!_recordSets.TryGetValue(nameServerRecordSetKey, out var nameServerRecordSet) || nameServerRecordSet.Count == 0)
            throw new InvalidOperationException("A DNS zone must contain a non-empty NS record set at its apex.");

        var recordSets = Array.AsReadOnly(_recordSets.Values.ToArray());
        return new DnsZone { Name = CanonicalApex.Value, Class = Class, RecordSets = recordSets };
    }

    private DnsName CreateOwnerName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("A relative DNS owner name is required.", nameof(name));
        if (name.Equals("@", StringComparison.Ordinal))
            return CanonicalApex;
        if (name.EndsWith(".", StringComparison.Ordinal))
            throw new ArgumentException("A DNS owner name must be relative to the zone apex.", nameof(name));

        var ownerName = CanonicalApex.Value.Equals(".", StringComparison.Ordinal) ? name : $"{name}.{CanonicalApex.Value}";

        try
        {
            return new DnsName(ownerName);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The relative DNS owner name is invalid.", nameof(name), exception);
        }
    }
}
