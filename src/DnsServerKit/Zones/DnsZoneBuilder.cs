using System.Buffers;
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

    public void AddAaaaRecord(uint ttl, string name, params IReadOnlyCollection<string> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        var records = new AaaaRecord[addresses.Count];
        var recordIndex = 0;
        foreach (var address in addresses)
            records[recordIndex++] = new AaaaRecord { Address = address };

        var recordSet = new AaaaRecordSet { Name = name, Ttl = ttl, Records = records };
        AddRecordSet(recordSet);
    }

    public void AddCnameRecord(uint ttl, string name, string target)
    {
        var recordSet = new CnameRecordSet
        {
            Name = name,
            Ttl = ttl,
            Record = new CnameRecord { Target = target },
        };
        AddRecordSet(recordSet);
    }

    public void AddMxRecord(uint ttl, string name, params IReadOnlyCollection<MxRecord> records)
    {
        ArgumentNullException.ThrowIfNull(records);

        var copiedRecords = new MxRecord[records.Count];
        var recordIndex = 0;
        foreach (var record in records)
            copiedRecords[recordIndex++] = record;

        var recordSet = new MxRecordSet { Name = name, Ttl = ttl, Records = copiedRecords };
        AddRecordSet(recordSet);
    }

    public void AddTxtRecord(uint ttl, string name, params IReadOnlyCollection<string> texts)
    {
        ArgumentNullException.ThrowIfNull(texts);

        var records = new TxtRecord[texts.Count];
        var recordIndex = 0;
        foreach (var text in texts)
            records[recordIndex++] = new TxtRecord { Text = text };

        var recordSet = new TxtRecordSet { Name = name, Ttl = ttl, Records = records };
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

            case AaaaRecordSet addressRecordSet:
                {
                    recordType = (ushort)RecordType.Aaaa;
                    ownerName = CreateOwnerName(addressRecordSet.Name);
                    if (addressRecordSet.Records is null)
                        throw new ArgumentException("An AAAA record set requires records.", nameof(recordSet));
                    if (addressRecordSet.Records.Count == 0)
                        throw new ArgumentException("An AAAA record set requires at least one record.", nameof(recordSet));
                    if (addressRecordSet.Records.Count > ushort.MaxValue)
                        throw new ArgumentException("A DNS record set cannot contain more than 65,535 records.", nameof(recordSet));

                    var records = new AaaaRecord[addressRecordSet.Records.Count];
                    var uniqueAddresses = new HashSet<string>(StringComparer.Ordinal);
                    var recordIndex = 0;
                    foreach (var record in addressRecordSet.Records)
                    {
                        if (record is null)
                            throw new ArgumentException("An AAAA record set cannot contain null records.", nameof(recordSet));
                        if (string.IsNullOrWhiteSpace(record.Address)
                            || record.Address.Contains('%')
                            || !IPAddress.TryParse(record.Address, out var parsedAddress)
                            || parsedAddress.AddressFamily != AddressFamily.InterNetworkV6)
                            throw new ArgumentException("Every AAAA record must contain a valid IPv6 address.", nameof(recordSet));

                        var addressBytes = parsedAddress.GetAddressBytes();
                        var normalizedAddress = string.Create(39, addressBytes, static (destination, bytes) =>
                        {
                            const string hexDigits = "0123456789abcdef";
                            var destinationOffset = 0;
                            for (var byteIndex = 0; byteIndex < bytes.Length; byteIndex++)
                            {
                                if (byteIndex > 0 && (byteIndex & 1) == 0)
                                    destination[destinationOffset++] = ':';

                                var value = bytes[byteIndex];
                                destination[destinationOffset++] = hexDigits[value >> 4];
                                destination[destinationOffset++] = hexDigits[value & 0x0F];
                            }
                        });
                        if (!uniqueAddresses.Add(normalizedAddress))
                            throw new ArgumentException("An AAAA record set cannot contain duplicate IPv6 addresses.", nameof(recordSet));

                        records[recordIndex++] = new AaaaRecord { Address = normalizedAddress };
                    }

                    var copiedRecordSet = new AaaaRecordSet { Name = addressRecordSet.Name, Ttl = addressRecordSet.Ttl, Records = Array.AsReadOnly(records) };
                    ownedRecordSet = copiedRecordSet;
                    break;
                }

            case CnameRecordSet canonicalNameRecordSet:
                {
                    recordType = (ushort)RecordType.CName;
                    ownerName = CreateOwnerName(canonicalNameRecordSet.Name);
                    if (canonicalNameRecordSet.Record is null)
                        throw new ArgumentException("A CNAME record set requires one record.", nameof(recordSet));
                    if (string.IsNullOrWhiteSpace(canonicalNameRecordSet.Record.Target))
                        throw new ArgumentException("A CNAME record must contain a complete DNS target name.", nameof(recordSet));

                    try
                    {
                        _ = new DnsName(canonicalNameRecordSet.Record.Target);
                    }
                    catch (FormatException exception)
                    {
                        throw new ArgumentException("A CNAME record must contain a valid DNS target name.", nameof(recordSet), exception);
                    }

                    var copiedRecord = new CnameRecord { Target = canonicalNameRecordSet.Record.Target };
                    var copiedRecordSet = new CnameRecordSet { Name = canonicalNameRecordSet.Name, Ttl = canonicalNameRecordSet.Ttl, Record = copiedRecord };
                    ownedRecordSet = copiedRecordSet;
                    break;
                }

            case MxRecordSet mailExchangeRecordSet:
                {
                    recordType = (ushort)RecordType.Mx;
                    ownerName = CreateOwnerName(mailExchangeRecordSet.Name);
                    if (mailExchangeRecordSet.Records is null)
                        throw new ArgumentException("An MX record set requires records.", nameof(recordSet));
                    if (mailExchangeRecordSet.Records.Count == 0)
                        throw new ArgumentException("An MX record set requires at least one record.", nameof(recordSet));
                    if (mailExchangeRecordSet.Records.Count > ushort.MaxValue)
                        throw new ArgumentException("A DNS record set cannot contain more than 65,535 records.", nameof(recordSet));

                    var records = new MxRecord[mailExchangeRecordSet.Records.Count];
                    var uniqueExchanges = new HashSet<(ushort Preference, DnsName Exchange)>();
                    var recordIndex = 0;
                    foreach (var record in mailExchangeRecordSet.Records)
                    {
                        if (record is null)
                            throw new ArgumentException("An MX record set cannot contain null records.", nameof(recordSet));
                        if (string.IsNullOrWhiteSpace(record.Exchange))
                            throw new ArgumentException("Every MX record must contain a complete exchange name.", nameof(recordSet));

                        DnsName exchange;
                        try
                        {
                            exchange = new DnsName(record.Exchange);
                        }
                        catch (FormatException exception)
                        {
                            throw new ArgumentException("Every MX record must contain a valid exchange name.", nameof(recordSet), exception);
                        }

                        if (!uniqueExchanges.Add((record.Preference, exchange)))
                            throw new ArgumentException("An MX record set cannot contain duplicate preference and exchange values.", nameof(recordSet));

                        records[recordIndex++] = new MxRecord { Preference = record.Preference, Exchange = record.Exchange };
                    }

                    var copiedRecordSet = new MxRecordSet { Name = mailExchangeRecordSet.Name, Ttl = mailExchangeRecordSet.Ttl, Records = Array.AsReadOnly(records) };
                    ownedRecordSet = copiedRecordSet;
                    break;
                }

            case TxtRecordSet textRecordSet:
                {
                    recordType = (ushort)RecordType.Txt;
                    ownerName = CreateOwnerName(textRecordSet.Name);
                    if (textRecordSet.Records is null)
                        throw new ArgumentException("A TXT record set requires records.", nameof(recordSet));
                    if (textRecordSet.Records.Count == 0)
                        throw new ArgumentException("A TXT record set requires at least one record.", nameof(recordSet));
                    if (textRecordSet.Records.Count > ushort.MaxValue)
                        throw new ArgumentException("A DNS record set cannot contain more than 65,535 records.", nameof(recordSet));

                    var records = new TxtRecord[textRecordSet.Records.Count];
                    var uniqueTexts = new HashSet<string>(StringComparer.Ordinal);
                    var recordIndex = 0;
                    foreach (var record in textRecordSet.Records)
                    {
                        if (record is null)
                            throw new ArgumentException("A TXT record set cannot contain null records.", nameof(recordSet));
                        if (record.Text is null)
                            throw new ArgumentException("A TXT record cannot contain a null text value.", nameof(recordSet));

                        var text = record.Text.AsSpan();
                        var resourceDataLength = 1;
                        var characterStringLength = 0;
                        while (!text.IsEmpty)
                        {
                            var status = Rune.DecodeFromUtf16(text, out var rune, out var charactersConsumed);
                            if (status != OperationStatus.Done)
                                throw new ArgumentException("A TXT record must contain valid Unicode text.", nameof(recordSet));

                            var runeLength = rune.Utf8SequenceLength;
                            if (characterStringLength + runeLength > byte.MaxValue)
                            {
                                resourceDataLength++;
                                characterStringLength = 0;
                            }

                            resourceDataLength += runeLength;
                            characterStringLength += runeLength;
                            text = text[charactersConsumed..];
                        }

                        if (resourceDataLength > ushort.MaxValue)
                            throw new ArgumentException("A TXT record cannot exceed 65,535 encoded octets.", nameof(recordSet));
                        if (!uniqueTexts.Add(record.Text))
                            throw new ArgumentException("A TXT record set cannot contain duplicate text values.", nameof(recordSet));

                        records[recordIndex++] = new TxtRecord { Text = record.Text };
                    }

                    var copiedRecordSet = new TxtRecordSet { Name = textRecordSet.Name, Ttl = textRecordSet.Ttl, Records = Array.AsReadOnly(records) };
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
        if (_recordSets.ContainsKey(recordSetKey))
            throw new InvalidOperationException($"The '{ownerName}' owner already contains a type {recordType} record set.");

        if (recordType == (ushort)RecordType.CName)
        {
            foreach (var existingKey in _recordSets.Keys)
            {
                if (existingKey.Owner.Equals(ownerName))
                    throw new InvalidOperationException($"The '{ownerName}' CNAME owner cannot contain another record set.");
            }
        }
        else if (_recordSets.ContainsKey((Owner: ownerName, Type: (ushort)RecordType.CName)))
        {
            throw new InvalidOperationException($"The '{ownerName}' owner cannot contain another record set alongside CNAME.");
        }

        _recordSets.Add(recordSetKey, ownedRecordSet);
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
