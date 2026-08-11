using System.Buffers;
using System.Collections.Frozen;
using System.Text;
using DnsServerKit.Internal.Lookup;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Parameters;
using DnsServerKit.Records;

namespace DnsServerKit.Zones;

/// <summary>Publishes DNS zone-set snapshots and their lookup indexes to concurrent readers.</summary>
public sealed class DnsZoneStore
{
    public DnsZoneSet Current =>
        Volatile.Read(ref _state)
            .ZoneSet;

    private const ushort DelegationSignerType = 43;
    private StoreState _state = CreateState(DnsZoneSet.Empty);

    public void Load(DnsZoneSet zoneSet)
    {
        ArgumentNullException.ThrowIfNull(zoneSet);

        var state = CreateState(zoneSet);
        ValidateCnameChains(state);
        Volatile.Write(ref _state, state);
    }

    internal bool TryGet(DnsName name, ushort type, ushort @class, out RecordSet? recordSet)
    {
        ArgumentNullException.ThrowIfNull(name);

        var state = Volatile.Read(ref _state);
        if (!TryFindZone(state, name.WireBytes, @class, out var zone) || !TryFindOwner(zone, name.WireBytes, name.WireHashCode, out var owner))
        {
            recordSet = null;
            return false;
        }

        if (owner.RecordSets.TryGetValue(type, out var indexedRecordSet))
        {
            recordSet = indexedRecordSet.RecordSet;
            return true;
        }

        if (owner.RecordSets.TryGetValue((ushort)RecordType.CName, out indexedRecordSet))
        {
            recordSet = indexedRecordSet.RecordSet;
            return true;
        }

        recordSet = null;
        return false;
    }

    internal bool TryResolve(DnsQuestionContext question, out RecordSet? recordSet)
    {
        ArgumentNullException.ThrowIfNull(question);

        var state = Volatile.Read(ref _state);
        if (!TryFindZone(state, question.EncodedName, question.Class, out var zone)
            || !TryFindOwner(zone, question.EncodedName, question.NameHashCode, out var owner))
        {
            recordSet = null;
            return false;
        }

        if (owner.DelegationName is not null)
        {
            recordSet = null;
            return false;
        }

        if (owner.RecordSets.TryGetValue(question.Type, out var indexedRecordSet)
            || owner.RecordSets.TryGetValue((ushort)RecordType.CName, out indexedRecordSet))
        {
            recordSet = indexedRecordSet.RecordSet;
            return true;
        }

        recordSet = null;
        return false;
    }

    internal void Resolve(DnsQuestionContext question, DnsResolutionContext resolution)
    {
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(resolution);

        if (question.Class is (ushort)DnsClass.Reserved or (ushort)DnsClass.None or (ushort)DnsClass.Any)
        {
            resolution.Clear();
            resolution.SetError(ResponseCode.Refused);
            return;
        }

        if (question.Type is (ushort)RecordType.IxFr or (ushort)RecordType.AxFr)
        {
            resolution.Clear();
            resolution.SetError(ResponseCode.Refused);
            return;
        }

        if (question.Type is 0 or (ushort)RecordType.MailB or (ushort)RecordType.MailA)
        {
            resolution.Clear();
            resolution.SetError(ResponseCode.NotImplemented);
            return;
        }

        var state = Volatile.Read(ref _state);
        if (!TryFindZone(state, question.EncodedName, question.Class, out var zone))
        {
            resolution.Clear();
            resolution.SetError(ResponseCode.Refused);
            return;
        }

        var ownerExists = TryFindOwner(zone, question.EncodedName, question.NameHashCode, out var owner);
        if (question.Type != DelegationSignerType && ownerExists && owner.DelegationName is null)
        {
            var minimalRecordSet = owner.MinimalRecordSet;
            if (question.Type == (ushort)RecordType.All && minimalRecordSet is not null)
            {
                resolution.SetDirectPositive(minimalRecordSet);
                return;
            }

            if (owner.RecordSets.Count == 1 && minimalRecordSet is not null && minimalRecordSet.Type == question.Type)
            {
                resolution.SetDirectPositive(minimalRecordSet);
                return;
            }

            if (owner.RecordSets.TryGetValue(question.Type, out var directAnswerSet))
            {
                resolution.SetDirectPositive(directAnswerSet);
                return;
            }
        }

        resolution.Clear();

        if (question.Type == DelegationSignerType && zone.Apex.WireEquals(question.EncodedName))
        {
            if (TryFindParentZoneAtDelegation(state, question.EncodedName, question.Class, zone, out var parentZone))
                zone = parentZone;

            SetNoData(resolution, zone);
            return;
        }

        Delegation delegation;
        if (ownerExists && owner.DelegationName is not null)
        {
            delegation = zone.Delegations[owner.DelegationName];
            if (question.Type == DelegationSignerType && delegation.Name.WireEquals(question.EncodedName))
            {
                SetNoData(resolution, zone);
                return;
            }

            resolution.SetReferral(delegation.NameServers, delegation.RequiredGlue, delegation.OptionalGlue);
            return;
        }

        if (!ownerExists && TryFindDelegation(zone, question.EncodedName, out delegation))
        {
            if (question.Type == DelegationSignerType && delegation.Name.WireEquals(question.EncodedName))
            {
                SetNoData(resolution, zone);
                return;
            }

            resolution.SetReferral(delegation.NameServers, delegation.RequiredGlue, delegation.OptionalGlue);
            return;
        }

        if (!ownerExists)
        {
            SetNxDomain(resolution, zone);
            return;
        }

        if (question.Type == (ushort)RecordType.All)
        {
            if (owner.MinimalRecordSet is not null)
            {
                resolution.SetDirectPositive(owner.MinimalRecordSet);
            }
            else
            {
                SetNoData(resolution, zone);
            }

            return;
        }

        if (owner.RecordSets.TryGetValue(question.Type, out var answerSet))
        {
            resolution.SetDirectPositive(answerSet);
            return;
        }

        if (!owner.RecordSets.TryGetValue((ushort)RecordType.CName, out var canonicalNameSet) || question.Type == (ushort)RecordType.CName)
        {
            SetNoData(resolution, zone);
            return;
        }

        for (var linkIndex = 0; linkIndex < DnsResolutionContext.MaximumCnameChainLength; linkIndex++)
        {
            if (!resolution.TryAddAnswer(canonicalNameSet))
            {
                resolution.SetError(ResponseCode.ServerFailure);
                return;
            }

            var canonicalTarget = canonicalNameSet.CanonicalTarget;
            if (canonicalTarget is null)
            {
                resolution.SetError(ResponseCode.ServerFailure);
                return;
            }

            if (!TryFindZone(state, canonicalTarget.WireBytes, question.Class, out zone))
            {
                resolution.SetPositive(true);
                return;
            }

            if (question.Type == DelegationSignerType && zone.Apex.Equals(canonicalTarget))
            {
                if (TryFindParentZoneAtDelegation(state, canonicalTarget.WireBytes, question.Class, zone, out var parentZone))
                    zone = parentZone;

                SetNoData(resolution, zone);
                return;
            }

            var targetOwnerExists = TryFindOwner(zone, canonicalTarget.WireBytes, canonicalTarget.WireHashCode, out owner);
            if (targetOwnerExists && owner.DelegationName is not null)
            {
                delegation = zone.Delegations[owner.DelegationName];
                if (question.Type == DelegationSignerType && delegation.Name.Equals(canonicalTarget))
                {
                    SetNoData(resolution, zone);
                    return;
                }

                resolution.SetReferral(delegation.NameServers, delegation.RequiredGlue, delegation.OptionalGlue);
                return;
            }

            if (!targetOwnerExists && TryFindDelegation(zone, canonicalTarget.WireBytes, out delegation))
            {
                if (question.Type == DelegationSignerType && delegation.Name.Equals(canonicalTarget))
                {
                    SetNoData(resolution, zone);
                    return;
                }

                resolution.SetReferral(delegation.NameServers, delegation.RequiredGlue, delegation.OptionalGlue);
                return;
            }

            if (!targetOwnerExists)
            {
                SetNxDomain(resolution, zone);
                return;
            }

            if (owner.RecordSets.TryGetValue(question.Type, out answerSet))
            {
                if (!resolution.TryAddAnswer(answerSet))
                {
                    resolution.SetError(ResponseCode.ServerFailure);
                    return;
                }

                resolution.SetPositive(true);
                return;
            }

            if (!owner.RecordSets.TryGetValue((ushort)RecordType.CName, out canonicalNameSet))
            {
                SetNoData(resolution, zone);
                return;
            }
        }

        resolution.SetError(ResponseCode.ServerFailure);
    }

    private static StoreState CreateState(DnsZoneSet zoneSet)
    {
        var zoneIndexes = new Dictionary<DnsZoneKey, CompiledZone>(DnsZoneKeyComparer.Instance);

        foreach (var zone in zoneSet.Zones)
        {
            var apex = new DnsName(zone.Name);
            var mutableOwners = new Dictionary<DnsName, Dictionary<ushort, DnsIndexedRecordSet>>(DnsNameComparer.Instance);

            foreach (var recordSet in zone.RecordSets)
            {
                var type = GetRecordType(recordSet);
                var ownerName = GetOwnerName(apex, recordSet.Name);
                if (!mutableOwners.TryGetValue(ownerName, out var recordSets))
                {
                    recordSets = new Dictionary<ushort, DnsIndexedRecordSet>();
                    mutableOwners.Add(ownerName, recordSets);
                }

                DnsName[] resourceNames = [];
                byte[] responsibleMailboxWireName = [];
                switch (recordSet)
                {
                    case CnameRecordSet canonicalNameRecordSet:
                        var canonicalTarget = new DnsName(canonicalNameRecordSet.Record.Target);
                        resourceNames = [canonicalTarget];
                        break;
                    case MxRecordSet mailExchangeRecordSet:
                        if (mailExchangeRecordSet.Records is not IReadOnlyList<MxRecord> mailExchangeRecords)
                            throw new InvalidOperationException("The MX record set has not been prepared for snapshot compilation.");
                        resourceNames = new DnsName[mailExchangeRecords.Count];
                        for (var recordIndex = 0; recordIndex < mailExchangeRecords.Count; recordIndex++)
                            resourceNames[recordIndex] = new DnsName(mailExchangeRecords[recordIndex].Exchange);
                        break;
                    case PtrRecordSet pointerRecordSet:
                        if (pointerRecordSet.Records is not IReadOnlyList<PtrRecord> pointerRecords)
                            throw new InvalidOperationException("The PTR record set has not been prepared for snapshot compilation.");
                        resourceNames = new DnsName[pointerRecords.Count];
                        for (var recordIndex = 0; recordIndex < pointerRecords.Count; recordIndex++)
                            resourceNames[recordIndex] = new DnsName(pointerRecords[recordIndex].Target);
                        break;
                    case NsRecordSet nameServerRecordSet:
                        if (nameServerRecordSet.Records is not IReadOnlyList<NsRecord> nameServerRecords)
                            throw new InvalidOperationException("The NS record set has not been prepared for snapshot compilation.");
                        resourceNames = new DnsName[nameServerRecords.Count];
                        for (var recordIndex = 0; recordIndex < nameServerRecords.Count; recordIndex++)
                            resourceNames[recordIndex] = new DnsName(nameServerRecords[recordIndex].NameServer);
                        break;
                    case SoaRecordSet startOfAuthorityRecordSet:
                        var startOfAuthorityRecord = startOfAuthorityRecordSet.Record;
                        resourceNames = [new DnsName(startOfAuthorityRecord.PrimaryNameServer)];
                        var separatorIndex = startOfAuthorityRecord.ResponsibleMailbox.LastIndexOf('@');
                        var responsibleMailboxHost = new DnsName(startOfAuthorityRecord.ResponsibleMailbox[(separatorIndex + 1)..]);
                        responsibleMailboxWireName = new byte[separatorIndex + 1 + responsibleMailboxHost.WireBytes.Length];
                        responsibleMailboxWireName[0] = (byte)separatorIndex;
                        for (var characterIndex = 0; characterIndex < separatorIndex; characterIndex++)
                        {
                            var character = startOfAuthorityRecord.ResponsibleMailbox[characterIndex];
                            responsibleMailboxWireName[characterIndex + 1] = DnsName.ToLowerAscii((byte)character);
                        }
                        responsibleMailboxHost.WireBytes.CopyTo(responsibleMailboxWireName.AsSpan(separatorIndex + 1));
                        break;
                }

                var uncompressedWireLength = GetRecordSetWireSize(ownerName, recordSet, resourceNames, responsibleMailboxWireName);
                var compressedWireLength = uncompressedWireLength - recordSet.Count * (ownerName.WireBytes.Length - 2);
                var compiledNames = resourceNames.Length == 0 ? null : new DnsCompiledRecordNames(resourceNames, responsibleMailboxWireName);
                recordSets.Add(type,
                    new DnsIndexedRecordSet(ownerName, type, (ushort)zone.Class, recordSet, compressedWireLength, uncompressedWireLength, compiledNames));
            }

            AddEmptyNonTerminals(mutableOwners, apex);

            var delegationNames = new Dictionary<DnsName, DnsName>(DnsNameComparer.Instance);
            foreach (var entry in mutableOwners)
            {
                if (!entry.Key.Equals(apex) && entry.Value.ContainsKey((ushort)RecordType.Ns))
                    delegationNames.Add(entry.Key, entry.Key);
            }

            var delegationNameLookup = delegationNames.GetAlternateLookup<DnsNameLookup>();

            var owners = new Dictionary<DnsName, OwnerNode>(mutableOwners.Count, DnsNameComparer.Instance);
            foreach (var entry in mutableOwners)
            {
                var frozenRecordSets = entry.Value.ToFrozenDictionary();
                DnsName? delegationName = null;
                var ownerWireName = entry.Key.WireBytes;
                var labelOffset = 0;
                while (!apex.WireEquals(ownerWireName[labelOffset..]))
                {
                    var candidate = ownerWireName[labelOffset..];
                    var candidateHashCode = DnsName.ComputeWireHash(candidate);
                    if (delegationNameLookup.TryGetValue(new DnsNameLookup(candidate, candidateHashCode), out delegationName))
                        break;

                    labelOffset += ownerWireName[labelOffset] + 1;
                }

                DnsIndexedRecordSet? minimalRecordSet = null;
                var minimalSize = int.MaxValue;
                foreach (var indexedRecordSet in entry.Value.Values)
                {
                    var responseSize = indexedRecordSet.CompressedWireLength;
                    if (responseSize < minimalSize || responseSize == minimalSize && indexedRecordSet.Type < minimalRecordSet!.Type)
                    {
                        minimalRecordSet = indexedRecordSet;
                        minimalSize = responseSize;
                    }
                }

                owners.Add(entry.Key, new OwnerNode(frozenRecordSets, delegationName, minimalRecordSet));
            }

            var frozenOwners = owners.ToFrozenDictionary(DnsNameComparer.Instance);
            if (!frozenOwners.TryGetValue(apex, out var apexOwner)
                || !apexOwner.RecordSets.TryGetValue((ushort)RecordType.Soa, out var startOfAuthority))
            {
                throw new InvalidOperationException($"The '{apex}' DNS zone requires an apex SOA record set.");
            }

            var delegations = BuildDelegations(apex, frozenOwners);
            var zoneKey = new DnsZoneKey(apex, (ushort)zone.Class);
            zoneIndexes.Add(zoneKey, new CompiledZone(apex, frozenOwners, delegations, startOfAuthority));
        }

        var frozenZoneIndexes = zoneIndexes.ToFrozenDictionary(DnsZoneKeyComparer.Instance);
        return new StoreState(zoneSet, frozenZoneIndexes);
    }

    private static FrozenDictionary<DnsName, Delegation> BuildDelegations(DnsName apex, FrozenDictionary<DnsName, OwnerNode> owners)
    {
        var delegations = new Dictionary<DnsName, Delegation>(DnsNameComparer.Instance);

        foreach (var entry in owners)
        {
            if (entry.Key.Equals(apex) || !entry.Value.RecordSets.TryGetValue((ushort)RecordType.Ns, out var nameServers))
                continue;

            var requiredGlue = new List<DnsIndexedRecordSet>();
            var optionalGlue = new List<DnsIndexedRecordSet>();
            var records = ((NsRecordSet)nameServers.RecordSet).Records;
            foreach (var record in records)
            {
                var target = new DnsName(record.NameServer);
                if (!owners.TryGetValue(target, out var targetOwner))
                    continue;

                var inDomain = IsSubdomain(target.WireBytes, entry.Key.WireBytes);
                if (targetOwner.RecordSets.TryGetValue((ushort)RecordType.A, out var addressSet))
                    (inDomain ? requiredGlue : optionalGlue).Add(addressSet);
                if (targetOwner.RecordSets.TryGetValue((ushort)RecordType.Aaaa, out addressSet))
                    (inDomain ? requiredGlue : optionalGlue).Add(addressSet);
            }

            delegations.Add(entry.Key, new Delegation(entry.Key, nameServers, requiredGlue.ToArray(), optionalGlue.ToArray()));
        }

        return delegations.ToFrozenDictionary(DnsNameComparer.Instance);
    }

    private static void AddEmptyNonTerminals(Dictionary<DnsName, Dictionary<ushort, DnsIndexedRecordSet>> owners, DnsName apex)
    {
        var existingOwners = owners.Keys.ToArray();
        var alternateLookup = owners.GetAlternateLookup<DnsNameLookup>();

        foreach (var owner in existingOwners)
        {
            var wireName = owner.WireBytes;
            var labelOffset = 0;
            while (!apex.WireEquals(wireName[labelOffset..]))
            {
                labelOffset += wireName[labelOffset] + 1;
                var parent = wireName[labelOffset..];
                var parentHashCode = DnsName.ComputeWireHash(parent);
                var parentLookup = new DnsNameLookup(parent, parentHashCode);
                if (!alternateLookup.ContainsKey(parentLookup))
                    owners.Add(DnsName.FromWire(parent), new Dictionary<ushort, DnsIndexedRecordSet>());
            }
        }
    }

    private static void ValidateCnameChains(StoreState state)
    {
        var visitedOwners = new DnsName[DnsResolutionContext.MaximumCnameChainLength + 1];

        foreach (var zone in state.ZoneIndexes.Values)
        foreach (var ownerEntry in zone.Owners)
        {
            if (!ownerEntry.Value.RecordSets.TryGetValue((ushort)RecordType.CName, out var canonicalNameSet))
                continue;

            visitedOwners[0] = canonicalNameSet.Owner;
            for (var linkIndex = 0; linkIndex < DnsResolutionContext.MaximumCnameChainLength; linkIndex++)
            {
                var target = canonicalNameSet.CanonicalTarget!;
                for (var visitedIndex = 0; visitedIndex <= linkIndex; visitedIndex++)
                {
                    if (visitedOwners[visitedIndex].Equals(target))
                        throw new InvalidOperationException($"The CNAME chain beginning at '{visitedOwners[0]}' contains a cycle.");
                }

                if (!TryFindZone(state, target.WireBytes, canonicalNameSet.Class, out var targetZone)
                    || TryFindDelegation(targetZone, target.WireBytes, out _)
                    || !TryFindOwner(targetZone, target.WireBytes, target.WireHashCode, out var targetOwner)
                    || !targetOwner.RecordSets.TryGetValue((ushort)RecordType.CName, out canonicalNameSet))
                {
                    break;
                }

                if (linkIndex + 1 == DnsResolutionContext.MaximumCnameChainLength)
                    throw new InvalidOperationException($"The CNAME chain beginning at '{visitedOwners[0]}' exceeds {DnsResolutionContext.MaximumCnameChainLength} links.");

                visitedOwners[linkIndex + 1] = target;
            }
        }
    }

    private static bool TryFindZone(StoreState state, ReadOnlySpan<byte> encodedName, ushort @class, out CompiledZone zone)
    {
        var alternateLookup = state.ZoneIndexes.GetAlternateLookup<DnsZoneLookup>();
        var labelOffset = 0;

        while (true)
        {
            var encodedApex = encodedName[labelOffset..];
            var apexHashCode = DnsName.ComputeWireHash(encodedApex);
            var zoneLookup = new DnsZoneLookup(encodedApex, @class, apexHashCode);
            if (alternateLookup.TryGetValue(zoneLookup, out zone!))
                return true;

            var labelLength = encodedName[labelOffset];
            if (labelLength == 0)
            {
                zone = null!;
                return false;
            }

            labelOffset += labelLength + 1;
        }
    }

    private static bool TryFindParentZoneAtDelegation(
        StoreState state,
        ReadOnlySpan<byte> encodedName,
        ushort @class,
        CompiledZone childZone,
        out CompiledZone parentZone)
    {
        var alternateLookup = state.ZoneIndexes.GetAlternateLookup<DnsZoneLookup>();
        var labelOffset = 0;

        while (true)
        {
            labelOffset += encodedName[labelOffset] + 1;
            if ((uint)labelOffset >= (uint)encodedName.Length)
                break;

            var encodedApex = encodedName[labelOffset..];
            var apexHashCode = DnsName.ComputeWireHash(encodedApex);
            var zoneLookup = new DnsZoneLookup(encodedApex, @class, apexHashCode);
            if (alternateLookup.TryGetValue(zoneLookup, out parentZone!)
                && !ReferenceEquals(parentZone, childZone)
                && ContainsExactDelegation(parentZone, encodedName))
            {
                return true;
            }

            if (encodedName[labelOffset] == 0)
                break;
        }

        parentZone = null!;
        return false;
    }

    private static bool TryFindOwner(CompiledZone zone, ReadOnlySpan<byte> encodedName, int nameHashCode, out OwnerNode owner)
    {
        var ownerLookup = new DnsNameLookup(encodedName, nameHashCode);
        var alternateLookup = zone.Owners.GetAlternateLookup<DnsNameLookup>();
        return alternateLookup.TryGetValue(ownerLookup, out owner);
    }

    private static bool TryFindDelegation(CompiledZone zone, ReadOnlySpan<byte> encodedName, out Delegation delegation)
    {
        var alternateLookup = zone.Delegations.GetAlternateLookup<DnsNameLookup>();
        var labelOffset = 0;

        while (!zone.Apex.WireEquals(encodedName[labelOffset..]))
        {
            var candidate = encodedName[labelOffset..];
            var hashCode = DnsName.ComputeWireHash(candidate);
            if (alternateLookup.TryGetValue(new DnsNameLookup(candidate, hashCode), out delegation))
                return true;

            labelOffset += encodedName[labelOffset] + 1;
        }

        delegation = default;
        return false;
    }

    private static bool ContainsExactDelegation(CompiledZone zone, ReadOnlySpan<byte> encodedName)
    {
        var hashCode = DnsName.ComputeWireHash(encodedName);
        var alternateLookup = zone.Delegations.GetAlternateLookup<DnsNameLookup>();
        return alternateLookup.ContainsKey(new DnsNameLookup(encodedName, hashCode));
    }

    private static void SetNoData(DnsResolutionContext resolution, CompiledZone zone)
    {
        var startOfAuthorityRecord = (SoaRecordSet)zone.StartOfAuthority.RecordSet;
        var negativeTtl = Math.Min(startOfAuthorityRecord.Ttl, startOfAuthorityRecord.Record.Minimum);
        resolution.SetNegative(ResponseCode.NoError, zone.StartOfAuthority, negativeTtl);
    }

    private static void SetNxDomain(DnsResolutionContext resolution, CompiledZone zone)
    {
        var startOfAuthorityRecord = (SoaRecordSet)zone.StartOfAuthority.RecordSet;
        var negativeTtl = Math.Min(startOfAuthorityRecord.Ttl, startOfAuthorityRecord.Record.Minimum);
        resolution.SetNegative(ResponseCode.NxDomain, zone.StartOfAuthority, negativeTtl);
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

    private static DnsName GetOwnerName(DnsName apex, string recordSetName)
    {
        if (recordSetName.Equals("@", StringComparison.Ordinal))
            return apex;

        var ownerNameValue = apex.Value.Equals(".", StringComparison.Ordinal) ? recordSetName : $"{recordSetName}.{apex.Value}";
        return new DnsName(ownerNameValue);
    }

    private static bool IsSubdomain(ReadOnlySpan<byte> candidate, ReadOnlySpan<byte> parent)
    {
        var labelOffset = 0;
        while (true)
        {
            if (candidate[labelOffset..].SequenceEqual(parent))
                return true;
            if (candidate[labelOffset] == 0)
                return false;

            labelOffset += candidate[labelOffset] + 1;
        }
    }

    private static int GetRecordSetWireSize(
        DnsName owner,
        RecordSet sourceRecordSet,
        DnsName[] resourceNames,
        byte[] responsibleMailboxWireName)
    {
        var ownerAndHeaderLength = owner.WireBytes.Length + 10;
        switch (sourceRecordSet)
        {
            case ARecordSet addressRecordSet:
                return addressRecordSet.Count * (ownerAndHeaderLength + 4);
            case AaaaRecordSet addressRecordSet:
                return addressRecordSet.Count * (ownerAndHeaderLength + 16);
            case CnameRecordSet:
                return ownerAndHeaderLength + resourceNames[0].WireBytes.Length;
            case MxRecordSet:
                {
                    var totalLength = 0;
                    for (var recordIndex = 0; recordIndex < resourceNames.Length; recordIndex++)
                        totalLength += ownerAndHeaderLength + 2 + resourceNames[recordIndex].WireBytes.Length;
                    return totalLength;
                }
            case PtrRecordSet:
            case NsRecordSet:
                {
                    var totalLength = 0;
                    for (var recordIndex = 0; recordIndex < resourceNames.Length; recordIndex++)
                        totalLength += ownerAndHeaderLength + resourceNames[recordIndex].WireBytes.Length;
                    return totalLength;
                }
            case SoaRecordSet:
                return ownerAndHeaderLength + resourceNames[0].WireBytes.Length + responsibleMailboxWireName.Length + 20;
            case TxtRecordSet textRecordSet:
                {
                    var totalLength = 0;
                    foreach (var record in textRecordSet.Records)
                    {
                        var resourceDataLength = 1;
                        var characterStringLength = 0;
                        var text = record.Text.AsSpan();
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

                        totalLength += ownerAndHeaderLength + resourceDataLength;
                    }

                    return totalLength;
                }
            default:
                throw new NotSupportedException($"The '{sourceRecordSet.GetType().Name}' DNS record set type is not supported.");
        }
    }

    private readonly struct OwnerNode(
        FrozenDictionary<ushort, DnsIndexedRecordSet> recordSets,
        DnsName? delegationName,
        DnsIndexedRecordSet? minimalRecordSet)
    {
        public FrozenDictionary<ushort, DnsIndexedRecordSet> RecordSets { get; } = recordSets;

        public DnsName? DelegationName { get; } = delegationName;

        public DnsIndexedRecordSet? MinimalRecordSet { get; } = minimalRecordSet;
    }

    private readonly struct Delegation(
        DnsName name,
        DnsIndexedRecordSet nameServers,
        DnsIndexedRecordSet[] requiredGlue,
        DnsIndexedRecordSet[] optionalGlue)
    {
        public DnsName Name { get; } = name;

        public DnsIndexedRecordSet NameServers { get; } = nameServers;

        public DnsIndexedRecordSet[] RequiredGlue { get; } = requiredGlue;

        public DnsIndexedRecordSet[] OptionalGlue { get; } = optionalGlue;
    }

    private sealed class CompiledZone(
        DnsName apex,
        FrozenDictionary<DnsName, OwnerNode> owners,
        FrozenDictionary<DnsName, Delegation> delegations,
        DnsIndexedRecordSet startOfAuthority)
    {
        public DnsName Apex { get; } = apex;

        public FrozenDictionary<DnsName, OwnerNode> Owners { get; } = owners;

        public FrozenDictionary<DnsName, Delegation> Delegations { get; } = delegations;

        public DnsIndexedRecordSet StartOfAuthority { get; } = startOfAuthority;
    }

    private sealed class StoreState(DnsZoneSet zoneSet, FrozenDictionary<DnsZoneKey, CompiledZone> zoneIndexes)
    {
        public DnsZoneSet ZoneSet { get; } = zoneSet;

        public FrozenDictionary<DnsZoneKey, CompiledZone> ZoneIndexes { get; } = zoneIndexes;
    }
}
