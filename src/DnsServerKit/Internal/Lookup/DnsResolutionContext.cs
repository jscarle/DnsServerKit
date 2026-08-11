using DnsServerKit.Internal.Protocol;
using DnsServerKit.Records;

namespace DnsServerKit.Internal.Lookup;

internal sealed class DnsCompiledRecordNames(DnsName[] resourceNames, byte[] responsibleMailboxWireName)
{
    public DnsName[] ResourceNames { get; } = resourceNames;

    public byte[] ResponsibleMailboxWireName { get; } = responsibleMailboxWireName;
}

internal sealed class DnsIndexedRecordSet
{
    public DnsName Owner { get; }

    public ushort Type { get; }

    public ushort Class { get; }

    public RecordSet RecordSet { get; }

    public DnsName? CanonicalTarget => Type == (ushort)RecordType.CName ? CompiledNames!.ResourceNames[0] : null;

    public DnsCompiledRecordNames? CompiledNames { get; }

    public int CompressedWireLength { get; }

    public int UncompressedWireLength { get; }

    public DnsIndexedRecordSet(
        DnsName owner,
        ushort type,
        ushort @class,
        RecordSet recordSet,
        int compressedWireLength,
        int uncompressedWireLength,
        DnsCompiledRecordNames? compiledNames)
    {
        Owner = owner;
        Type = type;
        Class = @class;
        RecordSet = recordSet;
        CompressedWireLength = compressedWireLength;
        UncompressedWireLength = uncompressedWireLength;
        CompiledNames = compiledNames;
    }
}

internal sealed class DnsResolutionContext
{
    public const int MaximumCnameChainLength = 16;

    public bool AuthoritativeAnswer { get; private set; }

    public ResponseCode ResponseCode { get; private set; }

    public int AnswerSetCount { get; private set; }

    public bool HasDirectAnswer { get; private set; }

    public DnsIndexedRecordSet AuthoritySet { get; private set; } = null!;

    public bool HasAuthoritySet { get; private set; }

    public uint AuthorityTtl { get; private set; }

    public DnsIndexedRecordSet[] RequiredAdditionalSets { get; private set; } = [];

    public DnsIndexedRecordSet[] OptionalAdditionalSets { get; private set; } = [];

    private readonly DnsIndexedRecordSet[] _answerSets = new DnsIndexedRecordSet[MaximumCnameChainLength + 1];

    public DnsIndexedRecordSet GetAnswerSet(int index)
    {
        if ((uint)index >= (uint)AnswerSetCount)
            throw new ArgumentOutOfRangeException(nameof(index));

        return _answerSets[index];
    }

    public void Clear()
    {
        AuthoritativeAnswer = false;
        ResponseCode = ResponseCode.Refused;
        AnswerSetCount = 0;
        HasDirectAnswer = false;
        AuthoritySet = null!;
        HasAuthoritySet = false;
        AuthorityTtl = 0;
        RequiredAdditionalSets = [];
        OptionalAdditionalSets = [];
    }

    public bool TryAddAnswer(DnsIndexedRecordSet answerSet)
    {
        if (AnswerSetCount == _answerSets.Length)
            return false;

        _answerSets[AnswerSetCount++] = answerSet;
        return true;
    }

    public void SetPositive(bool authoritativeAnswer)
    {
        AuthoritativeAnswer = authoritativeAnswer;
        ResponseCode = ResponseCode.NoError;
    }

    public void SetDirectPositive(DnsIndexedRecordSet answerSet)
    {
        _answerSets[0] = answerSet;
        AnswerSetCount = 1;
        HasDirectAnswer = true;
        AuthoritativeAnswer = true;
        ResponseCode = ResponseCode.NoError;
        AuthoritySet = null!;
        HasAuthoritySet = false;
        RequiredAdditionalSets = [];
        OptionalAdditionalSets = [];
    }

    public void SetNegative(ResponseCode responseCode, DnsIndexedRecordSet authoritySet, uint authorityTtl)
    {
        AuthoritativeAnswer = true;
        ResponseCode = responseCode;
        AuthoritySet = authoritySet;
        HasAuthoritySet = true;
        AuthorityTtl = authorityTtl;
    }

    public void SetReferral(DnsIndexedRecordSet authoritySet, DnsIndexedRecordSet[] requiredAdditionalSets, DnsIndexedRecordSet[] optionalAdditionalSets)
    {
        AuthoritativeAnswer = AnswerSetCount > 0;
        ResponseCode = ResponseCode.NoError;
        AuthoritySet = authoritySet;
        HasAuthoritySet = true;
        AuthorityTtl = authoritySet.RecordSet.Ttl;
        RequiredAdditionalSets = requiredAdditionalSets;
        OptionalAdditionalSets = optionalAdditionalSets;
    }

    public void SetError(ResponseCode responseCode)
    {
        AuthoritativeAnswer = false;
        ResponseCode = responseCode;
    }
}
