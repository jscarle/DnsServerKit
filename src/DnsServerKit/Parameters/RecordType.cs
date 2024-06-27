namespace DnsServerKit.Parameters;

/// <summary><c>Resource Record (RR) TYPEs</c> Represents the resource record types for DNS messages.</summary>
public enum RecordType : ushort
{
    /// <summary><c>A</c> Represents a host address.</summary>
    A = 1,

    /// <summary><c>NS</c> Represents an authoritative name server.</summary>
    Ns = 2,

    /// <summary><c>MD</c> Represents a mail destination (OBSOLETE - use MX).</summary>
    Md = 3,

    /// <summary><c>MF</c> Represents a mail forwarder (OBSOLETE - use MX).</summary>
    Mf = 4,

    /// <summary><c>CNAME</c> Represents the canonical name for an alias.</summary>
    CName = 5,

    /// <summary><c>SOA</c> Represents the start of a zone of authority.</summary>
    Soa = 6,

    /// <summary><c>MB</c> Represents a mailbox domain name (EXPERIMENTAL).</summary>
    Mb = 7,

    /// <summary><c>MG</c> Represents a mail group member (EXPERIMENTAL).</summary>
    Mg = 8,

    /// <summary><c>MR</c> Represents a mail rename domain name (EXPERIMENTAL).</summary>
    Mr = 9,

    /// <summary><c>NULL</c> Represents a null RR (EXPERIMENTAL).</summary>
    Null = 10,

    /// <summary><c>WKS</c> Represents a well known service description.</summary>
    Wks = 11,

    /// <summary><c>PTR</c> Represents a domain name pointer.</summary>
    Ptr = 12,

    /// <summary><c>HINFO</c> Represents host information.</summary>
    HInfo = 13,

    /// <summary><c>MINFO</c> Represents a mailbox or mail list information.</summary>
    MInfo = 14,

    /// <summary><c>MX</c> Represents mail exchange.</summary>
    Mx = 15,

    /// <summary><c>TXT</c> Represents text strings.</summary>
    Txt = 16,

    /// <summary><c>RP</c> Represents a Responsible Person.</summary>
    Rp = 17,

    /// <summary><c>AFSDB</c> Represents an AFS Data Base location.</summary>
    AfsDb = 18,

    /// <summary><c>X25</c> Represents a X.25 PSDN address.</summary>
    X25 = 19,

    /// <summary><c>ISDN</c> Represents an ISDN address.</summary>
    Isdn = 20,

    /// <summary><c>RT</c> Represents a Route Through.</summary>
    Rt = 21,

    /// <summary><c>NSAP</c> Represents a NSAP address, NSAP style A record (DEPRECATED).</summary>
    Nsap = 22,

    /// <summary><c>NSAP_PTR</c> Represents a domain name pointer, NSAP style (DEPRECATED).</summary>
    NsapPtr = 23,

    /// <summary><c>SIG</c> Represents a security signature.</summary>
    Sig = 24,

    /// <summary><c>KEY</c> Represents a security key.</summary>
    Key = 25,

    /// <summary><c>PX</c> Represents X.400 mail mapping information.</summary>
    Px = 26,

    /// <summary><c>GPOS</c> Represents a Geographical Position.</summary>
    Gpos = 27,

    /// <summary><c>AAAA</c> Represents an IP6 Address.</summary>
    Aaaa = 28,

    /// <summary><c>LOC</c> Represents Location Information.</summary>
    Loc = 29,

    /// <summary><c>NXT</c> Represents a Next Domain (OBSOLETE).</summary>
    Nxt = 30,

    /// <summary><c>EID</c> Represents an Endpoint Identifier.</summary>
    Eid = 31,

    /// <summary><c>NIMLOC</c> Represents a Nimrod Locator.</summary>
    NimLoc = 32,

    /// <summary><c>SRV</c> Represents a Server Selection.</summary>
    Srv = 33,

    /// <summary><c>ATMA</c> Represents an ATM Address.</summary>
    Atma = 34,

    /// <summary><c>NAPTR</c> Represents a Naming Authority Pointer.</summary>
    NaPtr = 35,

    /// <summary><c>KX</c> Represents a Key Exchanger.</summary>
    Kx = 36,

    /// <summary><c>CERT</c> Represents a CERT.</summary>
    Cert = 37,

    /// <summary><c>A6</c> Represents an A6 (OBSOLETE - use AAAA).</summary>
    A6 = 38,

    /// <summary><c>DNAME</c> Represents a DNAME.</summary>
    DName = 39,

    /// <summary><c>SINK</c> Represents a SINK.</summary>
    Sink = 40,

    /// <summary><c>OPT</c> Represents an OPT.</summary>
    Opt = 41,

    /// <summary><c>APL</c> Represents an APL.</summary>
    Apl = 42,

    /// <summary><c>DS</c> Represents a Delegation Signer.</summary>
    Ds = 43,

    /// <summary><c>SSHFP</c> Represents an SSH Key Fingerprint.</summary>
    SshFp = 44,

    /// <summary><c>IPSECKEY</c> Represents an IPSECKEY.</summary>
    IpsecKey = 45,

    /// <summary><c>RRSIG</c> Represents a RRSIG.</summary>
    RrSig = 46,

    /// <summary><c>NSEC</c> Represents a NSEC.</summary>
    NSec = 47,

    /// <summary><c>DNSKEY</c> Represents a DNSKEY.</summary>
    DnsKey = 48,

    /// <summary><c>DHCID</c> Represents a DHCID.</summary>
    DhcId = 49,

    /// <summary><c>NSEC3</c> Represents an NSEC3.</summary>
    NSec3 = 50,

    /// <summary><c>NSEC3PARAM</c> Represents an NSEC3PARAM.</summary>
    NSec3Param = 51,

    /// <summary><c>TLSA</c> Represents a TLSA.</summary>
    Tlsa = 52,

    /// <summary><c>SMIMEA</c> Represents a S/MIME cert association.</summary>
    SMimeA = 53,

    /// <summary><c>HIP</c> Represents a Host Identity Protocol.</summary>
    Hip = 55,

    /// <summary><c>NINFO</c> Represents a NINFO.</summary>
    NInfo = 56,

    /// <summary><c>RKEY</c> Represents a RKEY.</summary>
    RKey = 57,

    /// <summary><c>TALINK</c> Represents a Trust Anchor LINK.</summary>
    TaLink = 58,

    /// <summary><c>CDS</c> Represents a Child DS.</summary>
    Cds = 59,

    /// <summary><c>CDNSKEY</c> Represents a DNSKEY(s) the Child wants reflected in DS.</summary>
    CdnsKey = 60,

    /// <summary><c>OPENPGPKEY</c> Represents an OpenPGP Key.</summary>
    OpenPgpKey = 61,

    /// <summary><c>CSYNC</c> Represents a Child-To-Parent Synchronization.</summary>
    CSync = 62,

    /// <summary><c>ZONEMD</c> Represents a Message Digest Over Zone Data.</summary>
    ZoneMd = 63,

    /// <summary><c>SVCB</c> Represents a General-purpose service binding.</summary>
    Svcb = 64,

    /// <summary><c>HTTPS</c> Represents a SVCB-compatible type for use with HTTP.</summary>
    Https = 65,

    /// <summary><c>SPF</c> Represents an SPF.</summary>
    Spf = 99,

    /// <summary><c>UINFO</c> Represents a UINFO.</summary>
    UInfo = 100,

    /// <summary><c>UID</c> Represents a UID.</summary>
    Uid = 101,

    /// <summary><c>GID</c> Represents a GID.</summary>
    Gid = 102,

    /// <summary><c>UNSPEC</c> Represents an UNSPEC.</summary>
    UnSpec = 103,

    /// <summary><c>NID</c> Represents a NID.</summary>
    Nid = 104,

    /// <summary><c>L32</c> Represents an L32.</summary>
    L32 = 105,

    /// <summary><c>L64</c> Represents an L64.</summary>
    L64 = 106,

    /// <summary><c>LP</c> Represents an LP.</summary>
    Lp = 107,

    /// <summary><c>EUI48</c> Represents an EUI-48 address.</summary>
    Eui48 = 108,

    /// <summary><c>EUI64</c> Represents an EUI-64 address.</summary>
    Eui64 = 109,

    /// <summary><c>TKEY</c> Represents a Transaction Key.</summary>
    TKey = 249,

    /// <summary><c>TSIG</c> Represents a Transaction Signature.</summary>
    TSig = 250,

    /// <summary><c>IXFR</c> Represents a incremental transfer.</summary>
    IxFr = 251,

    /// <summary><c>AXFR</c> Represents a transfer of an entire zone.</summary>
    AxFr = 252,

    /// <summary><c>MAILB</c> Represents a mailbox-related RRs (MB, MG or MR).</summary>
    MailB = 253,

    /// <summary><c>MAILA</c> Represents a mail agent RRs (OBSOLETE - see MX).</summary>
    MailA = 254,

    /// <summary><c>All</c> Represents an A request for some or all records the server has available.</summary>
    All = 255,

    /// <summary><c>URI</c> Represents a URI.</summary>
    Uri = 256,

    /// <summary><c>CAA</c> Represents a Certification Authority Restriction.</summary>
    Caa = 257,

    /// <summary><c>AVC</c> Represents a Application Visibility and Control.</summary>
    Avc = 258,

    /// <summary><c>DOA</c> Represents a Digital Object Architecture.</summary>
    Doa = 259,

    /// <summary><c>AMTRELAY</c> Represents an Automatic Multicast Tunneling Relay.</summary>
    AmtRelay = 260,

    /// <summary><c>RESINFO</c> Represents a Resolver Information as Key/Value Pairs.</summary>
    ResInfo = 261,

    /// <summary><c>WALLET</c> Represents a Public wallet address.</summary>
    Wallet = 262,

    /// <summary><c>TA</c> Represents a DNSSEC Trust Authorities.</summary>
    Ta = 32768,

    /// <summary><c>DLV</c> Represents a DNSSEC Lookaside Validation (OBSOLETE).</summary>
    Dlv = 32769,
}
