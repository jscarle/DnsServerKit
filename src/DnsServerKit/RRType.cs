namespace DnsServerKit;

public enum RRType : ushort
{
    /// <summary>-</summary>
    Reserved = 0,

    /// <summary>a host address</summary>
    A = 1,

    /// <summary>an authoritative name server</summary>
    NS = 2,

    /// <summary>a mail destination (OBSOLETE - use MX)</summary>
    MD = 3,

    /// <summary>a mail forwarder (OBSOLETE - use MX)</summary>
    MF = 4,

    /// <summary>the canonical name for an alias</summary>
    CNAME = 5,

    /// <summary>marks the start of a zone of authority</summary>
    SOA = 6,

    /// <summary>a mailbox domain name (EXPERIMENTAL)</summary>
    MB = 7,

    /// <summary>a mail group member (EXPERIMENTAL)</summary>
    MG = 8,

    /// <summary>a mail rename domain name (EXPERIMENTAL)</summary>
    MR = 9,

    /// <summary>a null RR (EXPERIMENTAL)</summary>
    NULL = 10,

    /// <summary>a well known service description</summary>
    WKS = 11,

    /// <summary>a domain name pointer</summary>
    PTR = 12,

    /// <summary>host information</summary>
    HINFO = 13,

    /// <summary>mailbox or mail list information</summary>
    MINFO = 14,

    /// <summary>mail exchange</summary>
    MX = 15,

    /// <summary>text strings</summary>
    TXT = 16,

    /// <summary>for Responsible Person</summary>
    RP = 17,

    /// <summary>for AFS Data Base location</summary>
    AFSDB = 18,

    /// <summary>for X.25 PSDN address</summary>
    X25 = 19,

    /// <summary>for ISDN address</summary>
    ISDN = 20,

    /// <summary>for Route Through</summary>
    RT = 21,

    /// <summary>for NSAP address, NSAP style A record (DEPRECATED)</summary>
    NSAP = 22,

    /// <summary>for domain name pointer, NSAP style (DEPRECATED)</summary>
    NSAP_PTR = 23,

    /// <summary>for security signature</summary>
    SIG = 24,

    /// <summary>for security key</summary>
    KEY = 25,

    /// <summary>X.400 mail mapping information</summary>
    PX = 26,

    /// <summary>Geographical Position</summary>
    GPOS = 27,

    /// <summary>IP6 Address</summary>
    AAAA = 28,

    /// <summary>Location Information</summary>
    LOC = 29,

    /// <summary>Next Domain (OBSOLETE)</summary>
    NXT = 30,

    /// <summary>Endpoint Identifier</summary>
    EID = 31,

    /// <summary>Nimrod Locator</summary>
    NIMLOC = 32,

    /// <summary>Server Selection</summary>
    SRV = 33,

    /// <summary>ATM Address</summary>
    ATMA = 34,

    /// <summary>Naming Authority Pointer</summary>
    NAPTR = 35,

    /// <summary>Key Exchanger</summary>
    KX = 36,

    /// <summary>CERT</summary>
    CERT = 37,

    /// <summary>A6 (OBSOLETE - use AAAA)</summary>
    A6 = 38,

    /// <summary>DNAME</summary>
    DNAME = 39,

    /// <summary>SINK</summary>
    SINK = 40,

    /// <summary>OPT</summary>
    OPT = 41,

    /// <summary>APL</summary>
    APL = 42,

    /// <summary>Delegation Signer</summary>
    DS = 43,

    /// <summary>SSH Key Fingerprint</summary>
    SSHFP = 44,

    /// <summary>IPSECKEY</summary>
    IPSECKEY = 45,

    /// <summary>RRSIG</summary>
    RRSIG = 46,

    /// <summary>NSEC</summary>
    NSEC = 47,

    /// <summary>DNSKEY</summary>
    DNSKEY = 48,

    /// <summary>DHCID</summary>
    DHCID = 49,

    /// <summary>NSEC3</summary>
    NSEC3 = 50,

    /// <summary>NSEC3PARAM</summary>
    NSEC3PARAM = 51,

    /// <summary>TLSA</summary>
    TLSA = 52,

    /// <summary>S/MIME cert association</summary>
    SMIMEA = 53,

    /// <summary>Host Identity Protocol</summary>
    HIP = 55,

    /// <summary>NINFO</summary>
    NINFO = 56,

    /// <summary>RKEY</summary>
    RKEY = 57,

    /// <summary>Trust Anchor LINK</summary>
    TALINK = 58,

    /// <summary>Child DS</summary>
    CDS = 59,

    /// <summary>DNSKEY(s) the Child wants reflected in DS</summary>
    CDNSKEY = 60,

    /// <summary>OpenPGP Key</summary>
    OPENPGPKEY = 61,

    /// <summary>Child-To-Parent Synchronization</summary>
    CSYNC = 62,

    /// <summary>Message Digest Over Zone Data</summary>
    ZONEMD = 63,

    /// <summary>General-purpose service binding</summary>
    SVCB = 64,

    /// <summary>SVCB-compatible type for use with HTTP</summary>
    HTTPS = 65,

    /// <summary></summary>
    SPF = 99,

    /// <summary></summary>
    UINFO = 100,

    /// <summary></summary>
    UID = 101,

    /// <summary></summary>
    GID = 102,

    /// <summary></summary>
    UNSPEC = 103,

    /// <summary></summary>
    NID = 104,

    /// <summary></summary>
    L32 = 105,

    /// <summary></summary>
    L64 = 106,

    /// <summary></summary>
    LP = 107,

    /// <summary>an EUI-48 address</summary>
    EUI48 = 108,

    /// <summary>an EUI-64 address</summary>
    EUI64 = 109,

    /// <summary>Transaction Key</summary>
    TKEY = 249,

    /// <summary>Transaction Signature</summary>
    TSIG = 250,

    /// <summary>incremental transfer</summary>
    IXFR = 251,

    /// <summary>transfer of an entire zone</summary>
    AXFR = 252,

    /// <summary>mailbox-related RRs (MB, MG or MR)</summary>
    MAILB = 253,

    /// <summary>mail agent RRs (OBSOLETE - see MX)</summary>
    MAILA = 254,

    /// <summary>A request for some or all records the server has available</summary>
    Starrrrrrrr = 255,

    /// <summary>URI</summary>
    URI = 256,

    /// <summary>Certification Authority Restriction</summary>
    CAA = 257,

    /// <summary>Application Visibility and Control</summary>
    AVC = 258,

    /// <summary>Digital Object Architecture</summary>
    DOA = 259,

    /// <summary>Automatic Multicast Tunneling Relay</summary>
    AMTRELAY = 260,

    /// <summary>Resolver Information as Key/Value Pairs</summary>
    RESINFO = 261,

    /// <summary>Public wallet address</summary>
    WALLET = 262,

    /// <summary>DNSSEC Trust Authorities</summary>
    TA = 32768,

    /// <summary>DNSSEC Lookaside Validation (OBSOLETE)</summary>
    DLV = 32769,
}
