using DnsServerKit;
using DnsServerKit.Records;
using DnsServerKit.Zones;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

var forwardZoneBuilder = new DnsZoneBuilder("example.com");
forwardZoneBuilder.AddSoaRecord(
    300,
    "ns1.example.com",
    "hostmaster@example.com",
    serial: 1,
    refresh: 3600,
    retry: 600,
    expire: 1_209_600,
    minimum: 300);
forwardZoneBuilder.AddNsRecord(300, "ns1.example.com");
forwardZoneBuilder.AddARecord(300, "@", "151.101.2.217");
forwardZoneBuilder.AddARecord(300, "ns1", "192.0.2.53");

var reverseZoneBuilder = new DnsZoneBuilder("2.101.151.in-addr.arpa");
reverseZoneBuilder.AddRecordSet(new SoaRecordSet
{
    Name = "@",
    Ttl = 300,
    Record = new SoaRecord
    {
        PrimaryNameServer = "ns1.example.com",
        ResponsibleMailbox = "hostmaster@example.com",
        Serial = 1,
        Refresh = 3600,
        Retry = 600,
        Expire = 1_209_600,
        Minimum = 300,
    },
});
reverseZoneBuilder.AddRecordSet(new NsRecordSet
{
    Name = "@",
    Ttl = 300,
    Records = [new NsRecord { NameServer = "ns1.example.com" }],
});
reverseZoneBuilder.AddRecordSet(new PtrRecordSet
{
    Name = "217",
    Ttl = 300,
    Records = [new PtrRecord { Target = "example.com" }],
});

var zoneSetBuilder = new DnsZoneSetBuilder();
zoneSetBuilder.Load(forwardZoneBuilder);
zoneSetBuilder.Load(reverseZoneBuilder);

var zoneStore = new DnsZoneStore();
zoneStore.Load(zoneSetBuilder.Build());

var dnsOptions = new DnsServerOptions
{
    Port = 53,
};

builder.Services.AddSingleton(zoneStore);
builder.Services.AddSingleton(dnsOptions);
builder.Services.AddHostedService<DnsServer>();

using var host = builder.Build();
await host.RunAsync();
