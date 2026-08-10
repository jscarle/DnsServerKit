using System.Net;
using DnsServerKit;
using DnsServerKit.Data;
using DnsServerKit.ResourceRecords;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

var dataSetBuilder = new DnsDataSetBuilder();
dataSetBuilder.Add(new ARecord(
    new DnsName("example.com"),
    IPAddress.Parse("151.101.2.217")));
dataSetBuilder.Add(new PtrRecord(
    new DnsName("217.2.101.151.in-addr.arpa"),
    new DnsName("localhost")));

var dataSetStore = new DnsDataSetStore(dataSetBuilder.Build());
builder.Services.AddSingleton(dataSetStore);
builder.Services.AddSingleton(new DnsServerOptions());
builder.Services.AddHostedService<DnsServer>();

using var host = builder.Build();
await host.RunAsync();
