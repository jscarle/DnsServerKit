﻿using DnsServerKit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddHostedService<DnsServer>();

using var host = builder.Build();

await host.RunAsync();
