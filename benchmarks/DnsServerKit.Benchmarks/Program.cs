using BenchmarkDotNet.Running;
using DnsServerKit.Benchmarks;

BenchmarkSwitcher.FromAssembly(typeof(DnsPipelineBenchmarks).Assembly).Run(args);
