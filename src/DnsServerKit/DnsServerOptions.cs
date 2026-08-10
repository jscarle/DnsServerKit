using System.Net;

namespace DnsServerKit;

/// <summary>Configures the managed UDP DNS server.</summary>
public sealed class DnsServerOptions
{
    public IPAddress ListenAddress { get; init; } = IPAddress.Any;

    public int Port { get; init; } = 53;

    public int WorkerCount { get; init; } = Environment.ProcessorCount;

    public int ReceiveBufferSize { get; init; } = 4 * 1024 * 1024;

    public TimeSpan StatisticsInterval { get; init; } = TimeSpan.FromSeconds(10);

    public bool RecursionAvailable { get; init; } = true;
}
