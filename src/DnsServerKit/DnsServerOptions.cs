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

    /// <summary>
    /// Retained for source compatibility. <see cref="DnsServer"/> is authoritative-only and always reports recursion as unavailable.
    /// </summary>
    // ReSharper disable once UnusedAutoPropertyAccessor.Global -- The init accessor is part of the compatibility surface.
    public bool RecursionAvailable { get; init; }
}
