using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Parameters;
using DnsServerKit.Records;
using DnsServerKit.Zones;
using Microsoft.Extensions.Logging.Abstractions;

namespace DnsServerKit.LoadGenerator;

public static class Program
{
    public static async Task Main(string[] args)
    {
        var queriesPerClient = args.Length > 0 ? int.Parse(args[0]) : 10_000;
        var clientCount = args.Length > 1 ? int.Parse(args[1]) : Math.Max(4, Environment.ProcessorCount);
        if (queriesPerClient <= 0 || clientCount <= 0)
            throw new ArgumentOutOfRangeException(nameof(args), "Query and client counts must be greater than zero.");

        var zoneBuilder = new DnsZoneBuilder("load.example");
        zoneBuilder.AddRecordSet(new SoaRecordSet
        {
            Name = "@",
            Ttl = 300,
            Record = new SoaRecord
            {
                PrimaryNameServer = "ns1.load.example",
                ResponsibleMailbox = "hostmaster@load.example",
                Serial = 1,
                Refresh = 3600,
                Retry = 600,
                Expire = 1_209_600,
                Minimum = 300,
            },
        });
        zoneBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new NsRecord { NameServer = "ns1.load.example" }],
        });
        zoneBuilder.AddRecordSet(new ARecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new ARecord { Address = "192.0.2.1" }],
        });
        zoneBuilder.AddRecordSet(new ARecordSet
        {
            Name = "ns1",
            Ttl = 300,
            Records = [new ARecord { Address = "192.0.2.53" }],
        });
        var zoneSetBuilder = new DnsZoneSetBuilder();
        zoneSetBuilder.Load(zoneBuilder);
        var store = new DnsZoneStore();
        store.Load(zoneSetBuilder.Build());
        int[] requestedWorkerCounts =
        [
            1,
            Math.Max(1, Environment.ProcessorCount / 2),
            Environment.ProcessorCount,
            Environment.ProcessorCount * 2,
        ];
        var workerCounts = new SortedSet<int>(requestedWorkerCounts);

        Console.WriteLine($"Clients: {clientCount}; queries per client: {queriesPerClient:N0}");
        Console.WriteLine("Workers | Queries/s | p50 (us) | p99 (us) | Lost | Process bytes/query");
        foreach (var workerCount in workerCounts)
            await RunScenarioAsync(store, workerCount, clientCount, queriesPerClient);
    }

    private static async Task RunScenarioAsync(
        DnsZoneStore store,
        int workerCount,
        int clientCount,
        int queriesPerClient)
    {
        var options = new DnsServerOptions
        {
            ListenAddress = IPAddress.Loopback,
            Port = 0,
            WorkerCount = workerCount,
            ReceiveBufferSize = 4 * 1024 * 1024,
            StatisticsInterval = TimeSpan.FromHours(1),
        };
        await using var server = new DnsServer(store, options, NullLogger<DnsServer>.Instance);
        await server.StartAsync(CancellationToken.None);
        var endPoint = server.BoundEndPoint ?? throw new InvalidOperationException("The DNS server did not expose its bound endpoint.");
        using var timeoutSource = new CancellationTokenSource(TimeSpan.FromMinutes(2));

        var clientTasks = new Task<ClientLoadResult>[clientCount];
        var allocatedBytesBefore = GC.GetTotalAllocatedBytes(true);
        var stopwatch = Stopwatch.StartNew();
        for (var clientIndex = 0; clientIndex < clientTasks.Length; clientIndex++)
            clientTasks[clientIndex] = RunClientAsync(endPoint, clientIndex, queriesPerClient, timeoutSource.Token);

        var clientResults = await Task.WhenAll(clientTasks);
        stopwatch.Stop();
        var allocatedBytes = GC.GetTotalAllocatedBytes() - allocatedBytesBefore;
        await server.StopAsync(timeoutSource.Token);

        var completedQueries = 0;
        var lostQueries = 0;
        var latencyIndex = 0;
        var latencies = new long[clientCount * queriesPerClient];
        foreach (var clientResult in clientResults)
        {
            completedQueries += clientResult.CompletedQueries;
            lostQueries += clientResult.LostQueries;
            clientResult.LatencyTicks.AsSpan(0, clientResult.CompletedQueries).CopyTo(latencies.AsSpan(latencyIndex));
            latencyIndex += clientResult.CompletedQueries;
        }

        Array.Sort(latencies, 0, latencyIndex);
        if (latencyIndex == 0)
        {
            Console.WriteLine($"{workerCount,7} | {0,9:N0} | {"N/A",8} | {"N/A",8} | {lostQueries,4} | {0,19:N0}");
            return;
        }

        var p50Ticks = latencies[(latencyIndex - 1) / 2];
        var p99Ticks = latencies[(int)Math.Floor((latencyIndex - 1) * 0.99)];
        var p50Microseconds = p50Ticks * 1_000_000D / Stopwatch.Frequency;
        var p99Microseconds = p99Ticks * 1_000_000D / Stopwatch.Frequency;
        var queriesPerSecond = completedQueries / stopwatch.Elapsed.TotalSeconds;
        var allocatedBytesPerQuery = allocatedBytes / latencyIndex;

        Console.WriteLine($"{workerCount,7} | {queriesPerSecond,9:N0} | {p50Microseconds,8:N1} | {p99Microseconds,8:N1} | {lostQueries,4} | {allocatedBytesPerQuery,19:N0}");
    }

    private static async Task<ClientLoadResult> RunClientAsync(
        IPEndPoint serverEndPoint,
        int clientIndex,
        int queryCount,
        CancellationToken cancellationToken)
    {
        using var client = new UdpClient(AddressFamily.InterNetwork);
        var name = new DnsName("load.example");
        var wireName = name.WireBytes;
        var query = new byte[12 + wireName.Length + 4];
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(4), 1);
        wireName.CopyTo(query.AsSpan(12));
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(12 + wireName.Length), (ushort)RecordType.A);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(14 + wireName.Length), (ushort)DnsClass.Internet);

        var latencyTicks = new long[queryCount];
        var completedQueries = 0;
        var lostQueries = 0;
        for (var queryIndex = 0; queryIndex < queryCount; queryIndex++)
        {
            var transactionId = unchecked((ushort)((clientIndex * queryCount) + queryIndex + 1));
            BinaryPrimitives.WriteUInt16BigEndian(query, transactionId);
            var startTimestamp = Stopwatch.GetTimestamp();

            await client.SendAsync(query, serverEndPoint, cancellationToken);
            var response = await client.ReceiveAsync(cancellationToken);
            if (response.Buffer.Length < 12 || BinaryPrimitives.ReadUInt16BigEndian(response.Buffer) != transactionId)
            {
                lostQueries++;
                continue;
            }

            latencyTicks[completedQueries++] = Stopwatch.GetTimestamp() - startTimestamp;
        }

        return new ClientLoadResult(latencyTicks, completedQueries, lostQueries);
    }

    private sealed record ClientLoadResult(long[] LatencyTicks, int CompletedQueries, int LostQueries);
}
