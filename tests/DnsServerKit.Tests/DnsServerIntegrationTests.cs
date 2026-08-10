using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using DnsServerKit.Records;
using DnsServerKit.Zones;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DnsServerKit.Tests;

public sealed class DnsServerIntegrationTests
{
    [Fact]
    public async Task ConcurrentWorkers_WhenQueriesArriveFromMultipleClients_PreserveTransactionAndEndpointPairing()
    {
        var zoneBuilder = new DnsZoneBuilder("example.com");
        zoneBuilder.AddRecordSet(new SoaRecordSet
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
        zoneBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new NsRecord { NameServer = "ns1.example.com" }],
        });
        zoneBuilder.AddRecordSet(new ARecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new ARecord { Address = "192.0.2.1" }],
        });
        var zoneSetBuilder = new DnsZoneSetBuilder();
        zoneSetBuilder.Load(zoneBuilder);
        var store = new DnsZoneStore();
        store.Load(zoneSetBuilder.Build());
        var options = new DnsServerOptions
        {
            ListenAddress = IPAddress.Loopback,
            Port = 0,
            WorkerCount = 4,
            ReceiveBufferSize = 1024 * 1024,
            StatisticsInterval = TimeSpan.FromHours(1),
        };
        await using var server = new DnsServer(store, options, NullLogger<DnsServer>.Instance);
        await server.StartAsync(CancellationToken.None);
        var serverEndPoint = Assert.IsType<IPEndPoint>(server.BoundEndPoint);
        using var timeoutSource = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var timeoutToken = timeoutSource.Token;

        const int clientCount = 8;
        const int queriesPerClient = 50;
        var clientTasks = new Task[clientCount];
        for (var clientIndex = 0; clientIndex < clientTasks.Length; clientIndex++)
        {
            var capturedClientIndex = clientIndex;
            clientTasks[clientIndex] = Task.Run(async () =>
            {
                using var client = new UdpClient(AddressFamily.InterNetwork);
                for (var queryIndex = 0; queryIndex < queriesPerClient; queryIndex++)
                {
                    var transactionId = checked((ushort)((capturedClientIndex * queriesPerClient) + queryIndex + 1));
                    var packet = DnsTestPacket.CreateQuery(transactionId: transactionId);

                    await client.SendAsync(packet, serverEndPoint, timeoutToken);
                    var result = await client.ReceiveAsync(timeoutToken);
                    var response = result.Buffer;

                    Assert.Equal(transactionId, BinaryPrimitives.ReadUInt16BigEndian(response));
                    Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(4)));
                    Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6)));
                    Assert.Equal((ushort)0, (ushort)(BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2)) & 0x000F));
                }
            }, timeoutToken);
        }

        await Task.WhenAll(clientTasks);
        await server.StopAsync(timeoutToken);
    }
}
