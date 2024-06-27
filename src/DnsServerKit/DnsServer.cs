using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using DnsServerKit.Parameters;
using DnsServerKit.Queries;
using DnsServerKit.ResourceRecords;
using DnsServerKit.Responses;
using LightResults;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DnsServerKit;

public sealed class DnsServer : IHostedService, IAsyncDisposable
{
    private readonly ILogger<DnsServer> _logger;
    private CancellationTokenSource? _cts;
    private Socket? _udpSocket;
    private Task? _listeningTask;

    public DnsServer(ILogger<DnsServer> logger)
    {
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        _udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        var localEndpoint = new IPEndPoint(IPAddress.Any, 53);
        _udpSocket.Bind(localEndpoint);
        
        _listeningTask = ListenForQueriesAsync(_cts.Token);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _cts?.Cancel();
        
        return _listeningTask ?? Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        if (_listeningTask != null)
            await _listeningTask;

        if (_udpSocket != null)
        {
            _udpSocket.Close();
            _udpSocket.Dispose();
        }

        _cts?.Dispose();
    }

    private async Task ListenForQueriesAsync(CancellationToken cancellationToken)
    {
        Debug.Assert(_udpSocket is not null);

        _logger.LogInformation("Starting to listen...");

        var remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
        var buffer = new byte[512];
        var memory = buffer.AsMemory();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var result = await _udpSocket.ReceiveFromAsync(memory, SocketFlags.None, remoteEndpoint, cancellationToken);

                if (DnsQuery.TryParse(memory).IsFailed(out var error, out var dnsQuery))
                {
                    _logger.LogError("{Error}", error.Message);
                    continue;
                }

                var log = new StringBuilder();
                log.AppendLine($"{result.ReceivedBytes} bytes received.");
                log.AppendLine($"{dnsQuery}");
                foreach(var question in dnsQuery.Questions)
                    log.AppendLine($" - {question}");
                _logger.LogInformation("{Message}", log.ToString());

                var aRecord = new ARecord
                {
                    Name = "google.ca",
                    IpAddress = IPAddress.Parse("8.8.8.8"),
                };

                var answers = new List<IResourceRecord>
                {
                    aRecord,
                };

                var dnsResponse = new DnsResponse(dnsQuery, true, false, answers);

                var data = new List<ReadOnlyMemory<byte>>
                {
                    dnsResponse.HeaderData,
                };
                foreach (var question in dnsResponse.Questions)
                    data.Add(question.QuestionData);
                foreach (var answer in dnsResponse.Answers)
                    data.Add(answer.ResourceData);

                var length = data.Sum(x => x.Length);
                var bytes = new byte[length];
                var offset = 0;
                foreach (var readOnlyMemory in data)
                {
                    var arr = readOnlyMemory.ToArray();
                    Buffer.BlockCopy(arr, 0, bytes, offset, arr.Length);
                    offset += arr.Length;
                }
                var outMemory = new ReadOnlyMemory<byte>(bytes);

                // Echo back for now.
                await _udpSocket!.SendToAsync(outMemory, SocketFlags.None, result.RemoteEndPoint, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception occurred while receiving data: {ex}");
            }
        }
    }
}
