using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml;
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

        var memoryOwner = MemoryPool<byte>.Shared.Rent(512);
        var receiveBuffer = memoryOwner.Memory;

        while (!cancellationToken.IsCancellationRequested)
        {
                var receiveResult = await _udpSocket.ReceiveFromAsync(receiveBuffer, SocketFlags.None, remoteEndpoint, cancellationToken);
                if (DnsReader.TryReadBytes(receiveBuffer).IsFailed(out var error, out var dnsQuery))
                {
                    _logger.LogError("{Error}", error.Message);
                    continue;
                }
                
                LogQuery(receiveResult.ReceivedBytes, dnsQuery);
                var dnsResponse = CreateDnsResponse(dnsQuery);

                var sendBuffer = DnsWriter.GetBytes(dnsResponse);
                var sentBytes = await _udpSocket.SendToAsync(sendBuffer, SocketFlags.None, receiveResult.RemoteEndPoint, cancellationToken);
                LogResponse(sentBytes, dnsResponse);
            try
            {
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An exception occured while processing the DNS request.");
            }
        }
    }

    private static DnsResponse CreateDnsResponse(DnsQuery dnsQuery)
    {
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
        return dnsResponse;
    }

    private void LogQuery(int receivedBytes, DnsQuery dnsQuery)
    {
        var log = new StringBuilder();
        log.AppendLine($"{receivedBytes} bytes received.");
        log.AppendLine($"{dnsQuery}");
        foreach(var question in dnsQuery.Questions)
            log.AppendLine($" - {question}");
        _logger.LogInformation("{Message}", log.ToString());
    }

    private void LogResponse(int receivedBytes, DnsResponse dnsResponse)
    {
        var log = new StringBuilder();
        log.AppendLine($"{receivedBytes} bytes received.");
        log.AppendLine($"{dnsResponse}");
        foreach(var answer in dnsResponse.Answers)
            log.AppendLine($" - {answer}");
        _logger.LogInformation("{Message}", log.ToString());
    }
}
