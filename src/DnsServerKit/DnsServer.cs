using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using DnsServerKit.Parameters;
using DnsServerKit.Queries;
using DnsServerKit.ResourceRecords;
using DnsServerKit.Responses;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DnsServerKit;

public sealed class DnsServer : IHostedService, IAsyncDisposable
{
    private readonly IMemoryCache _memoryCache;
    private readonly ILogger<DnsServer> _logger;
    private CancellationTokenSource? _cts;
    private Socket? _udpSocket;
    private Task? _listeningTask;

    public DnsServer(IMemoryCache memoryCache, ILogger<DnsServer> logger)
    {
        _memoryCache = memoryCache;
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
            try
            {
                var receiveResult = await _udpSocket.ReceiveFromAsync(receiveBuffer, SocketFlags.None, remoteEndpoint, cancellationToken);
                if (DnsReader.TryReadBytes(receiveBuffer).IsFailed(out var error, out var dnsQuery))
                {
                    _logger.LogError("{Error}", error.Message);
                    continue;
                }
                
                //LogQuery(receiveResult.ReceivedBytes, dnsQuery);

                var dnsResponse = CreateDnsResponse(dnsQuery);
                
                Debug.Assert(dnsResponse is not null);

                using var dnsWriter = new DnsWriter(dnsResponse);
                var sendBuffer = dnsWriter.GetBytes();
                var sentBytes = await _udpSocket.SendToAsync(sendBuffer, SocketFlags.None, receiveResult.RemoteEndPoint, cancellationToken);
                //LogResponse(sentBytes, dnsResponse);
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
        var answers = new List<IResourceRecord>();

        foreach (var question in dnsQuery.Questions)
        {
            if (question is { Class: DnsClass.Internet, Type: RecordType.A })
            {
                answers.Add(new ARecord
                {
                    Name = question.Name,
                    IpAddress = IPAddress.Parse("151.101.2.217"),
                });
            }
            if (question is { Class: DnsClass.Internet, Type: RecordType.Ptr })
            {
                answers.Add(new PtrRecord
                {
                    Name = "localhost",
                });
            }
        }

        if (answers.Count == 0)
        {
            return new DnsResponse(dnsQuery, false, true, ResponseCode.NotZone);
        }
        
        return new DnsResponse(dnsQuery, false, true, answers);
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
