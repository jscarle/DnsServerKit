using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DnsServerKit;

public sealed class DnsServer : IHostedService, IAsyncDisposable
{
    private readonly byte[] _buffer = new byte[512];
    private readonly IPEndPoint _localEndpoint = new(IPAddress.Any, 53);
    private readonly ILogger<DnsServer> _logger;
    private CancellationTokenSource? _cts;
    private Task? _listeningTask;
    private Socket? _udpSocket;

    public DnsServer(ILogger<DnsServer> logger)
    {
        _logger = logger;
    }

    public async ValueTask DisposeAsync()
    {
        if (_udpSocket != null)
        {
            _udpSocket.Close();
            _udpSocket.Dispose();
        }

        _cts?.Dispose();

        if (_listeningTask != null)
            await _listeningTask;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _udpSocket.Bind(_localEndpoint);
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        _listeningTask = ListenForQueriesAsync(_cts.Token);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _cts?.Cancel();
        return _listeningTask ?? Task.CompletedTask;
    }

    private async Task ListenForQueriesAsync(CancellationToken cancellationToken)
    {
        Debug.Assert(_udpSocket is not null);

        _logger.LogInformation("Starting to listen...");

        try
        {
            var memory = _buffer.AsMemory();
            var remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var result = await _udpSocket.ReceiveFromAsync(memory, SocketFlags.None, remoteEndpoint, cancellationToken);

                    if (DnsRequest.TryCreate(memory).IsSuccess(out var dnsRequest, out var error))
                    {
                        _logger.LogInformation("{ReceivedBytes} bytes received.\r\n{Request}", result.ReceivedBytes, dnsRequest);
                        foreach(var question in dnsRequest.Questions)
                            _logger.LogInformation(" - {Question}", question);
                    }
                    else
                    {
                        _logger.LogError("{Error}", error.Message);
                    }
                    
                    

                    // Echo back for now.
                    await _udpSocket!.SendToAsync(memory, SocketFlags.None, result.RemoteEndPoint, cancellationToken);
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
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}
