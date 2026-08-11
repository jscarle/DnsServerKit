using System.Net;
using System.Net.Sockets;
using DnsServerKit.Internal.Protocol;
using DnsServerKit.Internal.Queries;
using DnsServerKit.Internal.Responses;
using DnsServerKit.Internal.Lookup;
using DnsServerKit.Zones;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DnsServerKit;

public sealed partial class DnsServer : IHostedService, IAsyncDisposable
{
    public IPEndPoint? BoundEndPoint => _udpSocket?.LocalEndPoint as IPEndPoint;
    private const int MaximumUdpMessageLength = 512;
    private readonly DnsZoneStore _zoneStore;
    private readonly DnsServerOptions _options;
    private readonly ILogger<DnsServer> _logger;
    private CancellationTokenSource? _stopSource;
    private Socket? _udpSocket;
    private DnsWorker[]? _workers;
    private Task[]? _workerTasks;
    private Task? _statisticsTask;

    public DnsServer(DnsZoneStore zoneStore, DnsServerOptions options, ILogger<DnsServer> logger)
    {
        ArgumentNullException.ThrowIfNull(zoneStore);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _zoneStore = zoneStore;
        _options = options;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_udpSocket is not null)
            throw new InvalidOperationException("The DNS server has already been started.");
        if (_options.ListenAddress is null)
            throw new InvalidOperationException("A listen address is required.");
        if (_options.ListenAddress.AddressFamily != AddressFamily.InterNetwork)
            throw new InvalidOperationException("This server currently supports only IPv4 UDP sockets.");
        if (_options.Port is < 0 or > ushort.MaxValue)
            throw new InvalidOperationException("The DNS server port must be between 0 and 65,535.");
        if (_options.WorkerCount <= 0)
            throw new InvalidOperationException("The DNS worker count must be greater than zero.");
        if (_options.ReceiveBufferSize < MaximumUdpMessageLength)
            throw new InvalidOperationException("The socket receive buffer must be at least 512 bytes.");
        if (_options.StatisticsInterval <= TimeSpan.Zero)
            throw new InvalidOperationException("The statistics interval must be greater than zero.");

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveBufferSize = _options.ReceiveBufferSize };

        try
        {
            socket.Bind(new IPEndPoint(_options.ListenAddress, _options.Port));
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        _udpSocket = socket;
        _stopSource = new CancellationTokenSource();
        _workers = new DnsWorker[_options.WorkerCount];
        _workerTasks = new Task[_options.WorkerCount];

        for (var workerIndex = 0; workerIndex < _workers.Length; workerIndex++)
        {
            var worker = new DnsWorker(workerIndex);
            _workers[workerIndex] = worker;
            _workerTasks[workerIndex] = RunWorkerAsync(socket, worker, _stopSource.Token);
        }

        _statisticsTask = ReportStatisticsAsync(_workers, _stopSource.Token);
        if (_options.RecursionAvailable)
            LogRecursionOptionIgnored(_logger);
        LogServerStarted(_logger, BoundEndPoint, _workers.Length, socket.ReceiveBufferSize);

        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        var socket = Interlocked.Exchange(ref _udpSocket, null);
        if (socket is null)
            return;

        _stopSource?.Cancel();
        socket.Dispose();

        if (_workerTasks is not null)
            await Task.WhenAll(_workerTasks)
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);

        if (_statisticsTask is not null)
            await _statisticsTask.WaitAsync(cancellationToken)
                .ConfigureAwait(false);

        LogServerStopped(_logger);
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync(CancellationToken.None)
            .ConfigureAwait(false);
        _stopSource?.Dispose();
    }

    private async Task RunWorkerAsync(Socket socket, DnsWorker worker, CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var hasTrustedQuery = false;
            try
            {
                var receivedBytes = await socket.ReceiveFromAsync(worker.Buffer.AsMemory(), SocketFlags.None, worker.RemoteAddress, CancellationToken.None)
                    .ConfigureAwait(false);
                worker.Received++;

                var datagram = worker.Buffer.AsMemory(0, receivedBytes);
                var readResult = DnsReader.Read(datagram, worker.Query);
                if (readResult.Outcome == DnsReadOutcome.Drop)
                {
                    worker.Dropped++;
                    continue;
                }

                if (readResult.Outcome == DnsReadOutcome.ErrorResponse)
                {
                    if (readResult.Failure == DnsReadFailure.UnsupportedOperation)
                    {
                        worker.Unsupported++;
                    }
                    else if (readResult.Failure == DnsReadFailure.UnexpectedException)
                    {
                        worker.UnexpectedFailures++;
                        LogUnexpectedFailure(_logger, readResult.Exception, worker.Id);
                    }
                    else
                    {
                        worker.Malformed++;
                    }

                    var errorLength = DnsWriter.WriteErrorResponse(worker.Buffer, readResult.ErrorResponse);
                    await socket.SendToAsync(worker.Buffer.AsMemory(0, errorLength), SocketFlags.None, worker.RemoteAddress, CancellationToken.None)
                        .ConfigureAwait(false);
                    worker.ResponsesSent++;
                    continue;
                }

                hasTrustedQuery = true;
                _zoneStore.Resolve(worker.Query.Question, worker.Resolution);
                worker.Response.Set(worker.Query, worker.Resolution);

                var responseLength = DnsWriter.Write(worker.Buffer, worker.Response);
                if ((worker.Buffer[2] & 0x02) != 0)
                    worker.Truncated++;

                await socket.SendToAsync(worker.Buffer.AsMemory(0, responseLength), SocketFlags.None, worker.RemoteAddress, CancellationToken.None)
                    .ConfigureAwait(false);
                worker.Answered++;
                worker.ResponsesSent++;
            }
            catch (SocketException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (SocketException)
            {
                worker.SocketFailures++;
            }
            catch (Exception exception)
            {
                worker.UnexpectedFailures++;
                LogUnexpectedFailure(_logger, exception, worker.Id);

                if (!hasTrustedQuery)
                    continue;

                try
                {
                    var serverFailureResponse = new DnsErrorResponse(worker.Query.TransactionId, worker.Query.Operation, worker.Query.RecursionDesired,
                        ResponseCode.ServerFailure
                    );
                    var errorLength = DnsWriter.WriteErrorResponse(worker.Buffer, serverFailureResponse);
                    await socket.SendToAsync(worker.Buffer.AsMemory(0, errorLength), SocketFlags.None, worker.RemoteAddress, CancellationToken.None)
                        .ConfigureAwait(false);
                    worker.ResponsesSent++;
                }
                catch (SocketException)
                {
                    worker.SocketFailures++;
                }
            }
        }
    }

    private async Task ReportStatisticsAsync(DnsWorker[] workers, CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_options.StatisticsInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken)
                       .ConfigureAwait(false))
            {
                long received = 0;
                long answered = 0;
                long responsesSent = 0;
                long dropped = 0;
                long malformed = 0;
                long unsupported = 0;
                long truncated = 0;
                long socketFailures = 0;
                long unexpectedFailures = 0;

                foreach (var worker in workers)
                {
                    received += Volatile.Read(ref worker.Received);
                    answered += Volatile.Read(ref worker.Answered);
                    responsesSent += Volatile.Read(ref worker.ResponsesSent);
                    dropped += Volatile.Read(ref worker.Dropped);
                    malformed += Volatile.Read(ref worker.Malformed);
                    unsupported += Volatile.Read(ref worker.Unsupported);
                    truncated += Volatile.Read(ref worker.Truncated);
                    socketFailures += Volatile.Read(ref worker.SocketFailures);
                    unexpectedFailures += Volatile.Read(ref worker.UnexpectedFailures);
                }

                LogStatistics(_logger, received, answered, responsesSent, dropped, malformed, unsupported, truncated, socketFailures, unexpectedFailures);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    [LoggerMessage(EventId = 1, Level = LogLevel.Information,
        Message = "DNS server listening on {EndPoint} with {WorkerCount} workers and a {ReceiveBufferSize}-byte socket receive buffer."
    )]
    private static partial void LogServerStarted(ILogger logger, IPEndPoint? endPoint, int workerCount, int receiveBufferSize);

    [LoggerMessage(EventId = 2, Level = LogLevel.Information, Message = "DNS server stopped.")]
    private static partial void LogServerStopped(ILogger logger);

    [LoggerMessage(EventId = 3, Level = LogLevel.Information,
        Message =
            "DNS totals: received={Received}, answered={Answered}, responses={ResponsesSent}, dropped={Dropped}, malformed={Malformed}, unsupported={Unsupported}, truncated={Truncated}, socketFailures={SocketFailures}, unexpectedFailures={UnexpectedFailures}."
    )]
    private static partial void LogStatistics(
        ILogger logger,
        long received,
        long answered,
        long responsesSent,
        long dropped,
        long malformed,
        long unsupported,
        long truncated,
        long socketFailures,
        long unexpectedFailures
    );

    [LoggerMessage(EventId = 4, Level = LogLevel.Error, Message = "Unexpected DNS worker failure on worker {WorkerId}.")]
    private static partial void LogUnexpectedFailure(ILogger logger, Exception? exception, int workerId);

    [LoggerMessage(EventId = 5, Level = LogLevel.Warning,
        Message = "DnsServerOptions.RecursionAvailable is ignored because DnsServerKit provides authoritative-only DNS service.")]
    private static partial void LogRecursionOptionIgnored(ILogger logger);

    private sealed class DnsWorker(int id)
    {
        public int Id { get; } = id;

        public byte[] Buffer { get; } = GC.AllocateUninitializedArray<byte>(MaximumUdpMessageLength, true);

        public SocketAddress RemoteAddress { get; } = new(AddressFamily.InterNetwork, 16);

        public DnsQueryContext Query { get; } = new();

        public DnsResponseContext Response { get; } = new();

        public DnsResolutionContext Resolution { get; } = new();

        public long Received;
        public long Answered;
        public long ResponsesSent;
        public long Dropped;
        public long Malformed;
        public long Unsupported;
        public long Truncated;
        public long SocketFailures;
        public long UnexpectedFailures;
    }
}
