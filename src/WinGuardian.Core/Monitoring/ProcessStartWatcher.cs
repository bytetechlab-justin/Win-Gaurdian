using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace WinGuardian.Core.Monitoring;

/// <summary>
/// Real-time process start notifications from the kernel via ETW (Event Tracing for Windows).
/// Unlike polling, this sees processes that start and exit within milliseconds, and it provides
/// the parent process and full command line. Requires administrator/SYSTEM rights.
/// </summary>
public sealed class ProcessStartWatcher(ProcessMonitor monitor, ProcessHistory history, ILogger<ProcessStartWatcher> logger) : IDisposable
{
    private const string SessionName = "WinGuardian-ProcessTrace";

    private readonly Channel<ProcessStart> _queue = Channel.CreateBounded<ProcessStart>(
        new BoundedChannelOptions(10_000) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });
    private TraceEventSession? _session;
    private Thread? _thread;
    private Task? _consumer;

    public bool IsRunning => _session is not null;

    public bool Start()
    {
        if (_session is not null) return true;
        try
        {
            if (TraceEventSession.IsElevated() != true)
            {
                logger.LogWarning("ETW process tracing needs administrator rights; falling back to polling only");
                return false;
            }

            // Windows 8+ allows kernel providers in privately named sessions, so this does not
            // collide with other tools using the global "NT Kernel Logger" session.
            var session = new TraceEventSession(SessionName) { StopOnDispose = true };
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);
            session.Source.Kernel.ProcessStart += OnProcessStart;
            _session = session;

            _thread = new Thread(() =>
            {
                try
                {
                    session.Source.Process(); // blocks until the session is disposed
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "ETW process trace stopped unexpectedly");
                }
            })
            { IsBackground = true, Name = "WinGuardian ETW" };
            _thread.Start();

            _consumer = Task.Run(ConsumeAsync);
            logger.LogInformation("ETW process start tracing enabled");
            return true;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not start ETW process tracing; falling back to polling only");
            _session?.Dispose();
            _session = null;
            return false;
        }
    }

    private void OnProcessStart(ProcessTraceData data)
    {
        // Resolve paths now, while the process (and probably its parent) still exist.
        var imagePath = NativeMethods.TryGetProcessImagePath(data.ProcessID)
                        ?? PathResolver.FromNtPath(data.KernelImageFileName)
                        ?? PathResolver.ExtractExecutablePath(data.CommandLine)
                        ?? PathResolver.FirstTokenPath(data.CommandLine); // process already gone and file deleted
        var name = Path.GetFileNameWithoutExtension(imagePath ?? data.ImageFileName);
        var parentPath = NativeMethods.TryGetProcessImagePath(data.ParentID);

        var commandLine = string.IsNullOrWhiteSpace(data.CommandLine) ? null : data.CommandLine.Trim();
        history.Add(new ProcessStartRecord(data.ProcessID, data.ParentID, imagePath, commandLine, data.TimeStamp.ToUniversalTime()));

        _queue.Writer.TryWrite(new ProcessStart(
            new ProcessSnapshot(data.ProcessID, name, imagePath),
            data.ParentID,
            parentPath,
            string.IsNullOrWhiteSpace(data.CommandLine) ? null : data.CommandLine.Trim()));
    }

    private async Task ConsumeAsync()
    {
        await foreach (var start in _queue.Reader.ReadAllAsync())
        {
            try
            {
                monitor.OnProcessStarted(start);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to handle process start for PID {Pid}", start.Process.Pid);
            }
        }
    }

    public void Dispose()
    {
        _session?.Dispose();
        _session = null;
        _queue.Writer.TryComplete();
    }
}
