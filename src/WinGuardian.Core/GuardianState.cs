using System.Threading.Channels;

namespace WinGuardian.Core;

public enum GuardianCommand
{
    FullScan,
    RebuildBaseline,
}

/// <summary>Live, in-memory state shared between the monitor worker and the IPC server.</summary>
public sealed class GuardianState
{
    private long _scanFilesProcessed;

    public DateTime StartedUtc { get; } = DateTime.UtcNow;
    public volatile string Phase = "Starting";
    public volatile bool ScanInProgress;
    public volatile string? LastError;
    public volatile bool EtwProcessTracing;

    public long ScanFilesProcessed => Interlocked.Read(ref _scanFilesProcessed);
    public void ResetScanProgress() => Interlocked.Exchange(ref _scanFilesProcessed, 0);
    public void IncrementScanProgress() => Interlocked.Increment(ref _scanFilesProcessed);

    /// <summary>Requests from the tray (via the pipe) or the file watcher for the worker to act on.</summary>
    public Channel<GuardianCommand> Commands { get; } = Channel.CreateUnbounded<GuardianCommand>();
}
