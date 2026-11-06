using System.Threading.Channels;

namespace WinGuardian.Core;

public enum GuardianCommand
{
    FullScan,
    RebuildBaseline,

    /// <summary>Protection was just turned off: stop the file scan that is running, if any.</summary>
    ProtectionTurnedOff,
}

/// <summary>Live, in-memory state shared between the monitor worker and the IPC server.</summary>
public sealed class GuardianState
{
    private long _scanFilesProcessed;
    private long _protectionOffSinceTicks;

    public DateTime StartedUtc { get; } = DateTime.UtcNow;
    public volatile string Phase = "Starting";
    public volatile bool ScanInProgress;
    public volatile string? LastError;
    public volatile bool EtwProcessTracing;

    /// <summary>
    /// "Turned off" by an administrator: changes are still monitored and recorded, but WinGaurdian does nothing
    /// that could disturb the PC: no automatic file scans or reputation lookups, no automatic quarantine,
    /// and blocked programs are not terminated. Persisted in the database, so it survives restarts.
    /// </summary>
    public bool ProtectionOff => Interlocked.Read(ref _protectionOffSinceTicks) != 0;

    public DateTime? ProtectionOffSinceUtc =>
        Interlocked.Read(ref _protectionOffSinceTicks) is var ticks and not 0 ? new DateTime(ticks, DateTimeKind.Utc) : null;

    /// <param name="sinceUtc">When it was turned off, or null to turn protection back on.</param>
    public void SetProtectionOff(DateTime? sinceUtc) =>
        Interlocked.Exchange(ref _protectionOffSinceTicks, sinceUtc?.ToUniversalTime().Ticks ?? 0);

    public long ScanFilesProcessed => Interlocked.Read(ref _scanFilesProcessed);
    public void ResetScanProgress() => Interlocked.Exchange(ref _scanFilesProcessed, 0);
    public void IncrementScanProgress() => Interlocked.Increment(ref _scanFilesProcessed);

    /// <summary>Requests from the tray (via the pipe) or the file watcher for the worker to act on.</summary>
    public Channel<GuardianCommand> Commands { get; } = Channel.CreateUnbounded<GuardianCommand>();
}
