namespace WinGuardian.Core;

/// <summary>Snapshot of the service's state, sent to the tray app over the pipe.</summary>
public sealed class GuardianStatus
{
    public string ServiceVersion { get; set; } = "";
    public string Phase { get; set; } = "";
    public DateTime StartedUtc { get; set; }
    public DateTime? BaselineCreatedUtc { get; set; }
    public DateTime? LastFullScanUtc { get; set; }
    public bool ScanInProgress { get; set; }
    public long ScanFilesProcessed { get; set; }
    public long BaselineFileCount { get; set; }
    public long BaselineProcessCount { get; set; }
    public long BaselineServiceCount { get; set; }
    public long BaselinePersistenceCount { get; set; }
    public long UnacknowledgedCount { get; set; }
    public Severity? HighestUnacknowledgedSeverity { get; set; }
    public long LatestEventId { get; set; }
    public string? LastError { get; set; }
    public bool EtwProcessTracing { get; set; }
    public bool MalwareBazaarConfigured { get; set; }
    public bool VirusTotalConfigured { get; set; }
    public int QuarantineCount { get; set; }
    public long BaselineTaskCount { get; set; }
    public bool TaskAuditingActive { get; set; }
    public int BlockedCount { get; set; }

    /// <summary>Turned off by an administrator: monitoring only, nothing is scanned, quarantined or blocked automatically.</summary>
    public bool ProtectionOff { get; set; }
    public DateTime? ProtectionOffSinceUtc { get; set; }
}
