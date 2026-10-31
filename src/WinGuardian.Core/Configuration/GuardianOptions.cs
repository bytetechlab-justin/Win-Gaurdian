namespace WinGuardian.Core.Configuration;

/// <summary>Bound from the "Guardian" section of the service's appsettings.json.</summary>
public sealed class GuardianOptions
{
    /// <summary>Directory trees included in the baseline and periodic full scans.</summary>
    public List<string> ScanRoots { get; set; } = [];

    /// <summary>Directory trees watched in real time with FileSystemWatcher.</summary>
    public List<string> WatchRoots { get; set; } = [];

    /// <summary>Volatile locations (logs, temp, registry hives, caches) that would only produce noise.</summary>
    public List<string> ExcludedPaths { get; set; } = [];

    public List<string> ExcludedExtensions { get; set; } = [];

    /// <summary>Files larger than this are tracked by size/timestamp only.</summary>
    public int MaxHashFileSizeMB { get; set; } = 256;

    /// <summary>Files hashed concurrently during full scans (scans are latency-bound, not CPU-bound).</summary>
    public int HashThreads { get; set; } = 4;

    public int ProcessPollSeconds { get; set; } = 5;
    public int ServicePollSeconds { get; set; } = 30;
    public int PersistencePollSeconds { get; set; } = 30;
    public int FullScanIntervalHours { get; set; } = 24;
    public int FileChangeDebounceMs { get; set; } = 2000;

    /// <summary>
    /// Fills in defaults for any list left empty. Done after binding because the configuration
    /// binder appends to (rather than replaces) pre-populated lists.
    /// </summary>
    public void ApplyDefaults()
    {
        if (ScanRoots.Count == 0) ScanRoots.Add("%WINDIR%");
        if (WatchRoots.Count == 0) WatchRoots.Add("%WINDIR%");
        if (ExcludedExtensions.Count == 0)
            ExcludedExtensions.AddRange([".log", ".etl", ".tmp", ".evtx", ".pf", ".blf", ".regtrans-ms"]);
        if (ExcludedPaths.Count == 0)
        {
            ExcludedPaths.AddRange(
            [
                @"%WINDIR%\Temp",
                @"%WINDIR%\Logs",
                @"%WINDIR%\Prefetch",
                @"%WINDIR%\SoftwareDistribution",
                @"%WINDIR%\ServiceProfiles",
                @"%WINDIR%\ServiceState",
                @"%WINDIR%\System32\config",
                @"%WINDIR%\System32\LogFiles",
                @"%WINDIR%\System32\winevt",
                @"%WINDIR%\System32\sru",
                @"%WINDIR%\System32\wbem\Repository",
                @"%WINDIR%\System32\catroot2",
                @"%WINDIR%\System32\spool\PRINTERS",
                @"%WINDIR%\WinSxS\Temp",
                @"%WINDIR%\WinSxS\ManifestCache",
                @"%WINDIR%\CbsTemp",
                @"%WINDIR%\tracing",
                @"%WINDIR%\appcompat",
            ]);
        }
    }
}
