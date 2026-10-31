using System.Text.Json;
using Microsoft.Win32;
using WinGuardian.Core;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Service;

/// <summary>
/// Detects attempts to switch WinGuardian off or tamper with it:
/// - a heartbeat in the database reveals, at the next start, that the service was stopped or killed
///   while Windows kept running (as opposed to a normal shutdown/reboot);
/// - a hash manifest of the program folder reveals modified, added or deleted program files, both at
///   startup and in real time.
/// install.ps1 sets a short-lived "maintenance" marker in HKLM so planned upgrades are reported as Info.
/// </summary>
public sealed class SelfProtection(GuardianDatabase db, EventRecorder events, ILogger<SelfProtection> logger) : IDisposable
{
    public const string MarkerKey = @"SOFTWARE\WinGuardian";
    public const string MarkerValue = "MaintenanceUntilUtc";

    private readonly string _installRoot = Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd('\\'))!;
    private FileSystemWatcher? _watcher;
    private Timer? _recheck;

    public void CheckStartup()
    {
        var maintenance = ConsumeMaintenanceMarker();
        CheckPreviousShutdown(maintenance);
        Heartbeat();
        CheckInstallIntegrity(maintenance);
        StartWatchingInstallFolder();
    }

    public void Heartbeat() => db.SetMetaDate(GuardianDatabase.MetaHeartbeat, DateTime.UtcNow);

    public void RecordCleanStop() => db.SetMetaDate(GuardianDatabase.MetaCleanStop, DateTime.UtcNow);

    private void CheckPreviousShutdown(bool maintenance)
    {
        var bootUtc = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
        var lastHeartbeat = db.GetMetaDate(GuardianDatabase.MetaHeartbeat);
        var cleanStop = db.GetMetaDate(GuardianDatabase.MetaCleanStop);
        db.SetMeta(GuardianDatabase.MetaCleanStop, null);

        // If the service was alive after this boot, it went down while Windows was running.
        if (lastHeartbeat is null || lastHeartbeat < bootUtc.AddMinutes(1)) return;

        var window = $"Protection was off from about {lastHeartbeat.Value.ToLocalTime():g} until {DateTime.Now:g}.";
        if (maintenance)
        {
            events.Info("WinGaurdian restarted for maintenance", window);
            return;
        }

        var stoppedNormally = cleanStop is not null && cleanStop >= lastHeartbeat;
        events.Record(new GuardianEvent
        {
            Severity = Severity.High,
            Category = EventCategory.Tamper,
            Change = ChangeKind.Detected,
            Subject = stoppedNormally
                ? "WinGaurdian service was stopped while Windows was running"
                : "WinGaurdian service was terminated unexpectedly (crashed or killed)",
            Details = window + (stoppedNormally
                ? " Someone with administrator rights stopped the service."
                : " The process ended without shutting down; check for a crash in the Application event log."),
        });
    }

    // --------------------------------------------------------------- program files

    private void CheckInstallIntegrity(bool maintenance)
    {
        var current = BuildManifest();
        var stored = db.GetMeta(GuardianDatabase.MetaSelfManifest) is { } json
            ? JsonSerializer.Deserialize<Dictionary<string, string>>(json)
            : null;
        db.SetMeta(GuardianDatabase.MetaSelfManifest, JsonSerializer.Serialize(current));

        if (stored is null) return; // first run
        var diffs = Diff(stored, current);
        if (diffs.Count == 0) return;

        if (maintenance)
            events.Info("WinGaurdian program files updated", $"{diffs.Count} file(s) changed during maintenance.");
        else
            RecordTamper("WinGaurdian program files changed while the service was not running", diffs);
    }

    private void StartWatchingInstallFolder()
    {
        try
        {
            _recheck = new Timer(_ => RecheckInstallFolder(), null, Timeout.Infinite, Timeout.Infinite);
            _watcher = new FileSystemWatcher(_installRoot)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size,
            };
            FileSystemEventHandler onChange = (_, _) => _recheck.Change(TimeSpan.FromSeconds(3), Timeout.InfiniteTimeSpan);
            _watcher.Changed += onChange;
            _watcher.Created += onChange;
            _watcher.Deleted += onChange;
            _watcher.Renamed += (_, _) => _recheck.Change(TimeSpan.FromSeconds(3), Timeout.InfiniteTimeSpan);
            _watcher.EnableRaisingEvents = true;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not watch the install folder {Folder}", _installRoot);
        }
    }

    private void RecheckInstallFolder()
    {
        try
        {
            var current = BuildManifest();
            var stored = db.GetMeta(GuardianDatabase.MetaSelfManifest) is { } json
                ? JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? []
                : [];
            var diffs = Diff(stored, current);
            db.SetMeta(GuardianDatabase.MetaSelfManifest, JsonSerializer.Serialize(current));
            if (diffs.Count > 0)
                RecordTamper("WinGaurdian program files were modified while it was running", diffs);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Install folder integrity check failed");
        }
    }

    private void RecordTamper(string subject, List<string> diffs) => events.Record(new GuardianEvent
    {
        Severity = Severity.High,
        Category = EventCategory.Tamper,
        Change = ChangeKind.Modified,
        Subject = subject,
        Details = string.Join("; ", diffs.Take(25)) + (diffs.Count > 25 ? $"; and {diffs.Count - 25} more" : ""),
        FilePath = _installRoot,
    });

    private Dictionary<string, string> BuildManifest()
    {
        var manifest = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in Directory.EnumerateFiles(_installRoot, "*", SearchOption.AllDirectories))
            manifest[Path.GetRelativePath(_installRoot, file)] = FileHasher.TryHash(file, long.MaxValue) ?? "(unreadable)";
        return manifest;
    }

    private static List<string> Diff(Dictionary<string, string> before, Dictionary<string, string> after)
    {
        var diffs = new List<string>();
        foreach (var (path, hash) in after)
        {
            if (!before.TryGetValue(path, out var old)) diffs.Add($"added {path}");
            else if (old != hash) diffs.Add($"modified {path}");
        }
        diffs.AddRange(before.Keys.Where(p => !after.ContainsKey(p)).Select(p => $"deleted {p}"));
        return diffs;
    }

    private bool ConsumeMaintenanceMarker()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(MarkerKey, writable: true);
            if (key?.GetValue(MarkerValue) is not string until) return false;
            key.DeleteValue(MarkerValue, throwOnMissingValue: false);
            return DateTime.TryParse(until, null, System.Globalization.DateTimeStyles.RoundtripKind, out var utc) &&
                   DateTime.UtcNow <= utc.ToUniversalTime();
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Could not read maintenance marker");
            return false;
        }
    }

    public void Dispose()
    {
        _watcher?.Dispose();
        _recheck?.Dispose();
    }
}
