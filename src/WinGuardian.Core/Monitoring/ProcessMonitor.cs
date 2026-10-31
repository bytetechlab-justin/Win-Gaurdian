using System.Diagnostics;
using Microsoft.Extensions.Logging;
using WinGuardian.Core.Configuration;
using WinGuardian.Core.Data;

namespace WinGuardian.Core.Monitoring;

/// <summary>
/// Tracks which executables have been seen running. The first snapshot becomes the baseline;
/// afterwards any executable not seen before raises an event (once). Process starts arrive from ETW
/// (<see cref="ProcessStartWatcher"/>, with parent and command line) and from periodic polling as a fallback.
/// </summary>
public sealed class ProcessMonitor(
    GuardianDatabase db,
    GuardianOptions options,
    EventRecorder events,
    ExecutionBlocker blocker,
    ILogger<ProcessMonitor> logger)
{
    private static readonly TimeSpan RepeatSuppression = TimeSpan.FromMinutes(10);

    private readonly long _maxHashBytes = options.MaxHashFileSizeMB * 1024L * 1024L;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, DateTime> _recentCommandLineAlerts = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string>? _known;

    public static List<ProcessSnapshot> Capture()
    {
        var result = new List<ProcessSnapshot>();
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                result.Add(new ProcessSnapshot(p.Id, p.ProcessName, NativeMethods.TryGetProcessImagePath(p.Id)));
            }
        }
        return result;
    }

    public int CaptureBaseline()
    {
        var snapshot = Distinct(Capture());
        lock (_gate)
        {
            using var c = db.Open();
            using var tx = c.BeginTransaction();
            GuardianDatabase.Execute(c, tx, "DELETE FROM processes");
            foreach (var p in snapshot)
                db.InsertProcess(c, tx, p, HashOf(p.ImagePath), inBaseline: true);
            tx.Commit();
            _known = new HashSet<string>(snapshot.Select(p => p.Key), StringComparer.OrdinalIgnoreCase);
        }
        logger.LogInformation("Process baseline captured: {Count} distinct executables", snapshot.Count);
        return snapshot.Count;
    }

    /// <summary>Fallback discovery: catches anything ETW missed (or everything, if ETW is unavailable).</summary>
    public void Poll()
    {
        foreach (var p in Distinct(Capture()))
        {
            bool known;
            lock (_gate) known = Known().Contains(p.Key);
            if (!known) Handle(new ProcessStart(p, 0, null, null));
        }
    }

    /// <summary>Called for every process start reported by ETW.</summary>
    public void OnProcessStarted(ProcessStart start) => Handle(start);

    /// <summary>Forgets the in-memory cache, e.g. after the baseline was cleared.</summary>
    public void Reset()
    {
        lock (_gate) _known = null;
    }

    private void Handle(ProcessStart start)
    {
        var p = start.Process;
        if (blocker.Enforce(start, sha256: null)) return; // blocked by path: terminated, nothing else to report
        CheckCommandLine(start);

        lock (_gate)
        {
            if (!Known().Add(p.Key)) return;
        }

        var hash = HashOf(p.ImagePath);
        if (blocker.Enforce(start, hash)) return; // a renamed copy of a blocked file
        using var c = db.Open();
        db.InsertProcess(c, null, p, hash, inBaseline: false);
        var e = new GuardianEvent
        {
            Category = EventCategory.Process,
            Change = ChangeKind.Added,
            Subject = p.ImagePath ?? p.Name,
            Details = $"New executable started: {p.Name} (PID {p.Pid}); {Describe(start)}; SHA256 {hash ?? "(not hashed)"}",
            FilePath = p.ImagePath,
            Sha256 = hash,
        };
        var signature = SeverityRules.Sign(e);
        e.Severity = SeverityRules.ForNewProcess(p.ImagePath, signature);
        if (signature is not null) e.Details += $"; {e.Signature}";
        events.Record(c, null, e);
    }

    private void CheckCommandLine(ProcessStart start)
    {
        if (CommandLineRules.Evaluate(start.Process.ImagePath, start.CommandLine) is not { } match) return;

        var dedupeKey = $"{start.Process.Key}|{start.CommandLine}";
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            if (_recentCommandLineAlerts.TryGetValue(dedupeKey, out var last) && now - last < RepeatSuppression) return;
            _recentCommandLineAlerts[dedupeKey] = now;
            if (_recentCommandLineAlerts.Count > 1000)
            {
                foreach (var old in _recentCommandLineAlerts.Where(kv => now - kv.Value > RepeatSuppression).Select(kv => kv.Key).ToList())
                    _recentCommandLineAlerts.Remove(old);
            }
        }

        events.Record(new GuardianEvent
        {
            Severity = match.Severity,
            Category = EventCategory.Process,
            Change = ChangeKind.Detected,
            Subject = $"{match.Rule}: {start.Process.ImagePath ?? start.Process.Name}",
            Details = $"PID {start.Process.Pid}; {Describe(start)}",
            FilePath = start.Process.ImagePath,
            TrustKey = $"{match.Rule}|{start.ParentPath ?? "(unknown parent)"}",
        });
    }

    private static string Describe(ProcessStart s) =>
        s.ParentPid == 0 && s.CommandLine is null
            ? "parent and command line not captured (found by polling)"
            : $"parent {s.ParentPath ?? "(exited)"} (PID {s.ParentPid}); command line: {s.CommandLine ?? "(none)"}";

    private HashSet<string> Known() => _known ??= db.GetProcessKeys();

    private string? HashOf(string? path) =>
        path is not null && File.Exists(path) ? FileHasher.TryHash(path, _maxHashBytes) : null;

    private static List<ProcessSnapshot> Distinct(IEnumerable<ProcessSnapshot> snapshot) =>
        snapshot.DistinctBy(p => p.Key, StringComparer.OrdinalIgnoreCase).ToList();
}
