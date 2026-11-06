using System.Collections.Concurrent;
using WinGuardian.Core;
using WinGuardian.Core.Configuration;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Service;

/// <summary>
/// Real-time file monitoring. Raw FileSystemWatcher notifications are debounced (files are often
/// written in several steps) and then handed to <see cref="FileMonitor.CheckPath"/>, which compares
/// against the baseline.
/// </summary>
public sealed class FileWatcherService(
    GuardianOptions options,
    PathFilter filter,
    FileMonitor fileMonitor,
    GuardianState state,
    ILogger<FileWatcherService> logger) : IDisposable
{
    private readonly ConcurrentDictionary<string, PendingChange> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = [];
    private Timer? _timer;
    private int _processing;

    private sealed record PendingChange(DateTime DueUtc, bool IncludeChildren);

    public void Start()
    {
        if (_watchers.Count > 0) return;

        foreach (var root in options.WatchRoots.Select(GuardianPaths.Normalize).Where(Directory.Exists))
        {
            var watcher = new FileSystemWatcher(root)
            {
                IncludeSubdirectories = true,
                InternalBufferSize = 64 * 1024,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite |
                               NotifyFilters.Size | NotifyFilters.CreationTime | NotifyFilters.Security,
            };
            watcher.Created += (_, e) => Enqueue(e.FullPath, includeChildren: true);
            watcher.Deleted += (_, e) => Enqueue(e.FullPath, includeChildren: true);
            watcher.Changed += (_, e) => Enqueue(e.FullPath, includeChildren: false);
            watcher.Renamed += (_, e) =>
            {
                Enqueue(e.OldFullPath, includeChildren: true);
                Enqueue(e.FullPath, includeChildren: true);
            };
            watcher.Error += OnError;
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
            logger.LogInformation("Watching {Root} for changes", root);
        }

        _timer = new Timer(_ => ProcessDue(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
    }

    public void Stop()
    {
        foreach (var w in _watchers) w.Dispose();
        _watchers.Clear();
        _timer?.Dispose();
        _timer = null;
        _pending.Clear();
    }

    private void Enqueue(string path, bool includeChildren)
    {
        if (filter.IsExcluded(path)) return;
        var due = DateTime.UtcNow.AddMilliseconds(options.FileChangeDebounceMs);
        _pending.AddOrUpdate(path,
            new PendingChange(due, includeChildren),
            (_, existing) => new PendingChange(due, includeChildren || existing.IncludeChildren));
    }

    private void ProcessDue()
    {
        if (Interlocked.Exchange(ref _processing, 1) == 1) return; // previous tick still running
        try
        {
            var now = DateTime.UtcNow;
            foreach (var (path, change) in _pending)
            {
                if (change.DueUtc > now || !_pending.TryRemove(new KeyValuePair<string, PendingChange>(path, change)))
                    continue;
                try
                {
                    fileMonitor.CheckPath(path, change.IncludeChildren);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to check {Path}", path);
                }
            }
        }
        finally
        {
            Volatile.Write(ref _processing, 0);
        }
    }

    private void OnError(object sender, ErrorEventArgs e)
    {
        // Usually an internal buffer overflow during heavy disk activity (e.g. Windows Update):
        // some notifications were lost, so fall back to a full scan to catch anything missed.
        // Not while turned off: a full scan is exactly the kind of disk load the user asked to avoid.
        if (state.ProtectionOff)
        {
            logger.LogWarning(e.GetException(), "File watcher overflowed or failed; WinGaurdian is turned off, so no full scan was scheduled");
            return;
        }
        logger.LogWarning(e.GetException(), "File watcher overflowed or failed; scheduling a full scan");
        state.Commands.Writer.TryWrite(GuardianCommand.FullScan);
    }

    public void Dispose() => Stop();
}
