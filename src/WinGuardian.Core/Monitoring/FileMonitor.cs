using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using WinGuardian.Core.Configuration;
using WinGuardian.Core.Data;

namespace WinGuardian.Core.Monitoring;

/// <summary>
/// Builds the file baseline, re-scans it for differences, and checks individual paths reported by the watcher.
/// Each full scan stamps every file it sees with a new "generation"; rows left on an older generation
/// at the end were not found on disk and are reported as removed.
/// </summary>
public sealed class FileMonitor(
    GuardianDatabase db,
    GuardianOptions options,
    PathFilter filter,
    EventRecorder events,
    GuardianState state,
    ILogger<FileMonitor> logger)
{
    private const int CommitSize = 2000;
    private const int HashBatchSize = 256;
    private readonly long _maxHashBytes = options.MaxHashFileSizeMB * 1024L * 1024L;
    private readonly Lock _gate = new();
    private long _activeScanGeneration; // non-zero while a full scan is running

    /// <summary>Walks every scan root. When <paramref name="isBaseline"/> is true, nothing is reported as a change.</summary>
    /// <returns>The number of changes detected.</returns>
    public int RunFullScan(bool isBaseline, CancellationToken ct)
    {
        var roots = options.ScanRoots.Select(GuardianPaths.Normalize).ToList();
        var generation = db.GetFileGeneration() + 1;
        var changes = 0;
        Interlocked.Exchange(ref _activeScanGeneration, generation);
        state.ResetScanProgress();
        logger.LogInformation("{Kind} file scan started (generation {Generation}) over {Roots}",
            isBaseline ? "Baseline" : "Full", generation, string.Join(", ", roots));

        using var c = db.Open();
        using var store = new FileStore(c);
        var tx = c.BeginTransaction();
        store.Transaction = tx;
        var pendingOps = 0;
        var batch = new List<FileInfo>(HashBatchSize);
        var parallel = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, options.HashThreads), CancellationToken = ct };

        try
        {
            foreach (var file in FileEnumerator.Enumerate(roots, filter).Append<FileInfo?>(null)) // trailing null flushes the last batch
            {
                ct.ThrowIfCancellationRequested();
                if (file is not null) batch.Add(file);
                if (batch.Count < HashBatchSize && file is not null) continue;

                // Database work stays on this thread; only the hashing (dominated by per-file open latency,
                // including antivirus on-access scanning) runs in parallel.
                var candidates = batch.Select(f => Inspect(store, f)).OfType<Candidate>().ToList();
                Parallel.ForEach(candidates.Where(x => x.NeedsHash), parallel,
                    x => x.Hash = FileHasher.TryHash(x.File.FullName, _maxHashBytes));
                foreach (var candidate in candidates)
                {
                    if (Apply(c, tx, store, candidate, generation, report: !isBaseline))
                        changes++;
                    state.IncrementScanProgress();
                }
                pendingOps += batch.Count;
                batch.Clear();

                if (pendingOps >= CommitSize)
                {
                    tx.Commit();
                    tx.Dispose();
                    tx = c.BeginTransaction();
                    store.Transaction = tx;
                    pendingOps = 0;
                }
            }

            // Anything not stamped with this generation is gone from disk.
            using (var cmd = GuardianDatabase.Command(c, tx, "SELECT path FROM files WHERE gen < $g", ("$g", generation)))
            using (var r = cmd.ExecuteReader())
            {
                while (r.Read())
                {
                    var path = r.GetString(0);
                    // Only treat it as removed if it lies under a current scan root (config may have changed).
                    if (!isBaseline && roots.Any(root => path.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase)))
                    {
                        events.Record(c, tx, FileEvent(path, ChangeKind.Removed, null));
                        changes++;
                    }
                }
            }
            GuardianDatabase.Execute(c, tx, "DELETE FROM files WHERE gen < $g", ("$g", generation));
            db.SetMeta(GuardianDatabase.MetaFileGeneration, generation.ToString(), c, tx);
            db.SetMeta(GuardianDatabase.MetaLastFullScan, DateTime.UtcNow.ToString("O"), c, tx);
            tx.Commit();
        }
        finally
        {
            tx.Dispose();
            Interlocked.Exchange(ref _activeScanGeneration, 0);
        }

        logger.LogInformation("File scan finished: {Count} files, {Changes} changes", state.ScanFilesProcessed, changes);
        return changes;
    }

    /// <summary>
    /// Re-checks a single path reported by the file system watcher. For created/renamed/deleted
    /// directories, <paramref name="includeChildren"/> also covers the files beneath them, since
    /// Windows only reports the directory itself in that case.
    /// </summary>
    public void CheckPath(string path, bool includeChildren)
    {
        if (filter.IsExcluded(path)) return;

        lock (_gate)
        {
            // Files seen while a full scan runs must carry its generation, or the scan would report them removed.
            var active = Interlocked.Read(ref _activeScanGeneration);
            var generation = active != 0 ? active : db.GetFileGeneration();
            using var c = db.Open();
            using var tx = c.BeginTransaction();
            using var store = new FileStore(c) { Transaction = tx };

            if (Directory.Exists(path))
            {
                if (includeChildren)
                {
                    foreach (var file in FileEnumerator.Enumerate([path], filter))
                        CompareAndStore(c, tx, store, file, generation, report: true);
                }
            }
            else if (File.Exists(path))
            {
                CompareAndStore(c, tx, store, new FileInfo(path), generation, report: true);
            }
            else
            {
                if (store.Get(path) is not null)
                {
                    events.Record(c, tx, FileEvent(path, ChangeKind.Removed, null));
                    store.Delete(path);
                }
                if (includeChildren)
                    RemoveChildren(c, tx, store, path);
            }
            tx.Commit();
        }
    }

    private void RemoveChildren(SqliteConnection c, SqliteTransaction tx, FileStore store, string directory)
    {
        // Range query on the primary key: every path starting with "dir\" sorts between "dir\" and "dir]".
        var removed = new List<string>();
        using (var cmd = GuardianDatabase.Command(c, tx, "SELECT path FROM files WHERE path >= $lo AND path < $hi",
                   ("$lo", directory + "\\"), ("$hi", directory + "]")))
        using (var r = cmd.ExecuteReader())
        {
            while (r.Read()) removed.Add(r.GetString(0));
        }
        foreach (var path in removed)
        {
            events.Record(c, tx, FileEvent(path, ChangeKind.Removed, null));
            store.Delete(path);
        }
    }

    /// <summary>A file on disk paired with its baseline row; hashed only if size or timestamp changed.</summary>
    private sealed class Candidate(FileInfo file, long size, long mtime, FileRecord? existing)
    {
        public FileInfo File { get; } = file;
        public long Size { get; } = size;
        public long Mtime { get; } = mtime;
        public FileRecord? Existing { get; } = existing;
        public bool NeedsHash => Existing is null || Existing.Size != Size || Existing.LastWriteTicksUtc != Mtime;
        public string? Hash { get; set; }
    }

    private static Candidate? Inspect(FileStore store, FileInfo file)
    {
        try
        {
            return new Candidate(file, file.Length, file.LastWriteTimeUtc.Ticks, store.Get(file.FullName));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null; // vanished or unreadable between enumeration and now
        }
    }

    /// <returns>True if a change was reported.</returns>
    private bool CompareAndStore(SqliteConnection c, SqliteTransaction tx, FileStore store, FileInfo file,
        long generation, bool report)
    {
        if (Inspect(store, file) is not { } candidate) return false;
        if (candidate.NeedsHash) candidate.Hash = FileHasher.TryHash(file.FullName, _maxHashBytes);
        return Apply(c, tx, store, candidate, generation, report);
    }

    /// <returns>True if a change was reported.</returns>
    private bool Apply(SqliteConnection c, SqliteTransaction tx, FileStore store, Candidate x, long generation, bool report)
    {
        var path = x.File.FullName;
        if (!x.NeedsHash)
        {
            store.Touch(path, generation);
            return false;
        }

        store.Upsert(new FileRecord(path, x.Size, x.Mtime, x.Hash), generation);

        if (x.Existing is null)
        {
            if (!report) return false;
            events.Record(c, tx, FileEvent(path, ChangeKind.Added, $"Size {x.Size:N0} bytes; SHA256 {x.Hash ?? "(not hashed)"}", x.Hash));
            return true;
        }

        // Timestamp-only changes with identical content are not interesting.
        if (!report || (x.Hash is not null && x.Hash == x.Existing.Sha256)) return false;

        events.Record(c, tx, FileEvent(path, ChangeKind.Modified,
            $"Size {x.Existing.Size:N0} -> {x.Size:N0} bytes; SHA256 {x.Existing.Sha256 ?? "(none)"} -> {x.Hash ?? "(not hashed)"}", x.Hash));
        return true;
    }

    private static GuardianEvent FileEvent(string path, ChangeKind change, string? details, string? sha256 = null)
    {
        var e = new GuardianEvent
        {
            Category = EventCategory.File,
            Change = change,
            Subject = path,
            Details = details,
            FilePath = path,
            Sha256 = sha256,
        };
        var signature = change == ChangeKind.Removed ? null : SeverityRules.Sign(e);
        e.Severity = SeverityRules.ForFile(path, change, signature);
        if (signature is not null) e.Details = $"{details}; {e.Signature}";
        return e;
    }
}
