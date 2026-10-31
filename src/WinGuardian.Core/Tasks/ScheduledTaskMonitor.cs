using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WinGuardian.Core.Configuration;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Core.Tasks;

/// <summary>
/// Investigates scheduled tasks: what each task runs (program or COM handler, resolved through the
/// registry), whether that code is signed, who can tamper with it, and what changed since the last
/// recorded version. Triggered by a debounced watcher on the Tasks folder, and by a periodic check that
/// also catches COM re-registrations and program-file changes that leave the task XML untouched.
/// </summary>
public sealed class ScheduledTaskMonitor : IDisposable
{
    private static readonly JsonSerializerOptions Json = new()
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly GuardianDatabase _db;
    private readonly GuardianOptions _options;
    private readonly EventRecorder _events;
    private readonly ITaskAttributor _attributor;
    private readonly ILogger<ScheduledTaskMonitor> _logger;
    private readonly TaskRiskScorer _scorer;
    private readonly string _root;
    private readonly Lock _gate = new();

    private readonly ConcurrentDictionary<string, DateTime> _debounce = new(StringComparer.OrdinalIgnoreCase);
    private readonly Channel<(string File, string Reason)> _queue =
        Channel.CreateBounded<(string, string)>(new BoundedChannelOptions(2000) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true });
    private readonly ConcurrentDictionary<string, byte> _queued = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (long Size, long Mtime, DateTime At, TargetInfo Info)> _targetCache = new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _needFullReconcile;
    private FileSystemWatcher? _watcher;
    private Timer? _timer;
    private Task? _worker;

    public ScheduledTaskMonitor(GuardianDatabase db, GuardianOptions options, EventRecorder events, ITaskAttributor attributor,
        ILogger<ScheduledTaskMonitor> logger)
    {
        _db = db;
        _options = options;
        _events = events;
        _attributor = attributor;
        _logger = logger;
        _scorer = new TaskRiskScorer(options);
        _root = GuardianPaths.Normalize(options.ScheduledTasksRoot);
    }

    public bool HasBaseline => _db.GetMeta(GuardianDatabase.MetaTasksBaseline) is not null;

    // ------------------------------------------------------------------ lifecycle

    /// <summary>Records every task as it is now, without raising events.</summary>
    public int CaptureBaseline()
    {
        lock (_gate)
        {
            var count = 0;
            foreach (var file in EnumerateTaskFiles())
            {
                Save(BuildState(file));
                count++;
            }
            _db.SetMeta(GuardianDatabase.MetaTasksBaseline, GuardianDatabase.Iso(DateTime.UtcNow));
            _logger.LogInformation("Scheduled task baseline captured: {Count} tasks", count);
            return count;
        }
    }

    public void Start()
    {
        if (_watcher is not null || !Directory.Exists(_root)) return;

        _watcher = new FileSystemWatcher(_root)
        {
            IncludeSubdirectories = true,
            InternalBufferSize = 64 * 1024,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite |
                           NotifyFilters.Size | NotifyFilters.Security | NotifyFilters.CreationTime,
        };
        _watcher.Created += (_, e) => Debounce(e.FullPath);
        _watcher.Changed += (_, e) => Debounce(e.FullPath);
        _watcher.Deleted += (_, e) => Debounce(e.FullPath);
        _watcher.Renamed += (_, e) =>
        {
            Debounce(e.OldFullPath);
            Debounce(e.FullPath);
        };
        _watcher.Error += (_, e) =>
        {
            _logger.LogWarning(e.GetException(), "Scheduled task watcher overflowed; a full check will run");
            _needFullReconcile = true;
        };
        _watcher.EnableRaisingEvents = true;

        _timer = new Timer(_ => FlushDebounced(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        _worker = Task.Run(WorkAsync);
        _logger.LogInformation("Watching scheduled tasks in {Root}", _root);
    }

    public void Stop()
    {
        _watcher?.Dispose();
        _watcher = null;
        _timer?.Dispose();
        _timer = null;
    }

    public void Dispose()
    {
        Stop();
        _queue.Writer.TryComplete();
    }

    /// <summary>Periodic check (cheap: file timestamps and registry reads; hashing only when something moved).</summary>
    public void Poll()
    {
        _needFullReconcile = false;
        foreach (var (file, reason) in Reconcile())
            Enqueue(file, reason);
    }

    // -------------------------------------------------------------- triggering

    private void Debounce(string path) =>
        _debounce[path] = DateTime.UtcNow.AddMilliseconds(_options.FileChangeDebounceMs);

    private void FlushDebounced()
    {
        var now = DateTime.UtcNow;
        foreach (var (path, due) in _debounce)
        {
            if (due <= now && _debounce.TryRemove(new KeyValuePair<string, DateTime>(path, due)))
                Enqueue(path, "Task file changed");
        }
        if (_needFullReconcile) Poll();
    }

    private void Enqueue(string file, string reason)
    {
        if (!_queued.TryAdd(file, 0)) return; // already waiting
        if (!_queue.Writer.TryWrite((file, reason)))
        {
            _queued.TryRemove(file, out _);
            _needFullReconcile = true; // queue full: catch up with a full check later
        }
    }

    private async Task WorkAsync()
    {
        await foreach (var (file, reason) in _queue.Reader.ReadAllAsync())
        {
            _queued.TryRemove(file, out _);
            try
            {
                Analyze(file, reason);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Scheduled task analysis failed for {File}", file);
            }
        }
    }

    /// <summary>Finds every task whose file, COM registration or program file changed since it was recorded.</summary>
    public List<(string File, string Reason)> Reconcile()
    {
        var work = new List<(string, string)>();
        var states = LoadAllStates();
        var onDisk = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var loaded = LoadedUserSids();
        var comCache = new Dictionary<string, ComResolution>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in EnumerateTaskFiles())
        {
            var taskPath = TaskPathOf(file);
            onDisk.Add(taskPath);
            if (!states.TryGetValue(taskPath, out var state))
            {
                work.Add((file, "New task file"));
                continue;
            }
            if (TargetInspector.LooksChanged(state.File))
            {
                work.Add((file, "Task file changed"));
                continue;
            }

            foreach (var action in state.Actions)
            {
                if (action.Com is { } com && state.Definition is { } def)
                {
                    var sids = RelevantSids(def, loaded);
                    var key = $"{com.ClassId}|{string.Join(",", sids)}";
                    if (!comCache.TryGetValue(key, out var now)) comCache[key] = now = ComResolver.Resolve(com.ClassId, sids);
                    if (TaskComparer.ComChanged(com, now, loaded))
                    {
                        work.Add((file, "COM registration changed"));
                        break;
                    }
                }
                if (action.Target is { } target && TargetInspector.LooksChanged(target.File))
                {
                    work.Add((file, "Program file changed"));
                    break;
                }
            }
        }

        foreach (var taskPath in states.Keys.Where(p => !onDisk.Contains(p)))
            work.Add((FileOf(taskPath), "Task file deleted"));
        return work;
    }

    // ---------------------------------------------------------------- analysis

    /// <summary>Analyses one task file (or every task under a folder) and records an event if anything meaningful changed.</summary>
    public List<GuardianEvent> Analyze(string file, string reason)
    {
        lock (_gate)
        {
            var results = new List<GuardianEvent>();
            if (Directory.Exists(file))
            {
                foreach (var child in Directory.EnumerateFiles(file, "*", SearchOption.AllDirectories))
                    AddIfNotNull(results, AnalyzeFile(child, reason));
                return results;
            }
            AddIfNotNull(results, AnalyzeFile(file, reason));
            return results;
        }
    }

    private GuardianEvent? AnalyzeFile(string file, string reason)
    {
        var taskPath = TaskPathOf(file);
        var previous = LoadState(taskPath);

        if (!File.Exists(file))
        {
            if (previous is null)
            {
                // A deleted folder: every task recorded beneath it is gone.
                GuardianEvent? last = null;
                foreach (var child in _db.GetTaskStatesJson().Keys.Where(k => k.StartsWith(taskPath + "\\", StringComparison.OrdinalIgnoreCase)))
                    last = AnalyzeFile(FileOf(child), reason) ?? last;
                return last;
            }
            if (FindRenamedCopy(previous) is { } renamedFile)
                return Record("Renamed", reason, previous, BuildState(renamedFile), oldPath: taskPath);
            return Record("Removed", reason, previous, null);
        }

        var current = BuildState(file);
        if (previous is null)
        {
            // The other half of a rename may be processed first: a recorded task whose file vanished, same content.
            if (FindRenamedOriginal(current) is { } original)
                return Record("Renamed", reason, original, current, oldPath: original.Path);
            return Record("Added", reason, null, current);
        }

        var loaded = LoadedUserSids();
        MergeUnloadedOverrides(previous, current, loaded);
        var comparison = TaskComparer.Compare(previous, current, loaded);
        var meaningful = comparison.TaskFileContentChanged == true || comparison.ComRegistrationChanged == true ||
                         comparison.TargetContentChanged == true;
        var timingOnly = comparison.ScheduleTimingOnly == true && comparison.ComRegistrationChanged != true &&
                         comparison.TargetContentChanged != true;

        if (!meaningful || timingOnly)
        {
            // Nothing security-relevant (e.g. Windows moving a repeating task's next start time): keep the record current, no alert.
            Save(current);
            if (timingOnly) _logger.LogDebug("Task {Task}: schedule timing updated", taskPath);
            return null;
        }
        return Record("Modified", reason, previous, current, comparison: comparison);
    }

    private GuardianEvent? Record(string change, string reason, TaskState? previous, TaskState? current,
        TaskComparison? comparison = null, string? oldPath = null)
    {
        var loaded = LoadedUserSids();
        comparison ??= TaskComparer.Compare(previous, current, loaded);
        var scoredChange = change == "Renamed" ? "Modified" : change;
        var assessment = _scorer.Assess(scoredChange, previous, current, comparison);
        var state = current ?? previous!;
        var taskPath = state.Path;

        var fileChange = reason.StartsWith("Task file", StringComparison.Ordinal) || reason == "New task file";
        var attribution = fileChange
            ? _attributor.Attribute(oldPath ?? taskPath, scoredChange, DateTime.UtcNow)
            : new ProcessAttribution
            {
                Note = "Unknown: COM registry and program-file changes are not attributed to a process (no registry/file auditing).",
            };

        var analysis = new TaskAnalysis
        {
            Task = taskPath,
            Change = change == "Renamed" ? $"Renamed (from {oldPath})" : change,
            Trigger = reason,
            TaskFile = FileOf(taskPath),
            TaskSha256 = current?.File.Sha256 ?? previous?.File.Sha256,
            Configuration = state.Definition,
            ParseError = state.ParseError,
            Actions = state.Actions,
            Comparison = comparison,
            ModifyingProcess = attribution,
            Assessment = assessment,
        };

        var primary = state.Actions.Select(a => a.Target).FirstOrDefault(t => t is not null);
        var verb = change switch
        {
            "Added" => "created",
            "Removed" => "deleted",
            "Renamed" => "renamed",
            _ when comparison.ComRegistrationChanged == true && comparison.TaskFileContentChanged != true => "COM target changed",
            _ when comparison.TargetContentChanged == true && comparison.TaskFileContentChanged != true => "program file changed",
            _ => "modified",
        };

        var e = new GuardianEvent
        {
            Severity = assessment.Severity,
            Category = EventCategory.ScheduledTask,
            Change = change switch { "Added" => ChangeKind.Added, "Removed" => ChangeKind.Removed, _ => ChangeKind.Modified },
            Subject = change == "Renamed" ? $"Scheduled task renamed: {oldPath} -> {taskPath}" : $"Scheduled task {verb}: {taskPath}",
            Details = $"{assessment.Verdict}. {assessment.Explanation} {assessment.Basis}",
            FilePath = primary?.File.Path,
            Sha256 = primary?.File.Sha256,
            Signature = primary?.Signature,
            Signer = primary?.Signer,
            TrustKey = $"Scheduled Task|{taskPath}",
            Analysis = JsonSerializer.Serialize(analysis, Json),
        };

        if (oldPath is not null) _db.DeleteTaskState(oldPath);
        if (current is not null) Save(current);
        else _db.DeleteTaskState(taskPath);

        return _events.Record(e) ? e : null;
    }

    // ------------------------------------------------------------- task state

    private TaskState BuildState(string file)
    {
        var taskPath = TaskPathOf(file);
        var (fileState, bytes) = ReadTaskFile(file);
        var state = new TaskState { Path = taskPath, File = fileState, AnalyzedUtc = DateTime.UtcNow };

        if (bytes is null)
        {
            state.ParseError = fileState.Exists ? "the task file could not be read" : null;
            return state;
        }
        try
        {
            state.Definition = TaskDefinitionParser.Parse(bytes, taskPath);
        }
        catch (TaskParseException ex)
        {
            state.ParseError = ex.Message;
            return state;
        }

        var sids = RelevantSids(state.Definition, LoadedUserSids());
        foreach (var action in state.Definition.Actions)
            state.Actions.Add(ResolveAction(action, sids));
        return state;
    }

    private ActionState ResolveAction(TaskAction action, List<string> sids)
    {
        var result = new ActionState { Action = action };
        switch (action.Type)
        {
            case "Exec":
                result.ResolvedPath = ResolveExec(action.Command, action.Arguments);
                break;
            case "ComHandler" when action.ClassId is not null:
                result.Com = ComResolver.Resolve(action.ClassId, sids);
                // A per-user registration shadows the machine one for that user, so that is what would run.
                var server = result.Com.UserOverrides.Select(o => o.Server).FirstOrDefault(s => s?.ServerPath is not null)
                             ?? result.Com.Server;
                var code = server?.ManagedAssembly is { } managed && Path.IsPathRooted(managed) ? managed : server?.ServerPath;
                result.ResolvedPath = code is not null && Path.IsPathRooted(code) ? code : null;
                break;
        }
        if (result.ResolvedPath is not null) result.Target = InspectCached(result.ResolvedPath);
        return result;
    }

    private static string? ResolveExec(string? command, string? arguments)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        var expanded = Environment.ExpandEnvironmentVariables(command.Trim().Trim('"'));
        // Handles rundll32/regsvr32 (resolves to the DLL), bare names in System32, and paths with spaces.
        return PathResolver.ExtractExecutablePath($"\"{expanded}\" {arguments}") ??
               (Path.IsPathRooted(expanded) ? expanded : null);
    }

    private TargetInfo InspectCached(string path)
    {
        var info = new FileInfo(path);
        var size = info.Exists ? info.Length : -1;
        var mtime = info.Exists ? info.LastWriteTimeUtc.Ticks : 0;
        lock (_targetCache)
        {
            if (_targetCache.TryGetValue(path, out var cached) && cached.Size == size && cached.Mtime == mtime &&
                DateTime.UtcNow - cached.At < TimeSpan.FromMinutes(5))
                return cached.Info;
        }
        var inspected = TargetInspector.Inspect(path);
        lock (_targetCache)
        {
            if (_targetCache.Count > 5000) _targetCache.Clear();
            _targetCache[path] = (size, mtime, DateTime.UtcNow, inspected);
        }
        return inspected;
    }

    /// <summary>Reads and hashes the task file in one go, so the hash and the parsed content always match.</summary>
    private static (FileState State, byte[]? Bytes) ReadTaskFile(string file)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                var before = new FileInfo(file);
                if (!before.Exists) return (new FileState { Path = file }, null);
                byte[] bytes;
                using (var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    bytes = new byte[stream.Length];
                    stream.ReadExactly(bytes);
                }
                var after = new FileInfo(file);
                var state = new FileState
                {
                    Path = file,
                    Exists = true,
                    Size = before.Length,
                    LastWriteTicksUtc = before.LastWriteTimeUtc.Ticks,
                    Sha256 = Convert.ToHexString(SHA256.HashData(bytes)),
                };
                if (after.Length == before.Length && after.LastWriteTimeUtc == before.LastWriteTimeUtc) return (state, bytes);
                if (attempt == 1)
                {
                    state.Inconsistent = true;
                    return (state, bytes);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (attempt == 1) return (new FileState { Path = file, Exists = File.Exists(file) }, null);
            }
            Thread.Sleep(200);
        }
        return (new FileState { Path = file, Exists = File.Exists(file) }, null);
    }

    /// <summary>A task file that disappeared while an unrecorded file with identical content appeared.</summary>
    private string? FindRenamedCopy(TaskState previous)
    {
        if (previous.File.Sha256 is null) return null;
        var known = _db.GetTaskStatesJson();
        foreach (var file in EnumerateTaskFiles())
        {
            if (known.ContainsKey(TaskPathOf(file))) continue;
            if (ReadTaskFile(file).State.Sha256 == previous.File.Sha256) return file;
        }
        return null;
    }

    private TaskState? FindRenamedOriginal(TaskState current)
    {
        if (current.File.Sha256 is null) return null;
        return LoadAllStates().Values.FirstOrDefault(s =>
            s.File.Sha256 == current.File.Sha256 && !File.Exists(FileOf(s.Path)) &&
            !s.Path.Equals(current.Path, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Keeps per-user COM overrides of users who are logged off, so they don't look new at next logon.</summary>
    private static void MergeUnloadedOverrides(TaskState previous, TaskState current, IReadOnlySet<string> loaded)
    {
        for (var i = 0; i < Math.Min(previous.Actions.Count, current.Actions.Count); i++)
        {
            var p = previous.Actions[i].Com;
            var c = current.Actions[i].Com;
            if (p is null || c is null || p.ClassId != c.ClassId) continue;
            foreach (var o in p.UserOverrides.Where(o => !loaded.Contains(o.Sid) && c.UserOverrides.All(x => x.Sid != o.Sid)))
                c.UserOverrides.Add(o);
        }
    }

    private static List<string> RelevantSids(TaskDefinition? def, IReadOnlySet<string> loaded)
    {
        if (def is null) return [];
        if (def.RunsAsSystem) return ["S-1-5-18"];
        if (def.UserId is { } user && user.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
            return loaded.Contains(user) ? [user] : [];
        // Group/interactive principals run as whoever is logged on.
        return loaded.Where(s => s.StartsWith("S-1-5-21-", StringComparison.Ordinal)).ToList();
    }

    private static HashSet<string> LoadedUserSids()
    {
        var sids = Registry.Users.GetSubKeyNames()
            .Where(n => n.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase) && !n.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        sids.Add("S-1-5-18");
        return sids;
    }

    private void Save(TaskState state) => _db.UpsertTaskState(state.Path, JsonSerializer.Serialize(state, Json));

    private TaskState? LoadState(string taskPath) =>
        _db.GetTaskStateJson(taskPath) is { } json ? JsonSerializer.Deserialize<TaskState>(json, Json) : null;

    private Dictionary<string, TaskState> LoadAllStates() =>
        _db.GetTaskStatesJson().ToDictionary(kv => kv.Key, kv => JsonSerializer.Deserialize<TaskState>(kv.Value, Json)!,
            StringComparer.OrdinalIgnoreCase);

    private IEnumerable<string> EnumerateTaskFiles() =>
        Directory.Exists(_root)
            ? Directory.EnumerateFiles(_root, "*", new System.IO.EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = 0 })
            : [];

    public string TaskPathOf(string file) => "\\" + Path.GetRelativePath(_root, file);

    public string FileOf(string taskPath) => Path.Combine(_root, taskPath.TrimStart('\\'));

    private static void AddIfNotNull(List<GuardianEvent> list, GuardianEvent? e)
    {
        if (e is not null) list.Add(e);
    }
}
