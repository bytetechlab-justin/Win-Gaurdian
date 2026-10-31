using System.Net;
using System.Text;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Core.Analysis;

/// <summary>
/// Records what a program does while it runs: every file it creates, changes, deletes or reads, every registry
/// key and value it writes, the network connections and DNS lookups it makes, and the same for every process
/// it starts. Uses the kernel's own ETW providers (Kernel-File, Kernel-Registry, Kernel-Network,
/// Kernel-Process, DNS-Client), so nothing is injected into the program.
/// <para>
/// This only observes: the program runs normally and its changes are real. The tray starts the program
/// suspended, the service begins recording its PID, then the tray lets it run, so nothing is missed at start-up.
/// </para>
/// </summary>
public sealed class ProgramAnalyzer : IDisposable
{
    public const int MaxConcurrentRuns = 4;
    private const string SessionName = "WinGuardian-ProgramAnalysis";
    private const int MaxChanges = 20_000;      // unique change entries per list per run
    private const int MaxReads = 15_000;        // unique "opened" entries per list per run
    private const int MaxObjectNames = 250_000; // file/key object → name maps
    private static readonly TimeSpan ExitGrace = TimeSpan.FromSeconds(3);  // late-arriving events after the last exit
    private static readonly TimeSpan MaxDuration = TimeSpan.FromHours(4);
    private static readonly TimeSpan KeepFinished = TimeSpan.FromHours(4);
    private const int MaxKeptRuns = 20;

    private static readonly Guid KernelFile = new("EDD08927-9CC4-4E65-B970-C2560FB5C289");
    private static readonly Guid KernelRegistry = new("70EB4F03-C1DE-4F73-A051-33D13D5413BD");
    private static readonly Guid KernelNetwork = new("7DD42A49-5329-4832-8DFD-43D979153A88");
    private static readonly Guid KernelProcess = new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");
    private static readonly Guid DnsClient = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    private readonly GuardianDatabase _db;
    private readonly ProcessHistory _history;
    private readonly ILogger<ProgramAnalyzer> _logger;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, Run> _runs = new(StringComparer.Ordinal);
    private readonly Dictionary<int, Run> _pids = new(); // PIDs being recorded (including recently exited ones, for late events)
    private readonly Timer _maintenance;
    private TraceEventSession? _session;
    private int _maintaining;

    public ProgramAnalyzer(GuardianDatabase db, ProcessHistory history, ILogger<ProgramAnalyzer> logger)
    {
        _db = db;
        _history = history;
        _logger = logger;
        _maintenance = new Timer(_ => Maintain(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
    }

    // ------------------------------------------------------------------ public API

    /// <summary>
    /// Starts recording <paramref name="pid"/>. Only the process that created it may ask (it is started
    /// suspended by the tray), so one user cannot use this to spy on another user's programs.
    /// </summary>
    /// <exception cref="InvalidOperationException">With a message for the user.</exception>
    public string Start(int pid, int requesterPid, string? requesterSid)
    {
        if (TraceEventSession.IsElevated() != true)
            throw new InvalidOperationException("The WinGaurdian service is not running with administrator rights, so it cannot record programs.");
        var parent = AnalysisNative.GetParentPid(pid) ?? throw new InvalidOperationException($"Process {pid} is not running.");
        if (parent != requesterPid)
            throw new InvalidOperationException("Only the program that started a process can ask for it to be monitored.");
        var created = AnalysisNative.GetCreationTimeUtc(pid) ?? throw new InvalidOperationException($"Process {pid} is not running.");

        var image = NativeMethods.TryGetProcessImagePath(pid);
        var commandLine = AnalysisNative.GetCommandLine(pid);
        long startEventId;
        try { startEventId = _db.GetEventSummary().LatestId; }
        catch { startEventId = 0; }

        lock (_gate)
        {
            if (_pids.ContainsKey(pid)) throw new InvalidOperationException($"Process {pid} is already being monitored.");
            if (_runs.Values.Count(r => r.State == AnalysisState.Running) >= MaxConcurrentRuns)
                throw new InvalidOperationException($"{MaxConcurrentRuns} programs are already being monitored. Stop one first.");

            EnsureSession();

            var run = new Run(Guid.NewGuid().ToString("N"), requesterSid, DateTime.UtcNow, pid, startEventId);
            var root = new AnalysisProcess
            {
                Pid = pid, ParentPid = parent, ImagePath = image, CommandLine = commandLine, StartedUtc = created,
                Elevated = AnalysisNative.IsElevated(pid),
            };
            run.Processes[pid] = root;
            run.Created[pid] = created;
            run.Live.Add(pid);
            Score(root, isRoot: true, parentElevated: root.Elevated);
            _runs[run.Id] = run;
            _pids[pid] = run;
            _logger.LogInformation("Program analysis {Id} started for PID {Pid} ({Image})", run.Id, pid, image);
            return run.Id;
        }
    }

    /// <summary>The run's report, or null if it does not exist or belongs to someone else.</summary>
    public AnalysisReport? GetReport(string id, bool includeReads, string? requesterSid, bool requesterIsAdmin)
    {
        AnalysisReport report;
        long startEventId;
        DateTime? ended;
        lock (_gate)
        {
            if (!_runs.TryGetValue(id, out var run) || !run.MayAccess(requesterSid, requesterIsAdmin)) return null;
            report = run.ToReport(includeReads);
            startEventId = run.StartEventId;
            ended = run.EndedUtc;
        }

        try
        {
            var until = (ended ?? DateTime.UtcNow).AddSeconds(60);
            report.RelatedEvents = _db.GetEvents(startEventId, 300, unacknowledgedOnly: false)
                .Where(e => e.TimeUtc <= until && e.Severity >= Severity.Low)
                .ToList();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read related events for analysis {Id}", id);
        }
        return report;
    }

    /// <summary>Stops recording; with <paramref name="terminate"/>, also ends every recorded process still running.</summary>
    public string? Stop(string id, bool terminate, string? requesterSid, bool requesterIsAdmin)
    {
        List<(int Pid, DateTime Created)> targets;
        lock (_gate)
        {
            if (!_runs.TryGetValue(id, out var run) || !run.MayAccess(requesterSid, requesterIsAdmin)) return null;
            targets = run.Live.Where(run.Created.ContainsKey).Select(p => (p, run.Created[p])).ToList();
            if (!terminate) Finish(run, AnalysisState.Stopped);
        }

        if (!terminate) return "Monitoring stopped. The program keeps running, but nothing more is recorded.";

        var ended = targets.Count(t => AnalysisNative.Terminate(t.Pid, t.Created));
        lock (_gate)
        {
            if (_runs.TryGetValue(id, out var run) && run.State == AnalysisState.Running)
                run.StopAfterExitsUtc = DateTime.UtcNow; // keep recording until the exits arrive, then finish
        }
        return ended == 0 ? "No monitored process was still running." : $"Ended {ended} process(es).";
    }

    public void Dispose()
    {
        _maintenance.Dispose();
        lock (_gate)
        {
            _session?.Dispose();
            _session = null;
        }
    }

    // ------------------------------------------------------------- ETW session

    private void EnsureSession()
    {
        if (_session is not null) return;
        var session = new TraceEventSession(SessionName) { StopOnDispose = true, BufferSizeMB = 128 };
        try
        {
            session.EnableProvider(KernelProcess, TraceEventLevel.Informational, 0x10);          // process start/stop
            session.EnableProvider(KernelFile, TraceEventLevel.Verbose,
                0x80 | 0x200 | 0x400 | 0x800 | 0x1000);                                          // create, write, delete, rename, new file
            session.EnableProvider(KernelRegistry, TraceEventLevel.Verbose,
                0x100 | 0x200 | 0x1000 | 0x2000 | 0x4000);                                       // set/delete value, create/open/delete key
            session.EnableProvider(KernelNetwork, TraceEventLevel.Verbose, 0x10 | 0x20);           // IPv4 + IPv6
            session.EnableProvider(DnsClient, TraceEventLevel.Verbose, ulong.MaxValue);

            var parser = new RegisteredTraceEventParser(session.Source);
            parser.All += OnEvent;
            new Thread(() =>
            {
                try
                {
                    session.Source.Process(); // returns when the session is disposed
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Program analysis trace stopped unexpectedly");
                }
            })
            { IsBackground = true, Name = "WinGuardian program analysis" }.Start();
            _session = session;
            _logger.LogInformation("Program analysis tracing started");
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    private void StopSessionIfIdle()
    {
        if (_session is null || _runs.Values.Any(r => r.State == AnalysisState.Running)) return;
        _session.Dispose();
        _session = null;
        _logger.LogInformation("Program analysis tracing stopped (nothing left to monitor)");
    }

    // ---------------------------------------------------------------- dispatch

    private void OnEvent(TraceEvent e)
    {
        try
        {
            var provider = e.ProviderGuid;
            if (provider == KernelNetwork)
            {
                // Network events are logged in the System process; the program's PID is in the payload.
                var pid = Int(e, "PID");
                lock (_gate)
                {
                    if (_pids.TryGetValue(pid, out var run)) OnNetwork(run, pid, e);
                }
                return;
            }
            if (provider == KernelProcess)
            {
                if ((int)e.ID == 1) OnProcessStart(e);
                else if ((int)e.ID == 2) OnProcessStop(e);
                return;
            }

            lock (_gate)
            {
                if (_pids.Count == 0 || !_pids.TryGetValue(e.ProcessID, out var run)) return;
                run.EventCount++;
                if (provider == KernelFile) OnFile(run, e.ProcessID, e);
                else if (provider == KernelRegistry) OnRegistry(run, e.ProcessID, e);
                else if (provider == DnsClient && (int)e.ID == 3008) OnDns(run, e.ProcessID, e);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not decode {Provider} event {Id}", e.ProviderName, e.ID);
        }
    }

    // ---------------------------------------------------------------- processes

    private void OnProcessStart(TraceEvent e)
    {
        var parent = Int(e, "ParentProcessID");
        var pid = Int(e, "ProcessID");
        lock (_gate)
        {
            if (!_pids.TryGetValue(parent, out var run) || run.State != AnalysisState.Running) return;
            if (_pids.TryGetValue(pid, out var previous) && previous != run) return;
            run.EventCount++;
            var created = e.PayloadByName("CreateTime") is DateTime t ? t.ToUniversalTime() : e.TimeStamp.ToUniversalTime();
            var process = new AnalysisProcess
            {
                Pid = pid,
                ParentPid = parent,
                StartedUtc = created,
                Elevated = Int(e, "ProcessTokenIsElevated") != 0,
                // Usually still running (events arrive within about a second), so ask it directly. Programs that
                // have already exited are filled in later from the service's process-start history.
                ImagePath = NativeMethods.TryGetProcessImagePath(pid),
                CommandLine = AnalysisNative.GetCommandLine(pid),
            };
            run.Processes[pid] = process;
            run.Created[pid] = created;
            run.Live.Add(pid);
            run.AllExitedUtc = null;
            Score(process, isRoot: false, parentElevated: run.Processes.GetValueOrDefault(parent)?.Elevated ?? false);
            _pids[pid] = run;
        }
    }

    private void OnProcessStop(TraceEvent e)
    {
        var pid = Int(e, "ProcessID");
        lock (_gate)
        {
            if (!_pids.TryGetValue(pid, out var run) || !run.Processes.TryGetValue(pid, out var process) || process.ExitedUtc is not null) return;
            run.EventCount++;
            process.ExitedUtc = e.PayloadByName("ExitTime") is DateTime exit ? exit.ToUniversalTime() : e.TimeStamp.ToUniversalTime();
            process.ExitCode = Int(e, "ExitCode");
            if (process.ImagePath is null && Str(e, "ImageName") is { Length: > 0 } name) process.ImagePath = name;
            run.Live.Remove(pid);
            if (run.Live.Count == 0) run.AllExitedUtc = DateTime.UtcNow;
        }
    }

    private static void Score(AnalysisProcess p, bool isRoot, bool parentElevated, SignatureInfo? signature = null)
    {
        var verdict = BehaviorRules.ForProcess(p.ImagePath, p.CommandLine, isRoot, signature);
        p.Severity = verdict.Severity;
        p.Reason = verdict.Reason;
        if (p.Elevated && !isRoot && !parentElevated && p.Severity < Severity.Medium)
        {
            p.Severity = Severity.Medium;
            p.Reason = "Gained administrator rights (a UAC prompt was accepted, or privilege escalation)";
        }
    }

    // ---------------------------------------------------------------------- files

    private const int FileDirectoryFile = 0x1;
    private const int FileDeleteOnClose = 0x1000;

    private void OnFile(Run run, int pid, TraceEvent e)
    {
        switch ((int)e.ID)
        {
            case 12: // Create (open or create)
            {
                var name = Str(e, "FileName");
                var fileObject = U64(e, "FileObject");
                var options = Int(e, "CreateOptions");
                if (name is null) return;
                run.RememberFile(fileObject, name);
                if ((options & FileDeleteOnClose) != 0)
                    Record(run, pid, name, FileOperation.Deleted);
                else if ((options & FileDirectoryFile) == 0 && !name.EndsWith('\\'))
                    Record(run, pid, name, FileOperation.Opened);
                break;
            }
            case 30: // CreateNewFile
            {
                var name = Str(e, "FileName");
                if (name is null) return;
                run.RememberFile(U64(e, "FileObject"), name);
                Record(run, pid, name, (Int(e, "CreateOptions") & FileDirectoryFile) != 0 ? FileOperation.FolderCreated : FileOperation.Created);
                break;
            }
            case 16: // Write
            {
                if (run.FileObjects.TryGetValue(U64(e, "FileObject"), out var name))
                    Record(run, pid, name, FileOperation.Modified, bytes: Int(e, "IOSize"));
                break;
            }
            case 26: // DeletePath
                if (Str(e, "FilePath") is { } deleted) Record(run, pid, deleted, FileOperation.Deleted);
                break;
            case 27: // RenamePath: FilePath is the new name; the file object still has the old one
            {
                if (Str(e, "FilePath") is not { } target) return;
                run.FileObjects.TryGetValue(U64(e, "FileObject"), out var original);
                var from = original is null ? null : DisplayPath(original);
                Record(run, pid, target, FileOperation.Renamed, detail: from is null ? null : "renamed from " + from);
                break;
            }
        }
    }

    /// <summary>Drive-letter path for \Device\HarddiskVolumeN\..., UNC for network shares, otherwise null (pipes, devices).</summary>
    private static string? DisplayPath(string ntPath)
    {
        if (ntPath.StartsWith(@"\Device\Mup\", StringComparison.OrdinalIgnoreCase)) return @"\\" + ntPath[12..];
        if (!ntPath.StartsWith(@"\Device\HarddiskVolume", StringComparison.OrdinalIgnoreCase) &&
            !ntPath.StartsWith(@"\??\", StringComparison.Ordinal) && !(ntPath.Length > 2 && ntPath[1] == ':'))
            return null;
        return PathResolver.FromNtPath(ntPath);
    }

    private void Record(Run run, int pid, string ntPath, FileOperation operation, long bytes = 0, string? detail = null)
    {
        if (DisplayPath(ntPath) is not { } path) return;
        var now = DateTime.UtcNow;

        // A write to a file this run created is part of creating it, not a separate change.
        if (operation == FileOperation.Modified && run.Files.TryGetValue((path, FileOperation.Created, pid), out var created))
        {
            created.Bytes += bytes;
            created.LastUtc = now;
            return;
        }
        var key = (path, operation, pid);
        if (!run.Files.TryGetValue(key, out var entry))
        {
            var reads = operation == FileOperation.Opened;
            if (reads ? run.FileReads >= MaxReads : run.FileChanges >= MaxChanges)
            {
                run.Truncated = true;
                return;
            }
            if (reads) run.FileReads++; else run.FileChanges++;
            var processName = run.ProcessName(pid);
            var verdict = BehaviorRules.ForFile(path, operation, Path.GetFileNameWithoutExtension(processName));
            entry = new FileActivity
            {
                Path = path, Operation = operation, Pid = pid, ProcessName = processName, FirstUtc = now,
                Severity = verdict.Severity, Reason = verdict.Reason,
            };
            run.Files[key] = entry;
        }
        entry.Count++;
        entry.LastUtc = now;
        entry.Bytes += bytes;
        if (detail is not null) entry.Detail = detail;
    }

    // ------------------------------------------------------------------- registry

    private const int RegCreatedNewKey = 1;

    private void OnRegistry(Run run, int pid, TraceEvent e)
    {
        switch ((int)e.ID)
        {
            case 1: // CreateKey
            case 2: // OpenKey
            {
                var status = Int(e, "Status");
                var name = run.ResolveKey(U64(e, "BaseObject"), Str(e, "BaseName"), Str(e, "RelativeName"));
                if (status == 0 && U64(e, "KeyObject") is var keyObject and not 0)
                    run.RememberKey(keyObject, name);
                if ((int)e.ID == 1 && status == 0 && Int(e, "Disposition") == RegCreatedNewKey)
                    Record(run, pid, name, null, RegistryOperation.KeyCreated);
                else if ((int)e.ID == 1 && IsDenied(status))
                    Record(run, pid, name, null, RegistryOperation.KeyCreated, failure: Describe(status));
                else if (status == 0)
                    Record(run, pid, name, null, RegistryOperation.KeyOpened);
                break;
            }
            case 5: // SetValueKey
            {
                var status = Int(e, "Status");
                var type = Int(e, "Type");
                var key = run.KeyName(U64(e, "KeyObject"), Str(e, "KeyName"));
                var valueName = Str(e, "ValueName") ?? "";
                if (IsActivityTracking(key, valueName)) return;
                var captured = e.PayloadByName("CapturedData") as byte[];
                var hasData = captured is { Length: > 0 } || Int(e, "DataSize") == 0;
                var entry = Record(run, pid, key, valueName, RegistryOperation.ValueSet,
                    failure: status == 0 ? null : Describe(status),
                    valueType: RegistryValueFormatter.TypeName(type),
                    data: hasData ? RegistryValueFormatter.Format(type, captured, Int(e, "DataSize")) : null);
                // Windows usually doesn't include the data in the event, so read what was written. Only for new
                // entries and flagged ones, so a program rewriting one value thousands of times stays cheap.
                if (entry is not null && !hasData && status == 0 && (entry.Count == 1 || entry.Severity >= Severity.Medium))
                    entry.Data = RegistryValueFormatter.ReadCurrent(key, valueName) ?? entry.Data ?? "(value already removed)";
                break;
            }
            case 6: // DeleteValueKey
            {
                var status = Int(e, "Status");
                var key = run.KeyName(U64(e, "KeyObject"), Str(e, "KeyName"));
                var valueName = Str(e, "ValueName") ?? "";
                if (IsActivityTracking(key, valueName)) return;
                Record(run, pid, key, valueName, RegistryOperation.ValueDeleted, failure: status == 0 ? null : Describe(status));
                break;
            }
            case 3: // DeleteKey
            {
                var status = Int(e, "Status");
                Record(run, pid, run.KeyName(U64(e, "KeyObject"), Str(e, "KeyName")), null, RegistryOperation.KeyDeleted,
                    failure: status == 0 ? null : Describe(status));
                break;
            }
        }
    }

    /// <summary>
    /// Windows' Background/Desktop Activity Moderator (bam/dam) records every program start and exit under
    /// Services\bam\State\UserSettings\&lt;SID&gt;, written by the kernel while the program is current. Not the program's doing.
    /// </summary>
    private static bool IsActivityTracking(string kernelKey, string valueName) =>
        valueName.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) &&
        (kernelKey.StartsWith("(unknown key)", StringComparison.Ordinal) ||
         kernelKey.Contains(@"\Services\bam\", StringComparison.OrdinalIgnoreCase) ||
         kernelKey.Contains(@"\Services\dam\", StringComparison.OrdinalIgnoreCase));

    private static bool IsDenied(int status) => status == unchecked((int)0xC0000022);

    private static string Describe(int status) => status switch
    {
        unchecked((int)0xC0000022) => "access denied",
        unchecked((int)0xC0000034) => "not found",
        unchecked((int)0xC000007C) => "no such key",
        _ => $"error 0x{status:X8}",
    };

    private RegistryActivity? Record(Run run, int pid, string kernelKey, string? valueName, RegistryOperation operation,
        string? failure = null, string? valueType = null, string? data = null)
    {
        var key = BehaviorRules.FriendlyKey(kernelKey, run.OwnerSid);
        var now = DateTime.UtcNow;
        var dictKey = (key, valueName, operation, pid);
        if (!run.Registry.TryGetValue(dictKey, out var entry))
        {
            var reads = operation == RegistryOperation.KeyOpened;
            if (reads ? run.RegistryReads >= MaxReads : run.RegistryChanges >= MaxChanges)
            {
                run.Truncated = true;
                return null;
            }
            if (reads) run.RegistryReads++; else run.RegistryChanges++;
            entry = new RegistryActivity
            {
                Key = key, ValueName = valueName, Operation = operation, Pid = pid, ProcessName = run.ProcessName(pid), FirstUtc = now,
            };
            run.Registry[dictKey] = entry;
        }
        entry.Count++;
        entry.LastUtc = now;
        if (valueType is not null) entry.ValueType = valueType;
        if (data is not null) entry.Data = data;
        // A later success replaces an earlier refusal (and vice versa only if it never succeeded).
        if (failure is null || entry.Count == 1) entry.Failure = failure;
        var verdict = BehaviorRules.ForRegistry(key, valueName, operation, entry.Failure is not null);
        entry.Severity = verdict.Severity;
        entry.Reason = verdict.Reason;
        return entry;
    }

    // -------------------------------------------------------------------- network

    private void OnNetwork(Run run, int pid, TraceEvent e)
    {
        var id = (int)e.ID;
        var (protocol, kind) = id switch
        {
            10 or 26 => ("TCP", 's'),
            11 or 27 => ("TCP", 'r'),
            12 or 28 or 16 or 32 => ("TCP", 'c'),
            15 or 31 => ("TCP", 'a'),
            42 or 58 => ("UDP", 's'),
            43 or 59 => ("UDP", 'r'),
            _ => ("", ' '),
        };
        if (kind == ' ') return;
        if (Address(e.PayloadByName("daddr")) is not { } remote) return;
        var port = Port(e.PayloadByName("dport"));
        var size = Int(e, "size");
        run.EventCount++;

        // Connections the program accepted are listed under its own (listening) port; their traffic follows them.
        var inbound = false;
        if (kind == 'a')
        {
            inbound = true;
            var localPort = Port(e.PayloadByName("sport"));
            run.InboundPeers[(remote, port)] = localPort;
            port = localPort;
        }
        else if (run.InboundPeers.TryGetValue((remote, port), out var listening))
        {
            inbound = true;
            port = listening;
        }
        var key = (protocol, remote, port, pid, inbound);
        var now = DateTime.UtcNow;
        if (!run.Network.TryGetValue(key, out var entry))
        {
            if (run.Network.Count >= MaxChanges) { run.Truncated = true; return; }
            entry = new NetworkActivity
            {
                Protocol = protocol, RemoteAddress = remote, RemotePort = port, Inbound = inbound, Pid = pid,
                ProcessName = run.ProcessName(pid), FirstUtc = now,
            };
            run.Network[key] = entry;
        }
        entry.Count++;
        entry.LastUtc = now;
        switch (kind)
        {
            case 's': entry.BytesSent += size; break;
            case 'r': entry.BytesReceived += size; break;
            case 'c': case 'a': entry.Attempts++; break;
        }
    }

    /// <summary>Kernel-Network addresses: IPv4 as a 32-bit number in network byte order, IPv6 as 16 bytes.</summary>
    internal static string? Address(object? value) => value switch
    {
        int i => new IPAddress(BitConverter.GetBytes(i)).ToString(),
        uint u => new IPAddress(BitConverter.GetBytes(u)).ToString(),
        byte[] { Length: 4 or 16 } b => new IPAddress(b).ToString(),
        IPAddress ip => ip.ToString(),
        string s when IPAddress.TryParse(s, out var ip) => ip.ToString(),
        _ => null,
    };

    /// <summary>Kernel-Network ports are in network byte order.</summary>
    internal static int Port(object? value)
    {
        var raw = value switch
        {
            int i => (ushort)i,
            uint u => (ushort)u,
            ushort s => s,
            short s => (ushort)s,
            _ => (ushort)0,
        };
        return (ushort)((raw >> 8) | (raw << 8));
    }

    // ------------------------------------------------------------------------ DNS

    private static readonly Dictionary<int, string> QueryTypes = new()
    {
        [1] = "A", [5] = "CNAME", [12] = "PTR", [15] = "MX", [16] = "TXT", [28] = "AAAA", [33] = "SRV", [65] = "HTTPS", [255] = "ANY",
    };

    private void OnDns(Run run, int pid, TraceEvent e)
    {
        var status = Int(e, "QueryStatus");
        if (status == 87) return; // ERROR_INVALID_PARAMETER: the resolver skipping a query type, not a real lookup
        var name = Str(e, "QueryName")?.TrimEnd('.');
        if (string.IsNullOrEmpty(name)) return;
        var typeNumber = Int(e, "QueryType");
        var type = QueryTypes.GetValueOrDefault(typeNumber, typeNumber.ToString());
        var addresses = (Str(e, "QueryResults") ?? "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(a => a.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase) ? a[7..] : a)
            .Where(a => IPAddress.TryParse(a, out _))
            .Distinct()
            .ToList();
        foreach (var address in addresses)
            run.AddressNames[address] = name;

        var key = (name.ToLowerInvariant(), type, pid);
        var now = DateTime.UtcNow;
        if (!run.Dns.TryGetValue(key, out var entry))
        {
            if (run.Dns.Count >= MaxChanges) { run.Truncated = true; return; }
            var verdict = BehaviorRules.ForDnsName(name);
            entry = new DnsActivity
            {
                Name = name, QueryType = type, Pid = pid, ProcessName = run.ProcessName(pid), FirstUtc = now,
                Severity = verdict.Severity, Reason = verdict.Reason,
            };
            run.Dns[key] = entry;
        }
        entry.Count++;
        entry.LastUtc = now;
        if (addresses.Count > 0)
        {
            entry.Results = string.Join(", ", addresses);
            entry.Failed = false;
        }
        else if (entry.Results is null)
        {
            entry.Failed = status != 0;
            if (status != 0) entry.Results = status == 9003 ? "(name does not exist)" : $"(failed, code {status})";
        }
    }

    // ---------------------------------------------------------------- maintenance

    private void Maintain()
    {
        if (Interlocked.Exchange(ref _maintaining, 1) == 1) return;
        try
        {
            List<(Run Run, AnalysisProcess Process)> incomplete;
            List<(Run Run, int Pid, DateTime Created)> alive;
            lock (_gate)
            {
                var now = DateTime.UtcNow;
                foreach (var run in _runs.Values.Where(r => r.State == AnalysisState.Running).ToList())
                {
                    if (run.Live.Count == 0 && run.AllExitedUtc is { } exited && now - exited > ExitGrace)
                        Finish(run, run.StopAfterExitsUtc is null ? AnalysisState.Finished : AnalysisState.Stopped, exited);
                    else if (now - run.StartedUtc > MaxDuration)
                        Finish(run, AnalysisState.Stopped);
                }

                // Forget old runs.
                var expired = _runs.Values.Where(r => r.State != AnalysisState.Running && now - (r.EndedUtc ?? now) > KeepFinished)
                    .Concat(_runs.Values.Where(r => r.State != AnalysisState.Running).OrderByDescending(r => r.StartedUtc).Skip(MaxKeptRuns))
                    .Distinct().ToList();
                foreach (var run in expired) _runs.Remove(run.Id);

                StopSessionIfIdle();

                incomplete = _runs.Values
                    .SelectMany(r => r.Processes.Values.Where(p => p.Signature is null).Select(p => (r, p)))
                    .Take(10).ToList();
                alive = _runs.Values.Where(r => r.State == AnalysisState.Running && (now - r.LastLivenessCheckUtc).TotalSeconds >= 5)
                    .SelectMany(r =>
                    {
                        r.LastLivenessCheckUtc = now;
                        return r.Live.Where(r.Created.ContainsKey).Select(p => (r, p, r.Created[p]));
                    }).ToList();
            }

            // Slow work outside the lock: process details, signature checks, and noticing exits ETW missed.
            foreach (var (run, process) in incomplete) CompleteProcess(run, process);

            foreach (var (run, pid, created) in alive)
            {
                if (AnalysisNative.IsRunning(pid, created)) continue;
                lock (_gate)
                {
                    if (!run.Live.Remove(pid)) continue;
                    if (run.Processes.TryGetValue(pid, out var p)) p.ExitedUtc ??= DateTime.UtcNow;
                    if (run.Live.Count == 0) run.AllExitedUtc ??= DateTime.UtcNow;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Program analysis maintenance failed");
        }
        finally
        {
            Volatile.Write(ref _maintaining, 0);
        }
    }

    /// <summary>
    /// Programs that exited before their start event was handled could not be asked for their path and
    /// command line; the service's own process-start trace recorded both. Then the signature is checked
    /// and the process re-scored.
    /// </summary>
    private void CompleteProcess(Run run, AnalysisProcess process)
    {
        string? image, commandLine;
        int attempt;
        lock (_gate)
        {
            image = process.ImagePath;
            commandLine = process.CommandLine;
            attempt = run.InfoAttempts[process.Pid] = run.InfoAttempts.GetValueOrDefault(process.Pid) + 1;
        }

        if (commandLine is null || image is null || !Path.IsPathRooted(image))
        {
            var record = _history.Find(process.Pid, process.StartedUtc.AddSeconds(1));
            if (record is not null && Math.Abs((record.StartUtc - process.StartedUtc).TotalSeconds) < 3)
            {
                if (record.ImagePath is not null) image = record.ImagePath;
                commandLine ??= record.CommandLine;
            }
            else if (attempt < 5)
            {
                return; // the history may not have caught up yet; try again next second
            }
        }

        SignatureInfo? signature = null;
        try
        {
            if (image is not null && Path.IsPathRooted(image) && File.Exists(image)) signature = SignatureVerifier.Verify(image);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Signature check failed for {Path}", image);
        }

        lock (_gate)
        {
            process.ImagePath = image;
            process.CommandLine = commandLine;
            process.Signature = signature?.Describe() ?? "(file not available to check)";
            var parentElevated = run.Processes.GetValueOrDefault(process.ParentPid)?.Elevated ?? process.Elevated;
            var before = (process.Severity, process.Reason);
            Score(process, process.Pid == run.RootPid, parentElevated, signature);
            if (before.Severity > process.Severity) (process.Severity, process.Reason) = before;
            foreach (var activity in run.Activities().Where(a => a.Pid == process.Pid))
                activity.ProcessName = run.ProcessName(process.Pid);
        }
    }

    /// <summary>Caller holds the lock.</summary>
    private void Finish(Run run, AnalysisState state, DateTime? endedUtc = null)
    {
        if (run.State != AnalysisState.Running) return;
        run.State = state;
        run.EndedUtc = endedUtc ?? DateTime.UtcNow;
        foreach (var pid in run.Processes.Keys)
        {
            if (_pids.TryGetValue(pid, out var owner) && owner == run) _pids.Remove(pid);
        }
        run.FileObjects.Clear();
        run.KeyObjects.Clear();
        _logger.LogInformation("Program analysis {Id} {State}: {Events} events", run.Id, state, run.EventCount);
    }

    // ------------------------------------------------------------------ payloads

    private static int Int(TraceEvent e, string name) => e.PayloadByName(name) switch
    {
        int i => i,
        uint u => unchecked((int)u),
        long l => unchecked((int)l),
        ulong ul => unchecked((int)ul),
        short s => s,
        ushort us => us,
        byte b => b,
        _ => 0,
    };

    private static ulong U64(TraceEvent e, string name) => e.PayloadByName(name) switch
    {
        ulong u => u,
        long l => unchecked((ulong)l),
        uint u => u,
        int i => unchecked((uint)i),
        _ => 0,
    };

    private static string? Str(TraceEvent e, string name) => e.PayloadByName(name) is string { Length: > 0 } s ? s : null;

    // ----------------------------------------------------------------------- state

    private sealed class Run(string id, string? ownerSid, DateTime startedUtc, int rootPid, long startEventId)
    {
        public string Id { get; } = id;
        public string? OwnerSid { get; } = ownerSid;
        public DateTime StartedUtc { get; } = startedUtc;
        public int RootPid { get; } = rootPid;
        public long StartEventId { get; } = startEventId;
        public AnalysisState State { get; set; } = AnalysisState.Running;
        public DateTime? EndedUtc { get; set; }
        public DateTime? AllExitedUtc { get; set; }
        public DateTime? StopAfterExitsUtc { get; set; }
        public DateTime LastLivenessCheckUtc { get; set; } = startedUtc;
        public long EventCount { get; set; }
        public bool Truncated { get; set; }
        public int FileReads, FileChanges, RegistryReads, RegistryChanges;

        public Dictionary<int, AnalysisProcess> Processes { get; } = [];
        public Dictionary<int, DateTime> Created { get; } = [];
        public HashSet<int> Live { get; } = [];
        public Dictionary<ulong, string> FileObjects { get; } = [];
        public Dictionary<ulong, string> KeyObjects { get; } = [];
        public Dictionary<(string, FileOperation, int), FileActivity> Files { get; } = [];
        public Dictionary<(string, string?, RegistryOperation, int), RegistryActivity> Registry { get; } = [];
        public Dictionary<(string, string, int, int, bool), NetworkActivity> Network { get; } = [];
        public Dictionary<(string, string, int), DnsActivity> Dns { get; } = [];
        public Dictionary<string, string> AddressNames { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<(string, int), int> InboundPeers { get; } = [];
        public Dictionary<int, int> InfoAttempts { get; } = [];

        public IEnumerable<ActivityBase> Activities() =>
            Files.Values.Cast<ActivityBase>().Concat(Registry.Values).Concat(Network.Values).Concat(Dns.Values);

        public bool MayAccess(string? sid, bool admin) => admin || OwnerSid is null || string.Equals(sid, OwnerSid, StringComparison.OrdinalIgnoreCase);

        public string ProcessName(int pid) =>
            Processes.TryGetValue(pid, out var p) && p.ImagePath is not null ? Path.GetFileName(p.ImagePath) : $"PID {pid}";

        public void RememberFile(ulong fileObject, string name)
        {
            if (fileObject == 0) return;
            if (FileObjects.Count >= MaxObjectNames) FileObjects.Clear();
            FileObjects[fileObject] = name;
        }

        public void RememberKey(ulong keyObject, string name)
        {
            if (KeyObjects.Count >= MaxObjectNames) KeyObjects.Clear();
            KeyObjects[keyObject] = name;
        }

        /// <summary>
        /// Kernel registry events name a key relative to a parent handle (often HKLM or HKCU opened earlier), so
        /// full paths are rebuilt from the names recorded when those handles were opened.
        /// </summary>
        public string ResolveKey(ulong baseObject, string? baseName, string? relativeName)
        {
            relativeName ??= "";
            if (relativeName.StartsWith(@"\REGISTRY", StringComparison.OrdinalIgnoreCase)) return relativeName;
            var parent = baseObject != 0 && KeyObjects.TryGetValue(baseObject, out var known) ? known : baseName;
            if (string.IsNullOrEmpty(parent)) parent = "(unknown key)";
            return relativeName.Length == 0 ? parent : parent.TrimEnd('\\') + "\\" + relativeName.TrimStart('\\');
        }

        public string KeyName(ulong keyObject, string? keyName) =>
            keyObject != 0 && KeyObjects.TryGetValue(keyObject, out var name) ? name
            : !string.IsNullOrEmpty(keyName) ? keyName
            : "(unknown key)";

        public AnalysisReport ToReport(bool includeReads)
        {
            var process = Processes.GetValueOrDefault(RootPid);
            static IEnumerable<T> Ordered<T>(IEnumerable<T> items) where T : ActivityBase =>
                items.OrderByDescending(a => a.Severity).ThenBy(a => a.FirstUtc);

            // Program files the run created and deleted again are temporary (e.g. PowerShell's policy test scripts).
            var deleted = Files.Values.Where(f => f.Operation == FileOperation.Deleted).Select(f => f.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var files = Files.Values.Where(f => includeReads || f.Operation != FileOperation.Opened || f.Severity > Severity.Info).Select(Clone).ToList();
            foreach (var f in files.Where(f => f.Operation == FileOperation.Created && f.Severity == Severity.Medium && deleted.Contains(f.Path)))
            {
                f.Severity = Severity.Low;
                f.Reason = "Temporary program/script file (created and deleted again)";
            }

            var network = Ordered(Network.Values).Select(Clone).ToList();
            foreach (var n in network)
            {
                n.HostName = AddressNames.GetValueOrDefault(n.RemoteAddress);
                var verdict = BehaviorRules.ForConnection(n.RemoteAddress, n.RemotePort, n.Inbound, n.HostName);
                n.Severity = verdict.Severity;
                n.Reason = verdict.Reason;
            }

            return new AnalysisReport
            {
                Id = Id,
                State = State,
                StartedUtc = StartedUtc,
                EndedUtc = EndedUtc,
                RootPid = RootPid,
                ProgramPath = process?.ImagePath,
                CommandLine = process?.CommandLine,
                EventCount = EventCount,
                Truncated = Truncated,
                ReadsOmitted = !includeReads,
                Processes = Processes.Values.OrderBy(p => p.StartedUtc).Select(Clone).ToList(),
                Files = Ordered(files).ToList(),
                Registry = Ordered(Registry.Values.Where(r => includeReads || r.Operation != RegistryOperation.KeyOpened)).Select(Clone).ToList(),
                Network = network.OrderByDescending(n => n.Severity).ThenBy(n => n.FirstUtc).ToList(),
                Dns = Ordered(Dns.Values).Select(Clone).ToList(),
            };
        }

        // Copies, so the report can be serialized outside the lock while recording continues.
        private static T Clone<T>(T item) where T : ActivityBase => (T)item.Copy();
        private static AnalysisProcess Clone(AnalysisProcess item) => item.Copy();
    }
}

/// <summary>Formats registry value data captured by the kernel for display.</summary>
public static class RegistryValueFormatter
{
    public static string TypeName(int type) => type switch
    {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        11 => "REG_QWORD",
        _ => $"type {type}",
    };

    public static string? Format(int type, byte[]? data, int fullSize)
    {
        if (data is null) return null;
        var truncated = fullSize > data.Length ? $" ... ({fullSize:N0} bytes in total)" : "";
        string text = type switch
        {
            1 or 2 or 6 => Encoding.Unicode.GetString(data).TrimEnd('\0'),
            7 => string.Join(" | ", Encoding.Unicode.GetString(data).Split('\0', StringSplitOptions.RemoveEmptyEntries)),
            4 when data.Length >= 4 => FormatNumber(BitConverter.ToUInt32(data, 0)),
            5 when data.Length >= 4 => FormatNumber((uint)(data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3])),
            11 when data.Length >= 8 => FormatNumber(BitConverter.ToUInt64(data, 0)),
            _ => data.Length == 0 ? "(empty)" : Convert.ToHexString(data, 0, Math.Min(data.Length, 64)) + (data.Length > 64 ? "..." : ""),
        };
        return text + truncated;
    }

    private static string FormatNumber(ulong value) => $"{value} (0x{value:X})";

    /// <summary>Reads a value as it is now, from a kernel path (\REGISTRY\MACHINE\... or \REGISTRY\USER\...).</summary>
    public static string? ReadCurrent(string kernelKey, string valueName)
    {
        RegistryHive hive;
        string subKey;
        if (kernelKey.StartsWith(@"\REGISTRY\MACHINE\", StringComparison.OrdinalIgnoreCase))
            (hive, subKey) = (RegistryHive.LocalMachine, kernelKey[18..]);
        else if (kernelKey.StartsWith(@"\REGISTRY\USER\", StringComparison.OrdinalIgnoreCase))
            (hive, subKey) = (RegistryHive.Users, kernelKey[15..]);
        else
            return null;
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64); // kernel paths spell out WOW6432Node themselves
            using var key = root.OpenSubKey(subKey);
            return key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) switch
            {
                null => null,
                string s => s,
                string[] lines => string.Join(" | ", lines),
                int i => FormatNumber(unchecked((uint)i)),
                long l => FormatNumber(unchecked((ulong)l)),
                byte[] b => b.Length == 0 ? "(empty)" : Convert.ToHexString(b, 0, Math.Min(b.Length, 64)) + (b.Length > 64 ? "..." : ""),
                var other => other.ToString(),
            };
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException or ArgumentException)
        {
            return null;
        }
    }
}
