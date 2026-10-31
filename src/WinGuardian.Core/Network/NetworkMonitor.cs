using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Core.Network;

/// <summary>
/// Ports, connections and the Windows Firewall. Provides live snapshots for the Firewall tab, keeps a
/// 24-hour history of which programs connected where, and raises events when a program starts listening
/// on a new port, when firewall rules are added/changed/removed, and when the firewall is switched off.
/// </summary>
public sealed class NetworkMonitor(GuardianDatabase db, EventRecorder events, ILogger<NetworkMonitor> logger)
{
    /// <summary>Windows' ephemeral port range starts here; such ports change constantly and are baselined as "dynamic".</summary>
    public const int DynamicPortStart = 49152;
    private const int MaxHistory = 5000;
    private static readonly TimeSpan HistoryWindow = TimeSpan.FromHours(24);
    private static readonly TimeSpan SnapshotMaxAge = TimeSpan.FromSeconds(2);

    private readonly Lock _gate = new();
    private readonly Dictionary<string, ConnectionHistoryEntry> _history = new(StringComparer.OrdinalIgnoreCase);
    private NetworkSnapshot? _last;

    private sealed record FirewallState(Dictionary<string, bool> Profiles, bool ServiceRunning);

    // --------------------------------------------------------------- snapshots

    /// <summary>A recent snapshot (re-captured if older than two seconds).</summary>
    public NetworkSnapshot GetSnapshot()
    {
        lock (_gate)
        {
            if (_last is not null && DateTime.UtcNow - _last.CapturedUtc < SnapshotMaxAge) return _last;
            return _last = Capture();
        }
    }

    private NetworkSnapshot Capture()
    {
        var sockets = SocketTables.Capture();
        var services = ServiceProcessMap.Capture();
        var processes = new Dictionary<int, (string Name, string? Path)>();
        var firstSeen = db.GetListenerFirstSeen();
        var rules = FirewallConfig.ReadRules();

        var snapshot = new NetworkSnapshot
        {
            Rules = rules,
            Firewall = FirewallConfig.ReadStatus(rules),
        };

        foreach (var s in sockets)
        {
            if (!processes.TryGetValue(s.Pid, out var process))
                processes[s.Pid] = process = DescribeProcess(s.Pid);

            var endpoint = new NetworkEndpoint
            {
                Protocol = s.Protocol,
                LocalAddress = Format(s.LocalAddress),
                LocalPort = s.LocalPort,
                RemoteAddress = s.RemoteAddress is null ? null : Format(s.RemoteAddress),
                RemotePort = s.RemotePort,
                State = s.State,
                Pid = s.Pid,
                ProcessName = process.Name,
                ProcessPath = process.Path,
                Services = services.TryGetValue(s.Pid, out var svc) ? string.Join(", ", svc) : null,
                InUserWritableLocation = process.Path is not null && SeverityRules.IsUserWritable(process.Path),
            };
            if (process.Path is not null && File.Exists(process.Path))
            {
                var signature = SignatureVerifier.Verify(process.Path); // cached by path/size/timestamp
                endpoint.Signature = signature.Describe();
                endpoint.Signer = signature.IsValid ? signature.Signer : null;
                endpoint.SignedByMicrosoft = signature.IsMicrosoft;
            }

            var listening = s.State == "Listen" || s.Protocol.StartsWith("UDP", StringComparison.Ordinal);
            if (listening)
            {
                endpoint.FirstSeenUtc = firstSeen.TryGetValue(ListenerKey(endpoint), out var seen) ? seen : null;
                snapshot.Listeners.Add(endpoint);
            }
            else
            {
                snapshot.Connections.Add(endpoint);
            }
        }

        UpdateHistory(snapshot.Connections, snapshot.CapturedUtc);
        snapshot.History = _history.Values.OrderByDescending(h => h.LastSeenUtc).Take(3000).ToList();
        snapshot.Listeners = snapshot.Listeners.OrderBy(l => l.LocalPort).ThenBy(l => l.Protocol).ToList();
        snapshot.Connections = snapshot.Connections.OrderBy(c => c.ProcessName).ThenBy(c => c.RemoteAddress).ToList();
        return snapshot;
    }

    private void UpdateHistory(List<NetworkEndpoint> connections, DateTime now)
    {
        foreach (var c in connections)
        {
            if (c.Pid == 0 || c.RemoteAddress is null or "0.0.0.0" or "::" || c.RemotePort is null or 0) continue;
            var proto = c.Protocol.StartsWith("TCP", StringComparison.Ordinal) ? "TCP" : "UDP";
            var key = $"{c.ProcessPath ?? c.ProcessName}|{proto}|{c.RemoteAddress}|{c.RemotePort}";
            if (_history.TryGetValue(key, out var entry))
            {
                entry.LastSeenUtc = now;
                entry.TimesSeen++;
            }
            else
            {
                _history[key] = new ConnectionHistoryEntry
                {
                    Protocol = proto,
                    ProcessName = c.ProcessName,
                    ProcessPath = c.ProcessPath,
                    Services = c.Services,
                    RemoteAddress = c.RemoteAddress,
                    RemotePort = c.RemotePort.Value,
                    FirstSeenUtc = now,
                    LastSeenUtc = now,
                    TimesSeen = 1,
                };
            }
        }

        foreach (var stale in _history.Where(kv => now - kv.Value.LastSeenUtc > HistoryWindow).Select(kv => kv.Key).ToList())
            _history.Remove(stale);
        if (_history.Count > MaxHistory)
        {
            foreach (var oldest in _history.OrderBy(kv => kv.Value.LastSeenUtc).Take(_history.Count - MaxHistory).Select(kv => kv.Key).ToList())
                _history.Remove(oldest);
        }
    }

    // ------------------------------------------------------- baseline & polling

    public bool HasBaseline => db.GetMeta(GuardianDatabase.MetaNetworkBaseline) is not null;

    public int CaptureBaseline()
    {
        lock (_gate)
        {
            var snapshot = _last = Capture();
            foreach (var l in snapshot.Listeners.DistinctBy(ListenerKey))
                db.InsertListener(ListenerKey(l), l.Protocol, l.LocalPort, l.ProcessPath ?? l.ProcessName);
            db.ReplaceFirewallRules(snapshot.Rules.ToDictionary(r => r.Key, r => r.Raw));
            db.SetMeta(GuardianDatabase.MetaFirewallState, JsonSerializer.Serialize(StateOf(snapshot.Firewall)));
            db.SetMeta(GuardianDatabase.MetaNetworkBaseline, GuardianDatabase.Iso(DateTime.UtcNow));
            logger.LogInformation("Network baseline captured: {Listeners} listeners, {Rules} firewall rules",
                snapshot.Listeners.Count, snapshot.Rules.Count);
            return snapshot.Listeners.Count;
        }
    }

    public void Poll()
    {
        NetworkSnapshot snapshot;
        lock (_gate) snapshot = _last = Capture();
        CheckListeners(snapshot);
        CheckRules(snapshot.Rules);
        CheckFirewallState(snapshot.Firewall);
    }

    private void CheckListeners(NetworkSnapshot snapshot)
    {
        var known = db.GetListenerFirstSeen();
        foreach (var l in snapshot.Listeners.DistinctBy(ListenerKey))
        {
            var key = ListenerKey(l);
            if (known.ContainsKey(key)) continue;
            db.InsertListener(key, l.Protocol, l.LocalPort, l.ProcessPath ?? l.ProcessName);
            l.FirstSeenUtc = DateTime.UtcNow;

            var binding = l.IsLoopbackOnly ? "this computer only" : l.IsAllInterfaces ? "all network interfaces" : "one interface";
            var dynamicNote = l.LocalPort >= DynamicPortStart ? " (dynamic port range; further dynamic ports by this program are not reported)" : "";
            events.Record(new GuardianEvent
            {
                Severity = ListenerSeverity(l),
                Category = EventCategory.Network,
                Change = ChangeKind.Added,
                Subject = $"New listening port: {l.Protocol} {l.LocalPort} by {l.ProcessName}",
                Details = $"{l.Protocol} {l.LocalAddress}:{l.LocalPort} reachable from {binding}{dynamicNote}; " +
                          $"process {l.ProcessName} (PID {l.Pid}){(l.Services is null ? "" : $" hosting {l.Services}")}; " +
                          $"{l.Signature ?? "signature unknown"}; {l.ProcessPath ?? "(path unavailable)"}",
                FilePath = l.ProcessPath,
                Sha256 = l.ProcessPath is not null ? FileHasher.TryHash(l.ProcessPath, 256L * 1024 * 1024) : null,
                Signature = l.Signature,
                Signer = l.Signer,
                TrustKey = $"Listener|{key}",
            });
        }
    }

    /// <summary>
    /// Microsoft-signed: Info. Other valid publisher: Low. Unsigned: Medium, or High from a user-writable
    /// folder. Listening on loopback only (not reachable from the network) lowers it by one step.
    /// </summary>
    public static Severity ListenerSeverity(NetworkEndpoint l)
    {
        var severity = l.SignedByMicrosoft ? Severity.Info
            : l.Signer is not null ? Severity.Low
            : l.ProcessPath is null ? Severity.Low
            : l.InUserWritableLocation ? Severity.High
            : Severity.Medium;
        if (l.IsLoopbackOnly && severity > Severity.Info) severity--;
        return severity;
    }

    /// <summary>
    /// Ports in the dynamic range are grouped per program; fixed ports are tracked individually.
    /// A program is identified by its path (or name, for protected system processes).
    /// </summary>
    public static string ListenerKey(NetworkEndpoint l)
    {
        var proto = l.Protocol.StartsWith("TCP", StringComparison.Ordinal) ? "TCP" : "UDP";
        var port = l.LocalPort >= DynamicPortStart ? "dynamic" : l.LocalPort.ToString();
        return $"{proto}|{port}|{(l.ProcessPath ?? l.ProcessName).ToUpperInvariant()}";
    }

    private void CheckRules(List<FirewallRule> current)
    {
        var stored = db.GetFirewallRules();
        var changes = DiffRules(stored, current);
        if (changes.Count == 0) return;
        foreach (var (change, rule, previous) in changes)
            events.Record(RuleEvent(change, rule, previous));
        db.ReplaceFirewallRules(current.ToDictionary(r => r.Key, r => r.Raw));
    }

    /// <summary>Compares stored rule strings (key → raw) with the current rules.</summary>
    public static List<(ChangeKind Change, FirewallRule Rule, FirewallRule? Previous)> DiffRules(
        IReadOnlyDictionary<string, string> stored, IReadOnlyCollection<FirewallRule> current)
    {
        var result = new List<(ChangeKind, FirewallRule, FirewallRule?)>();
        var currentKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in current)
        {
            currentKeys.Add(rule.Key);
            if (!stored.TryGetValue(rule.Key, out var raw))
                result.Add((ChangeKind.Added, rule, null));
            else if (raw != rule.Raw)
                result.Add((ChangeKind.Modified, rule, Reparse(rule.Key, raw)));
        }
        foreach (var (key, raw) in stored)
        {
            if (!currentKeys.Contains(key)) result.Add((ChangeKind.Removed, Reparse(key, raw), null));
        }
        return result;
    }

    private static FirewallRule Reparse(string key, string raw)
    {
        var bar = key.IndexOf('|');
        return FirewallConfig.Parse(key[(bar + 1)..], key[..bar], raw);
    }

    private static GuardianEvent RuleEvent(ChangeKind change, FirewallRule rule, FirewallRule? previous)
    {
        SignatureInfo? signature = rule.Program is not null && File.Exists(rule.Program) ? SignatureVerifier.Verify(rule.Program) : null;
        var opensInbound = rule.AllowsInbound && (change == ChangeKind.Added || previous?.AllowsInbound != true);

        Severity severity;
        if (change == ChangeKind.Removed || !opensInbound) severity = Severity.Low;
        else if (signature?.IsMicrosoft == true) severity = Severity.Info;
        else if (signature?.IsValid == true) severity = Severity.Low;
        else if (rule.Program is not null && SeverityRules.IsUserWritable(rule.Program) && signature?.IsValid != true) severity = Severity.High;
        else severity = Severity.Medium;
        if (signature?.Status == SignatureStatus.Tampered) severity = Severity.High;

        var verb = change switch { ChangeKind.Added => "added", ChangeKind.Removed => "removed", _ => "changed" };
        return new GuardianEvent
        {
            Severity = severity,
            Category = EventCategory.Network,
            Change = change,
            Subject = $"Firewall rule {verb}: {rule.Name}",
            Details = (previous is null ? rule.Describe() : $"{previous.Describe()} -> {rule.Describe()}") +
                      (opensInbound ? ". This rule lets other computers connect in." : "") +
                      $" ({rule.Source} rule)",
            FilePath = rule.Program,
            Sha256 = signature is not null && rule.Program is not null ? FileHasher.TryHash(rule.Program, 256L * 1024 * 1024) : null,
            Signature = signature?.Describe(),
            Signer = signature?.IsValid == true ? signature.Signer : null,
            TrustKey = $"FirewallRule|{rule.Key}",
        };
    }

    private void CheckFirewallState(FirewallStatus status)
    {
        var current = StateOf(status);
        var stored = db.GetMeta(GuardianDatabase.MetaFirewallState) is { } json
            ? JsonSerializer.Deserialize<FirewallState>(json)
            : null;
        db.SetMeta(GuardianDatabase.MetaFirewallState, JsonSerializer.Serialize(current));
        if (stored is null) return;

        foreach (var (profile, enabled) in current.Profiles)
        {
            if (!stored.Profiles.TryGetValue(profile, out var was) || was == enabled) continue;
            events.Record(enabled
                ? Info($"Windows Firewall turned back on ({profile} profile)")
                : Tamper($"Windows Firewall turned OFF ({profile} profile)",
                    "Inbound connections are no longer filtered on networks of this type. Malware commonly does this."));
        }
        if (stored.ServiceRunning && !current.ServiceRunning)
            events.Record(Tamper("Windows Firewall service (mpssvc) stopped",
                "With the firewall service stopped, no firewall rules are enforced."));
        else if (!stored.ServiceRunning && current.ServiceRunning)
            events.Record(Info("Windows Firewall service (mpssvc) is running again"));
    }

    private static FirewallState StateOf(FirewallStatus status) =>
        new(status.Profiles.ToDictionary(p => p.Name, p => p.Enabled), status.ServiceRunning);

    private static GuardianEvent Tamper(string subject, string details) => new()
    {
        Severity = Severity.High,
        Category = EventCategory.Tamper,
        Change = ChangeKind.Modified,
        Subject = subject,
        Details = details,
    };

    private static GuardianEvent Info(string subject) => new()
    {
        Severity = Severity.Info,
        Category = EventCategory.Network,
        Change = ChangeKind.Modified,
        Subject = subject,
    };

    // ----------------------------------------------------------------- helpers

    private static (string Name, string? Path) DescribeProcess(int pid)
    {
        if (pid == 0) return ("System Idle Process", null);
        if (pid == 4) return ("System", null);
        var path = NativeMethods.TryGetProcessImagePath(pid);
        if (path is not null) return (Path.GetFileName(path), path);
        try
        {
            using var p = Process.GetProcessById(pid);
            return (p.ProcessName, null);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return ($"PID {pid} (exited)", null);
        }
    }

    private static string Format(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) return address.MapToIPv4().ToString();
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            address = new IPAddress(address.GetAddressBytes()); // drop the %scope suffix for display
        return address.ToString();
    }
}
