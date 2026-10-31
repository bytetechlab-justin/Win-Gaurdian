using System.Management;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WinGuardian.Core.Configuration;
using WinGuardian.Core.Data;

namespace WinGuardian.Core.Monitoring;

/// <summary>
/// Watches the places malware uses to survive a reboot: Run/RunOnce keys (machine and every loaded
/// user hive), startup folders, WMI event subscriptions, Winlogon/AppInit/LSA/
/// Session Manager values, Image File Execution Options debuggers and SilentProcessExit monitors,
/// and Active Setup. (Services and drivers are covered by <see cref="ServiceMonitor"/>.)
/// </summary>
public sealed class PersistenceMonitor(
    GuardianDatabase db,
    GuardianOptions options,
    EventRecorder events,
    ILogger<PersistenceMonitor> logger)
{
    public const string MachineScope = "machine";
    private const int MaxValueLength = 2000;

    private const string Run = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOnce = @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string PolicyRun = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";
    private const string WowRun = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string WowRunOnce = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string Winlogon = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string WindowsNtWindows = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    private const string WowWindowsNtWindows = @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows";
    private const string Ifeo = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string WowIfeo = @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string SilentProcessExit = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
    private const string ActiveSetup = @"SOFTWARE\Microsoft\Active Setup\Installed Components";
    private const string SessionManager = @"SYSTEM\CurrentControlSet\Control\Session Manager";
    private const string AppCertDlls = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";
    private const string Lsa = @"SYSTEM\CurrentControlSet\Control\Lsa";

    private readonly long _maxHashBytes = options.MaxHashFileSizeMB * 1024L * 1024L;

    public sealed record CaptureResult(List<PersistenceEntry> Entries, HashSet<string> Scopes);

    public CaptureResult Capture()
    {
        var entries = new List<PersistenceEntry>();
        var scopes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { MachineScope };

        // Machine-wide registry locations.
        foreach (var path in new[] { Run, RunOnce, PolicyRun, WowRun, WowRunOnce, AppCertDlls })
            AddAllValues(entries, MachineScope, Registry.LocalMachine, "HKLM", path);
        AddNamedValues(entries, MachineScope, Registry.LocalMachine, "HKLM", Winlogon, "Shell", "Userinit", "Taskman", "AppSetup");
        AddNamedValues(entries, MachineScope, Registry.LocalMachine, "HKLM", WindowsNtWindows, "AppInit_DLLs", "LoadAppInit_DLLs");
        AddNamedValues(entries, MachineScope, Registry.LocalMachine, "HKLM", WowWindowsNtWindows, "AppInit_DLLs", "LoadAppInit_DLLs");
        AddNamedValues(entries, MachineScope, Registry.LocalMachine, "HKLM", SessionManager, "BootExecute");
        AddNamedValues(entries, MachineScope, Registry.LocalMachine, "HKLM", Lsa,
            "Authentication Packages", "Security Packages", "Notification Packages");
        foreach (var path in new[] { Ifeo, WowIfeo })
            AddSubkeyValues(entries, Registry.LocalMachine, "HKLM", path, "Debugger", "VerifierDlls");
        AddSubkeyValues(entries, Registry.LocalMachine, "HKLM", SilentProcessExit, "MonitorProcess");
        AddSubkeyValues(entries, Registry.LocalMachine, "HKLM", ActiveSetup, "StubPath");

        // Per-user locations, for every user hive currently loaded.
        foreach (var sid in LoadedUserSids())
        {
            scopes.Add(sid);
            foreach (var path in new[] { Run, RunOnce, PolicyRun })
                AddAllValues(entries, sid, Registry.Users, $@"HKU\{sid}", $@"{sid}\{path}");
            AddNamedValues(entries, sid, Registry.Users, $@"HKU\{sid}", $@"{sid}\{Winlogon}", "Shell");
            AddNamedValues(entries, sid, Registry.Users, $@"HKU\{sid}", $@"{sid}\{WindowsNtWindows}", "Load", "Run");
        }

        AddStartupFolders(entries);
        AddWmiSubscriptions(entries);
        return new CaptureResult(entries, scopes);
    }

    public int CaptureBaseline()
    {
        var capture = Capture();
        using var c = db.Open();
        using var tx = c.BeginTransaction();
        GuardianDatabase.Execute(c, tx, "DELETE FROM persistence; DELETE FROM persistence_scopes;");
        db.ReplacePersistence(c, tx, capture.Scopes, capture.Entries);
        db.SetMeta(GuardianDatabase.MetaPersistenceBaseline, GuardianDatabase.Iso(DateTime.UtcNow), c, tx);
        tx.Commit();
        logger.LogInformation("Persistence baseline captured: {Count} autostart entries", capture.Entries.Count);
        return capture.Entries.Count;
    }

    public void Poll()
    {
        var capture = Capture();
        var stored = db.GetPersistence();
        var knownScopes = db.GetPersistenceScopes();
        // A user hive seen for the first time (first logon since install) is baselined silently.
        var newScopes = capture.Scopes.Where(s => !knownScopes.Contains(s)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var changes = new List<GuardianEvent>();

        foreach (var entry in capture.Entries)
        {
            if (newScopes.Contains(entry.Scope)) continue;
            if (!stored.Remove(entry.Key, out var old))
                changes.Add(PersistenceEvent(entry, ChangeKind.Added, $"Value: {entry.Value}"));
            else if (old.Value != entry.Value)
                changes.Add(PersistenceEvent(entry, ChangeKind.Modified, $"'{old.Value}' -> '{entry.Value}'"));
        }

        // Entries of unloaded user hives are left alone; they are not "removed", the user just logged off.
        foreach (var gone in stored.Values.Where(e => capture.Scopes.Contains(e.Scope)))
            changes.Add(PersistenceEvent(gone, ChangeKind.Removed, $"Was: {gone.Value}"));

        if (changes.Count == 0 && newScopes.Count == 0) return;

        using var c = db.Open();
        using var tx = c.BeginTransaction();
        foreach (var e in changes) events.Record(c, tx, e);
        db.ReplacePersistence(c, tx, capture.Scopes, capture.Entries);
        tx.Commit();
    }

    private GuardianEvent PersistenceEvent(PersistenceEntry entry, ChangeKind change, string details)
    {
        var severity = change == ChangeKind.Removed ? Severity.Low
            : entry.Location.StartsWith("HKLM\\" + ActiveSetup, StringComparison.OrdinalIgnoreCase) ? Severity.Medium
            : Severity.High;

        var who = entry.Scope == MachineScope ? "" : $" (user {AccountName(entry.Scope)})";
        var e = new GuardianEvent
        {
            Category = EventCategory.Persistence,
            Change = change,
            Subject = $"{entry.Location}: {entry.Name}{who}",
            Details = details,
            FilePath = entry.TargetPath,
            Sha256 = change != ChangeKind.Removed && entry.TargetPath is not null
                ? FileHasher.TryHash(entry.TargetPath, _maxHashBytes) : null,
            TrustKey = entry.Key,
        };
        var signature = change == ChangeKind.Removed ? null : SeverityRules.Sign(e);
        e.Severity = SeverityRules.ForLaunchTarget(severity, change, entry.TargetPath, signature);
        if (signature is not null) e.Details += $"; target {e.Signature}";
        return e;
    }

    // ------------------------------------------------------------ registry

    private void AddAllValues(List<PersistenceEntry> entries, string scope, RegistryKey hive, string hiveName, string path)
    {
        TryRegistry(path, () =>
        {
            using var key = hive.OpenSubKey(path);
            if (key is null) return;
            foreach (var name in key.GetValueNames())
                AddValue(entries, scope, key, $@"{hiveName}\{StripSid(path, scope)}", name);
        });
    }

    private void AddNamedValues(List<PersistenceEntry> entries, string scope, RegistryKey hive, string hiveName, string path, params string[] names)
    {
        TryRegistry(path, () =>
        {
            using var key = hive.OpenSubKey(path);
            if (key is null) return;
            foreach (var name in names)
                AddValue(entries, scope, key, $@"{hiveName}\{StripSid(path, scope)}", name);
        });
    }

    /// <summary>For keys like IFEO: one subkey per program, each possibly holding a hijack value.</summary>
    private void AddSubkeyValues(List<PersistenceEntry> entries, RegistryKey hive, string hiveName, string path, params string[] names)
    {
        TryRegistry(path, () =>
        {
            using var key = hive.OpenSubKey(path);
            if (key is null) return;
            foreach (var sub in key.GetSubKeyNames())
            {
                using var subKey = key.OpenSubKey(sub);
                if (subKey is null) continue;
                foreach (var name in names)
                    AddValue(entries, MachineScope, subKey, $@"{hiveName}\{path}\{sub}", name);
            }
        });
    }

    private static void AddValue(List<PersistenceEntry> entries, string scope, RegistryKey key, string location, string name)
    {
        var raw = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (raw is null) return;
        var value = raw switch
        {
            string[] multi => string.Join(" | ", multi),
            byte[] bytes => Convert.ToHexString(bytes),
            _ => raw.ToString() ?? "",
        };
        var target = raw is string s ? PathResolver.ExtractExecutablePath(s) : null;
        entries.Add(new PersistenceEntry(scope, location, name.Length == 0 ? "(Default)" : name, Truncate(value), target));
    }

    private void TryRegistry(string path, Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            logger.LogDebug("Cannot read {Path}: {Message}", path, ex.Message);
        }
    }

    private static IEnumerable<string> LoadedUserSids() =>
        Registry.Users.GetSubKeyNames().Where(n =>
            n.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase) &&
            !n.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase));

    private static string StripSid(string path, string scope) =>
        scope != MachineScope && path.StartsWith(scope + "\\", StringComparison.OrdinalIgnoreCase) ? path[(scope.Length + 1)..] : path;

    private static string AccountName(string sid)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        }
        catch
        {
            return sid;
        }
    }

    // ----------------------------------------------------- startup folders

    private static void AddStartupFolders(List<PersistenceEntry> entries)
    {
        var folders = new List<string>
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)),
        };
        // Read from the registry: when running as SYSTEM, the "user profile" folder is under System32.
        var usersRoot = Environment.ExpandEnvironmentVariables(
            Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
                "ProfilesDirectory", null) as string ?? @"%SystemDrive%\Users");
        try
        {
            foreach (var profile in Directory.EnumerateDirectories(usersRoot))
                folders.Add(Path.Combine(profile, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }

        foreach (var folder in folders.Where(Directory.Exists))
        {
            try
            {
                foreach (var file in new DirectoryInfo(folder).EnumerateFiles("*", new System.IO.EnumerationOptions { AttributesToSkip = 0, IgnoreInaccessible = true }))
                {
                    if (file.Name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    entries.Add(new PersistenceEntry(MachineScope, "Startup folder", file.FullName,
                        $"{file.Length:N0} bytes, modified {file.LastWriteTimeUtc:u}", file.FullName));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    // --------------------------------------------------- WMI subscriptions

    private void AddWmiSubscriptions(List<PersistenceEntry> entries)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();

            foreach (var o in Query(scope, "SELECT Name, Query FROM __EventFilter"))
                entries.Add(new PersistenceEntry(MachineScope, "WMI subscription", $"Filter: {o["Name"]}", Truncate($"{o["Query"]}"), null));

            foreach (var o in Query(scope, "SELECT * FROM __EventConsumer"))
            {
                var cls = o.ClassPath.ClassName;
                string value;
                string? target = null;
                switch (cls)
                {
                    case "CommandLineEventConsumer":
                        var exe = o["ExecutablePath"] as string;
                        var cmd = o["CommandLineTemplate"] as string;
                        value = $"{exe} {cmd}".Trim();
                        target = PathResolver.ExtractExecutablePath(exe) ?? PathResolver.ExtractExecutablePath(cmd);
                        break;
                    case "ActiveScriptEventConsumer":
                        var file = o["ScriptFileName"] as string;
                        value = $"{o["ScriptingEngine"]} {file} {o["ScriptText"]}".Trim();
                        target = PathResolver.ExtractExecutablePath(file);
                        break;
                    default:
                        value = cls;
                        break;
                }
                entries.Add(new PersistenceEntry(MachineScope, "WMI subscription", $"Consumer: {o["Name"]} ({cls})", Truncate(value), target));
            }

            foreach (var o in Query(scope, "SELECT Filter, Consumer FROM __FilterToConsumerBinding"))
            {
                var binding = $"{o["Filter"]} -> {o["Consumer"]}";
                entries.Add(new PersistenceEntry(MachineScope, "WMI subscription", $"Binding: {Truncate(binding)}", Truncate(binding), null));
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            logger.LogDebug("WMI subscription query failed: {Message}", ex.Message);
        }
    }

    private static IEnumerable<ManagementObject> Query(ManagementScope scope, string wql)
    {
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql));
        using var results = searcher.Get();
        foreach (var o in results.OfType<ManagementObject>())
        {
            using (o) yield return o;
        }
    }

    private static string Truncate(string s) => s.Length <= MaxValueLength ? s : s[..MaxValueLength] + "…";
}
