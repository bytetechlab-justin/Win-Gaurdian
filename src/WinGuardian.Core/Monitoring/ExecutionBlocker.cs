using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WinGuardian.Core.Data;
using WinGuardian.Core.Ipc;

namespace WinGuardian.Core.Monitoring;

public sealed class BlockedService
{
    public string Name { get; set; } = "";
    public int PreviousStart { get; set; }
    public bool PreviousDelayedAutoStart { get; set; }
}

public sealed class BlockedItem
{
    public string Id { get; set; } = "";
    public string Path { get; set; } = "";
    public string? Sha256 { get; set; }
    public DateTime AddedUtc { get; set; }
    public string? Reason { get; set; }

    /// <summary>The "deny execute" entry is on the file (false: blocked by termination only, e.g. TrustedInstaller-owned files).</summary>
    public bool AclApplied { get; set; }

    /// <summary>Services that ran this file, stopped and disabled by the block (restored on unblock).</summary>
    public List<BlockedService> Services { get; set; } = [];
}

/// <summary>
/// Keeps blocked programs from running, in three layers:
/// 1. a "deny Execute to Everyone" entry on the file — Windows itself then refuses to start it as a
///    process or load it as a DLL (works on every Windows edition, no driver needed);
/// 2. services that run the file are stopped and disabled (their start type is restored on unblock);
/// 3. any process started from the file — or a renamed copy with the same SHA-256 — is terminated as soon
///    as it is seen (ETW), as a backstop if the file's permissions are reset or it is copied elsewhere.
/// While WinGaurdian is turned off (<see cref="GuardianState.ProtectionOff"/>), nothing is terminated and a removed
/// deny-execute entry is not put back; the entries already on blocked files stay. Explicit Block/Unblock still work.
/// </summary>
public sealed class ExecutionBlocker(GuardianDatabase db, EventRecorder events, GuardianState state, ILogger<ExecutionBlocker> logger)
{
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);
    private static readonly TimeSpan RepeatSuppression = TimeSpan.FromMinutes(1);

    private readonly Lock _gate = new();
    private readonly Dictionary<string, DateTime> _recentKills = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string>? _paths;
    private HashSet<string>? _hashes;

    public List<BlockedItem> List() => db.GetBlocked().Select(Deserialize).ToList();

    public bool IsBlockedPath(string? path)
    {
        if (path is null) return false;
        lock (_gate) return Paths().Contains(path);
    }

    public bool IsBlockedHash(string? sha256)
    {
        if (sha256 is null) return false;
        lock (_gate) return Hashes().Contains(sha256);
    }

    // ------------------------------------------------------------------ block

    public BlockedItem Block(string path, string? reason)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw new FileNotFoundException("The file does not exist.", full);
        EnsureAllowed(full);
        if (IsBlockedPath(full)) throw new InvalidOperationException("This file is already blocked.");

        var item = new BlockedItem
        {
            Id = Guid.NewGuid().ToString("N"),
            Path = full,
            Sha256 = FileHasher.TryHash(full, long.MaxValue),
            AddedUtc = DateTime.UtcNow,
            Reason = reason,
        };

        // Services first (stopping them releases the file), then running processes, then the file itself.
        foreach (var service in ServicesUsing(full))
            item.Services.Add(DisableService(service));
        var killed = KillRunning(full);
        item.AclApplied = TryDenyExecute(full);

        db.InsertBlocked(item.Id, item.Path, JsonSerializer.Serialize(item));
        Invalidate();

        events.Record(new GuardianEvent
        {
            Severity = Severity.Info,
            Category = EventCategory.Process,
            Change = ChangeKind.Info,
            Subject = $"Program blocked: {full}",
            Details = $"Reason: {reason ?? "(none)"}; " +
                      (item.AclApplied ? "Windows will refuse to run it (deny-execute permission set)" : "its permissions could not be changed, so it will be terminated whenever it starts") +
                      (killed > 0 ? $"; terminated {killed} running process(es)" : "") +
                      (item.Services.Count > 0 ? $"; stopped and disabled service(s): {string.Join(", ", item.Services.Select(s => s.Name))}" : "") +
                      $"; SHA256 {item.Sha256}",
            FilePath = full,
            Sha256 = item.Sha256,
        });
        logger.LogWarning("Blocked {Path}", full);
        return item;
    }

    public BlockedItem Unblock(string id)
    {
        var json = db.GetBlocked().FirstOrDefault(j => Deserialize(j).Id == id)
                   ?? throw new KeyNotFoundException("No such blocked item.");
        var item = Deserialize(json);

        if (File.Exists(item.Path)) RemoveDenyExecute(item.Path);
        foreach (var service in item.Services) RestoreService(service);
        db.DeleteBlocked(id);
        Invalidate();

        events.Info($"Program unblocked: {item.Path}",
            item.Services.Count > 0 ? $"Restored the start type of: {string.Join(", ", item.Services.Select(s => s.Name))} (not started automatically)." : null);
        return item;
    }

    // ---------------------------------------------------------------- enforcement

    /// <summary>Called for every process start. Returns true if the process was blocked (terminated).</summary>
    public bool Enforce(ProcessStart start, string? sha256)
    {
        if (state.ProtectionOff) return false;
        var p = start.Process;
        var byPath = IsBlockedPath(p.ImagePath);
        if (!byPath && !IsBlockedHash(sha256)) return false;

        var terminated = Kill(p.Pid);
        bool report;
        lock (_gate)
        {
            var key = p.ImagePath ?? p.Name;
            report = !_recentKills.TryGetValue(key, out var last) || DateTime.UtcNow - last > RepeatSuppression;
            _recentKills[key] = DateTime.UtcNow;
        }
        if (report)
        {
            events.Record(new GuardianEvent
            {
                Severity = Severity.Medium,
                Category = EventCategory.Process,
                Change = ChangeKind.Detected,
                Subject = $"Blocked program started{(byPath ? "" : " (renamed copy)")}: {p.ImagePath ?? p.Name}",
                Details = $"PID {p.Pid} {(terminated ? "was terminated" : "could not be terminated")}; " +
                          $"parent {start.ParentPath ?? "(unknown)"} (PID {start.ParentPid}); command line: {start.CommandLine ?? "(not captured)"}" +
                          (byPath ? "" : $"; same content (SHA256 {sha256}) as a blocked file"),
                FilePath = p.ImagePath,
                Sha256 = sha256,
            });
        }
        return true;
    }

    /// <summary>
    /// Periodic check: puts the deny-execute entry back if someone removed it, and terminates anything
    /// running from a blocked file (covers processes started while ETW was unavailable).
    /// </summary>
    public void Verify()
    {
        if (state.ProtectionOff) return;
        foreach (var item in List())
        {
            if (!File.Exists(item.Path)) continue;
            if (item.AclApplied && !HasDenyExecute(item.Path) && TryDenyExecute(item.Path))
            {
                events.Record(new GuardianEvent
                {
                    Severity = Severity.Medium,
                    Category = EventCategory.Tamper,
                    Change = ChangeKind.Modified,
                    Subject = $"Block on {item.Path} was removed by someone; re-applied",
                    Details = "The file's deny-execute permission had been taken off. WinGaurdian has put it back.",
                    FilePath = item.Path,
                });
            }
            KillRunning(item.Path);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static void EnsureAllowed(string full)
    {
        QuarantineManager.EnsureNotProtected(full);
        // The .NET runtime and anything loaded in this process are needed by WinGaurdian itself.
        var dotnet = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet");
        if (full.StartsWith(dotnet + "\\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Refusing to block the .NET runtime that WinGaurdian runs on.");
        using var self = Process.GetCurrentProcess();
        if (self.Modules.Cast<ProcessModule>().Any(m => string.Equals(m.FileName, full, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Refusing to block a file WinGaurdian itself depends on.");
    }

    private static bool TryDenyExecute(string path)
    {
        try
        {
            var info = new FileInfo(path);
            var security = info.GetAccessControl(AccessControlSections.Access);
            security.AddAccessRule(new FileSystemAccessRule(Everyone, FileSystemRights.ExecuteFile, AccessControlType.Deny));
            info.SetAccessControl(security);
            return HasDenyExecute(path);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            return false;
        }
    }

    private void RemoveDenyExecute(string path)
    {
        try
        {
            var info = new FileInfo(path);
            var security = info.GetAccessControl(AccessControlSections.Access);
            security.RemoveAccessRuleSpecific(new FileSystemAccessRule(Everyone, FileSystemRights.ExecuteFile, AccessControlType.Deny));
            info.SetAccessControl(security);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            logger.LogWarning(ex, "Could not remove the deny-execute entry from {Path}", path);
        }
    }

    public static bool HasDenyExecute(string path)
    {
        try
        {
            return new FileInfo(path).GetAccessControl(AccessControlSections.Access)
                .GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Any(r => r.AccessControlType == AccessControlType.Deny && r.IdentityReference.Equals(Everyone) &&
                          r.FileSystemRights.HasFlag(FileSystemRights.ExecuteFile));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    private int KillRunning(string path)
    {
        var killed = 0;
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (string.Equals(NativeMethods.TryGetProcessImagePath(p.Id), path, StringComparison.OrdinalIgnoreCase) && Kill(p.Id))
                    killed++;
            }
        }
        return killed;
    }

    private bool Kill(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            p.Kill();
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            logger.LogDebug("Could not terminate PID {Pid}: {Message}", pid, ex.Message);
            return false;
        }
    }

    /// <summary>Services whose program (or svchost ServiceDll) is <paramref name="path"/>.</summary>
    public static List<string> ServicesUsing(string path)
    {
        var result = new List<string>();
        using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (root is null) return result;
        foreach (var name in root.GetSubKeyNames())
        {
            try
            {
                using var key = root.OpenSubKey(name);
                if (key?.GetValue("Type") is not int type || (type & 0x30) == 0) continue; // Win32 services only
                using var parameters = key.OpenSubKey("Parameters");
                var dll = parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                var image = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                var target = PathResolver.ExtractExecutablePath(dll) ?? PathResolver.ExtractExecutablePath(image);
                if (string.Equals(target, path, StringComparison.OrdinalIgnoreCase)) result.Add(name);
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
            }
        }
        return result;
    }

    private BlockedService DisableService(string name)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}");
        var service = new BlockedService
        {
            Name = name,
            PreviousStart = key?.GetValue("Start") as int? ?? 3,
            PreviousDelayedAutoStart = (key?.GetValue("DelayedAutostart") as int? ?? 0) != 0,
        };
        Sc($"stop \"{name}\"");
        for (var i = 0; i < 30 && ServiceInfo.GetState(name) == ServiceInfo.State.Running; i++) Thread.Sleep(500);
        Sc($"config \"{name}\" start= disabled");
        return service;
    }

    private void RestoreService(BlockedService service)
    {
        var start = service.PreviousStart switch
        {
            0 => "boot",
            1 => "system",
            2 => service.PreviousDelayedAutoStart ? "delayed-auto" : "auto",
            4 => "disabled",
            _ => "demand",
        };
        Sc($"config \"{service.Name}\" start= {start}");
    }

    private void Sc(string arguments)
    {
        using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"), arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
        })!;
        p.WaitForExit(20_000);
        if (p.ExitCode != 0) logger.LogWarning("sc.exe {Args} exited with {Code}", arguments, p.ExitCode);
    }

    private HashSet<string> Paths() => _paths ??= List().Select(i => i.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);

    private HashSet<string> Hashes() => _hashes ??= List().Select(i => i.Sha256).OfType<string>().ToHashSet(StringComparer.OrdinalIgnoreCase);

    private void Invalidate()
    {
        lock (_gate)
        {
            _paths = null;
            _hashes = null;
        }
    }

    private static BlockedItem Deserialize(string json) => JsonSerializer.Deserialize<BlockedItem>(json)!;
}
