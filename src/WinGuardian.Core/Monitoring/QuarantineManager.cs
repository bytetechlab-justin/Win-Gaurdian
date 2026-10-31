using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using WinGuardian.Core.Data;

namespace WinGuardian.Core.Monitoring;

/// <summary>
/// Moves suspicious files into C:\ProgramData\WinGuardian\Quarantine (SYSTEM/Administrators only).
/// Contents are XOR-encoded with a random per-item key so they cannot be executed or accidentally
/// opened, and so other antivirus products don't repeatedly flag the quarantine folder.
/// </summary>
public sealed class QuarantineManager(GuardianDatabase db, TrustStore trust, EventRecorder events, ILogger<QuarantineManager> logger)
{
    private const int MoveFileDelayUntilReboot = 0x4;

    private static readonly string QuarantineDir = Path.Combine(GuardianPaths.DataDirectory, "Quarantine");

    /// <summary>Removing any of these would leave Windows unbootable.</summary>
    private static readonly HashSet<string> CriticalSystemFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntoskrnl.exe", "hal.dll", "winload.exe", "winload.efi", "ci.dll", "smss.exe", "csrss.exe",
        "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "advapi32.dll", "userinit.exe",
    };

    public QuarantineItem Quarantine(string path, string? reason)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw new FileNotFoundException("The file no longer exists.", full);
        EnsureAllowed(full);

        var killed = KillProcessesRunning(full);
        var sha256 = FileHasher.TryHash(full, long.MaxValue);
        var key = RandomNumberGenerator.GetBytes(32);
        var item = new QuarantineItem
        {
            Id = Guid.NewGuid().ToString("N"),
            OriginalPath = full,
            Sha256 = sha256,
            Size = new FileInfo(full).Length,
            QuarantinedUtc = DateTime.UtcNow,
            Reason = reason,
        };

        Directory.CreateDirectory(QuarantineDir);
        var stored = Path.Combine(QuarantineDir, item.Id + ".bin");
        using (var input = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (var output = new FileStream(stored, FileMode.CreateNew, FileAccess.Write))
            XorCopy(input, output, key);

        try
        {
            File.SetAttributes(full, FileAttributes.Normal);
            File.Delete(full);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Typically a DLL loaded into a process we must not kill. Remove it at the next boot instead.
            if (!MoveFileExW(full, null, MoveFileDelayUntilReboot))
            {
                File.Delete(stored);
                throw new IOException($"The file is in use and could not be scheduled for removal: {ex.Message}", ex);
            }
            item.PendingReboot = true;
        }

        // Forget it in the file baseline so the watcher doesn't report the removal separately.
        if (!item.PendingReboot) db.DeleteFile(full);
        db.InsertQuarantine(item, key);

        events.Record(new GuardianEvent
        {
            Severity = Severity.Info,
            Category = EventCategory.Malware,
            Change = ChangeKind.Removed,
            Subject = $"File quarantined: {full}",
            Details = $"Reason: {reason ?? "(none)"}; SHA256 {sha256}" +
                      (killed > 0 ? $"; terminated {killed} process(es) running it" : "") +
                      (item.PendingReboot ? "; the file is in use and will be deleted at the next reboot" : ""),
            FilePath = full,
            Sha256 = sha256,
        });
        logger.LogWarning("Quarantined {Path} as {Id}", full, item.Id);
        return item;
    }

    /// <summary>Puts the file back where it was and trusts that path so it isn't flagged again.</summary>
    public void Restore(string id)
    {
        var (item, key) = db.GetQuarantineItem(id) ?? throw new KeyNotFoundException("No such quarantine item.");
        if (File.Exists(item.OriginalPath))
            throw new IOException("A file already exists at the original location.");

        var stored = Path.Combine(QuarantineDir, id + ".bin");
        Directory.CreateDirectory(Path.GetDirectoryName(item.OriginalPath)!);
        using (var input = File.OpenRead(stored))
        using (var output = new FileStream(item.OriginalPath, FileMode.CreateNew, FileAccess.Write))
            XorCopy(input, output, key);

        var info = new FileInfo(item.OriginalPath);
        db.UpsertFile(new FileRecord(info.FullName, info.Length, info.LastWriteTimeUtc.Ticks, item.Sha256));
        db.AddTrusted(TrustKind.Path, item.OriginalPath, "Restored from quarantine");
        trust.Invalidate();
        File.Delete(stored);
        db.DeleteQuarantine(id);

        events.Info($"File restored from quarantine: {item.OriginalPath}", "The path has been added to the trusted list.");
    }

    public void Delete(string id)
    {
        var (item, _) = db.GetQuarantineItem(id) ?? throw new KeyNotFoundException("No such quarantine item.");
        var stored = Path.Combine(QuarantineDir, id + ".bin");
        if (File.Exists(stored)) File.Delete(stored);
        db.DeleteQuarantine(id);
        events.Info($"Quarantined file permanently deleted: {item.OriginalPath}", $"SHA256 {item.Sha256}");
    }

    private static void EnsureAllowed(string full)
    {
        if (CriticalSystemFiles.Contains(Path.GetFileName(full)) &&
            full.StartsWith(GuardianPaths.Normalize("%WINDIR%") + "\\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Refusing to quarantine a core Windows file; doing so would break Windows.");

        var installDir = Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd('\\'))!;
        if (full.StartsWith(installDir + "\\", StringComparison.OrdinalIgnoreCase) ||
            full.StartsWith(GuardianPaths.DataDirectory + "\\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Refusing to quarantine WinGuardian's own files.");
    }

    private int KillProcessesRunning(string path)
    {
        var killed = 0;
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (!string.Equals(NativeMethods.TryGetProcessImagePath(p.Id), path, StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    p.Kill();
                    p.WaitForExit(5000);
                    killed++;
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Could not terminate PID {Pid} running {Path}", p.Id, path);
                }
            }
        }
        return killed;
    }

    private static void XorCopy(Stream input, Stream output, byte[] key)
    {
        var buffer = new byte[1 << 16];
        long offset = 0;
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (var i = 0; i < read; i++)
                buffer[i] ^= key[(offset + i) % key.Length];
            output.Write(buffer, 0, read);
            offset += read;
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileExW(string existing, string? newName, int flags);
}
