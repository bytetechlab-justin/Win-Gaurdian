using System.Security.AccessControl;
using System.Security.Principal;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Core.Tasks;

/// <summary>Hashes, signature-checks and ACL-checks the file an action runs. Never executes it.</summary>
public static class TargetInspector
{
    private const long MaxHashBytes = 512L * 1024 * 1024;

    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "conhost.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "forfiles.exe",
    };

    /// <summary>Accounts whose write access is expected and not a risk.</summary>
    private static readonly HashSet<string> PrivilegedSids =
    [
        "S-1-5-18",                                                        // SYSTEM
        "S-1-5-32-544",                                                    // Administrators
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
        "S-1-3-0",                                                         // CREATOR OWNER (applies to children only)
    ];

    private const FileSystemRights ModifyRights =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    private const FileSystemRights ReplaceViaFolderRights =
        FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    private const FileSystemRights CreateInFolderRights =
        FileSystemRights.CreateFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    public static bool IsScriptHost(string? path) => path is not null && ScriptHosts.Contains(Path.GetFileName(path));

    public static TargetInfo Inspect(string path)
    {
        var info = new TargetInfo
        {
            File = ReadFileState(path),
            InUserWritableLocation = SeverityRules.IsUserWritable(path),
            IsScriptHost = IsScriptHost(path),
        };

        var directory = Path.GetDirectoryName(path);
        if (info.File.Exists)
        {
            var signature = SignatureVerifier.Verify(path);
            info.Signature = signature.Describe();
            info.SignatureStatus = signature.Status.ToString();
            info.Signer = signature.IsValid ? signature.Signer : null;
            info.SignedByMicrosoft = signature.IsMicrosoft;
            info.WritableBy = UnprivilegedWriters(path, isDirectory: false, ModifyRights)
                .Union(directory is null ? [] : UnprivilegedWriters(directory, isDirectory: true, ReplaceViaFolderRights))
                .Distinct().ToList();
        }
        else if (directory is not null)
        {
            // A missing target in a folder ordinary users can write to can be planted ("phantom" hijack).
            info.DirectoryWritableBy = UnprivilegedWriters(NearestExistingDirectory(directory), isDirectory: true, CreateInFolderRights);
        }
        return info;
    }

    /// <summary>
    /// Size, timestamp and SHA-256. If the file changes while being hashed it is re-read once, and marked
    /// inconsistent if it is still changing.
    /// </summary>
    public static FileState ReadFileState(string path)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var before = new FileInfo(path);
            if (!before.Exists) return new FileState { Path = path, Exists = false };
            var size = before.Length;
            var mtime = before.LastWriteTimeUtc.Ticks;

            var hash = FileHasher.TryHash(path, MaxHashBytes);
            var after = new FileInfo(path);
            if (after.Exists && after.Length == size && after.LastWriteTimeUtc.Ticks == mtime)
                return new FileState { Path = path, Exists = true, Size = size, LastWriteTicksUtc = mtime, Sha256 = hash };
            if (attempt == 1)
                return new FileState { Path = path, Exists = after.Exists, Size = size, LastWriteTicksUtc = mtime, Sha256 = hash, Inconsistent = true };
        }
        return new FileState { Path = path };
    }

    /// <summary>Quick check whether a tracked file changed since <paramref name="previous"/> (no hashing).</summary>
    public static bool LooksChanged(FileState previous)
    {
        var now = new FileInfo(previous.Path);
        if (now.Exists != previous.Exists) return true;
        return now.Exists && (now.Length != previous.Size || now.LastWriteTimeUtc.Ticks != previous.LastWriteTicksUtc);
    }

    /// <summary>
    /// Non-administrative identities granted any of <paramref name="rights"/> by allow rules. Deny rules are
    /// not subtracted, so this can over-report in unusual ACLs, but never under-reports.
    /// </summary>
    public static List<string> UnprivilegedWriters(string path, bool isDirectory, FileSystemRights rights)
    {
        try
        {
            FileSystemSecurity security = isDirectory
                ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access)
                : new FileInfo(path).GetAccessControl(AccessControlSections.Access);

            return security.GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .Where(r => r.AccessControlType == AccessControlType.Allow && (r.FileSystemRights & rights) != 0 &&
                            !r.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)) // inherit-only entries apply to children, not this object
                .Select(r => (SecurityIdentifier)r.IdentityReference)
                .Where(sid => !PrivilegedSids.Contains(sid.Value) && !IsServiceSid(sid))
                .Select(Name)
                .Distinct()
                .ToList();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            return [];
        }
    }

    private static bool IsServiceSid(SecurityIdentifier sid) => sid.Value.StartsWith("S-1-5-80-", StringComparison.Ordinal);

    private static string NearestExistingDirectory(string directory)
    {
        var current = directory;
        while (!string.IsNullOrEmpty(current) && !Directory.Exists(current))
            current = Path.GetDirectoryName(current);
        return current ?? directory;
    }

    private static string Name(SecurityIdentifier sid)
    {
        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch
        {
            return sid.Value;
        }
    }
}
