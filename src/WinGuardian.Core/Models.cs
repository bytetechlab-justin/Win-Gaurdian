namespace WinGuardian.Core;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

public enum EventCategory
{
    System,
    File,
    Process,
    Service,
    Persistence,
    Malware,
    Tamper,
}

public enum ChangeKind
{
    Info,
    Added,
    Removed,
    Modified,
    Detected,
}

/// <summary>A detected change (or informational notice) recorded by the service.</summary>
public sealed class GuardianEvent
{
    public long Id { get; set; }
    public DateTime TimeUtc { get; set; } = DateTime.UtcNow;
    public Severity Severity { get; set; }
    public EventCategory Category { get; set; }
    public ChangeKind Change { get; set; }
    public string Subject { get; set; } = "";
    public string? Details { get; set; }
    public bool Acknowledged { get; set; }

    /// <summary>The file this event is about (the file itself, a process image, or a service/persistence target).</summary>
    public string? FilePath { get; set; }

    public string? Sha256 { get; set; }

    /// <summary>Identifies the item for "trust" when it is not a file: a service name or persistence key.</summary>
    public string? TrustKey { get; set; }

    /// <summary>Human-readable signature status of <see cref="FilePath"/>, e.g. "Signed by Microsoft Windows (catalog)".</summary>
    public string? Signature { get; set; }

    /// <summary>The publisher, only when the signature is valid (used for publisher trust).</summary>
    public string? Signer { get; set; }
}

public sealed record FileRecord(string Path, long Size, long LastWriteTicksUtc, string? Sha256);

public sealed record ProcessSnapshot(int Pid, string Name, string? ImagePath)
{
    /// <summary>Processes are baselined by executable path (PIDs change); protected processes fall back to name.</summary>
    public string Key => ImagePath ?? $"[{Name}]";
}

/// <summary>A process start reported by ETW (or found by polling, in which case the extra fields are empty).</summary>
public sealed record ProcessStart(
    ProcessSnapshot Process,
    int ParentPid,
    string? ParentPath,
    string? CommandLine);

public sealed record ServiceRecord(
    string Name,
    string? DisplayName,
    string? ImagePath,
    string? ServiceDll,
    int Type,
    int Start,
    string? ObjectName)
{
    public bool IsDriver => (Type & 0x0B) != 0 && (Type & 0x30) == 0; // kernel/file-system/recognizer driver

    public static string StartName(int start) => start switch
    {
        0 => "Boot",
        1 => "System",
        2 => "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => $"Unknown({start})",
    };
}

/// <summary>
/// An autostart ("persistence") entry. <see cref="Scope"/> is "machine" or a user SID, so per-user
/// registry hives that are unloaded at logoff are not reported as removed.
/// </summary>
public sealed record PersistenceEntry(string Scope, string Location, string Name, string Value, string? TargetPath)
{
    public string Key => $"{Location}|{Name}";
}

public enum TrustKind
{
    /// <summary>An exact file path (file and process events).</summary>
    Path,
    /// <summary>Everything under a folder (file and process events).</summary>
    Folder,
    /// <summary>A SHA-256 hash, wherever the file is.</summary>
    Hash,
    /// <summary>A service name.</summary>
    Service,
    /// <summary>A persistence entry key.</summary>
    Persistence,
    /// <summary>A suspicious command-line rule when triggered by a specific parent program ("rule|parent path").</summary>
    Behavior,
    /// <summary>Everything with a valid signature from this publisher (certificate subject name).</summary>
    Publisher,
}

public sealed class TrustEntry
{
    public TrustKind Kind { get; set; }
    public string Value { get; set; } = "";
    public DateTime AddedUtc { get; set; }
    public string? Note { get; set; }
}

public sealed class QuarantineItem
{
    public string Id { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public string? Sha256 { get; set; }
    public long Size { get; set; }
    public DateTime QuarantinedUtc { get; set; }
    public string? Reason { get; set; }

    /// <summary>The original could not be deleted (in use) and is scheduled for deletion at the next reboot.</summary>
    public bool PendingReboot { get; set; }
}

public enum ReputationVerdict
{
    NotFound,
    Clean,
    Suspicious,
    Malicious,
    Error,
}

public sealed record ReputationResult(string Provider, ReputationVerdict Verdict, string? Label, string? Detail, string? Link);

/// <summary>Settings changed at runtime from the tray (stored in the protected database, not appsettings.json).</summary>
public sealed class RuntimeSettings
{
    public string? MalwareBazaarApiKey { get; set; }
    public string? VirusTotalApiKey { get; set; }
    public int VirusTotalDailyLimit { get; set; } = 450;
    public bool AutoQuarantineMalicious { get; set; }
    public int EventRetentionDays { get; set; } = 90;
}
