namespace WinGuardian.Core.Tasks;

/// <summary>A scheduled task definition parsed from its XML file in System32\Tasks.</summary>
public sealed class TaskDefinition
{
    public string Path { get; set; } = "";
    public string? Description { get; set; }
    public string? Author { get; set; }
    public string? RegistrationDate { get; set; }
    public string? Source { get; set; }
    public bool Enabled { get; set; } = true;
    public bool Hidden { get; set; }

    public string? UserId { get; set; }
    public string? GroupId { get; set; }
    public string? LogonType { get; set; }
    public string? RunLevel { get; set; }

    /// <summary>Friendly name of the account the actions run as, e.g. "LocalSystem" or "DESKTOP\\Justin".</summary>
    public string ExecutionAccount { get; set; } = "(unspecified)";
    public bool RunsAsSystem { get; set; }

    /// <summary>Runs as SYSTEM/LocalService/NetworkService or with highest privileges.</summary>
    public bool RunsPrivileged { get; set; }

    public List<string> Triggers { get; set; } = [];

    /// <summary>Trigger start/end times only. Windows rewrites these on its own for repeating tasks.</summary>
    public List<string> TriggerBoundaries { get; set; } = [];

    public List<TaskAction> Actions { get; set; } = [];
}

public sealed class TaskAction
{
    /// <summary>Exec, ComHandler, SendEmail or ShowMessage.</summary>
    public string Type { get; set; } = "";
    public string? Command { get; set; }
    public string? Arguments { get; set; }
    public string? WorkingDirectory { get; set; }
    public string? ClassId { get; set; }
    public string? Data { get; set; }

    public string Describe() => Type switch
    {
        "Exec" => $"{Command} {Arguments}".Trim(),
        "ComHandler" => $"COM Handler {ClassId}" + (string.IsNullOrEmpty(Data) ? "" : $" (data: {Data})"),
        _ => Type,
    };
}

/// <summary>Identity and content of a file at a point in time.</summary>
public sealed class FileState
{
    public string Path { get; set; } = "";
    public bool Exists { get; set; }
    public long Size { get; set; }
    public long LastWriteTicksUtc { get; set; }
    public string? Sha256 { get; set; }

    /// <summary>The file changed while it was being read; the hash may not match any single version.</summary>
    public bool Inconsistent { get; set; }

    public bool SameContentAs(FileState? other) =>
        other is not null && Exists == other.Exists && (!Exists || (Sha256 is not null && Sha256 == other.Sha256));
}

/// <summary>Security-relevant facts about an action's target (executable, DLL, COM server).</summary>
public sealed class TargetInfo
{
    public FileState File { get; set; } = new();
    public string? Signature { get; set; }
    public string? SignatureStatus { get; set; }
    public string? Signer { get; set; }
    public bool SignedByMicrosoft { get; set; }

    /// <summary>Under \Users\, \ProgramData\, Temp etc.</summary>
    public bool InUserWritableLocation { get; set; }

    /// <summary>Non-administrative identities that may modify or replace the file (from its ACL and its folder's).</summary>
    public List<string> WritableBy { get; set; } = [];

    /// <summary>For a missing file: identities that could create it (from the folder ACL).</summary>
    public List<string> DirectoryWritableBy { get; set; } = [];

    public bool IsScriptHost { get; set; }
}

public sealed class ComServer
{
    /// <summary>InprocServer32, LocalServer32, LocalService (AppID) or DllSurrogate (AppID).</summary>
    public string RegistrationType { get; set; } = "";
    public string? RawValue { get; set; }
    public string? ServerPath { get; set; }
    public string? ThreadingModel { get; set; }

    /// <summary>For .NET COM classes hosted by mscoree.dll: the assembly that actually runs.</summary>
    public string? ManagedAssembly { get; set; }
}

public sealed class UserComOverride
{
    public string Sid { get; set; } = "";
    public string Account { get; set; } = "";
    public string RegistryLocation { get; set; } = "";
    public ComServer? Server { get; set; }
}

/// <summary>How Windows will resolve a COM class ID to code.</summary>
public sealed class ComResolution
{
    public string ClassId { get; set; } = "";
    public bool Resolved { get; set; }
    public string? RegistryLocation { get; set; }

    /// <summary>"64-bit" or "32-bit" (WOW6432Node).</summary>
    public string? RegistryView { get; set; }

    public string? ClassName { get; set; }

    /// <summary>Class IDs followed through TreatAs redirections, starting with the original.</summary>
    public List<string> TreatAsChain { get; set; } = [];

    public string? AppId { get; set; }
    public string? AppIdLocalService { get; set; }
    public string? AppIdDllSurrogate { get; set; }
    public string? AppIdRunAs { get; set; }
    public ComServer? Server { get; set; }

    /// <summary>Per-user registrations that shadow the machine-wide one for that user's processes.</summary>
    public List<UserComOverride> UserOverrides { get; set; } = [];

    public string? Error { get; set; }

    /// <summary>Everything that decides which code runs; a different fingerprint means a redirection.</summary>
    public string Fingerprint() =>
        string.Join("|",
            RegistryView, string.Join(">", TreatAsChain), Server?.RegistrationType, Server?.ServerPath?.ToUpperInvariant(),
            Server?.ManagedAssembly, AppIdLocalService, AppIdDllSurrogate,
            string.Join(";", UserOverrides.OrderBy(o => o.Sid).Select(o => $"{o.Sid}={o.Server?.ServerPath?.ToUpperInvariant()}")));

    public string Describe() =>
        !Resolved ? $"{ClassId}: unresolved ({Error ?? "not registered"})"
        : $"{ClassId} -> {Server?.ServerPath ?? Server?.RawValue ?? AppIdLocalService ?? "(no server)"} ({Server?.RegistrationType}, {RegistryView})" +
          (TreatAsChain.Count > 1 ? $" via TreatAs {string.Join(" > ", TreatAsChain.Skip(1))}" : "") +
          (UserOverrides.Count > 0 ? $"; per-user override for {string.Join(", ", UserOverrides.Select(o => o.Account))}" : "");
}

/// <summary>An action together with what it resolves to.</summary>
public sealed class ActionState
{
    public TaskAction Action { get; set; } = new();
    public string? ResolvedPath { get; set; }
    public TargetInfo? Target { get; set; }
    public ComResolution? Com { get; set; }
}

/// <summary>Everything stored about a task between checks.</summary>
public sealed class TaskState
{
    public string Path { get; set; } = "";
    public FileState File { get; set; } = new();
    public TaskDefinition? Definition { get; set; }
    public string? ParseError { get; set; }
    public List<ActionState> Actions { get; set; } = [];
    public DateTime AnalyzedUtc { get; set; }
}

public sealed class RiskIndicator
{
    public string Id { get; set; } = "";
    public int Weight { get; set; }
    public string Explanation { get; set; } = "";
}

public sealed class TaskComparison
{
    /// <summary>False when there is no earlier record of this task to compare with.</summary>
    public bool BaselineAvailable { get; set; }
    public string? PreviousTaskSha256 { get; set; }
    public bool? TaskFileContentChanged { get; set; }
    public bool? DefinitionChanged { get; set; }
    public bool? MetadataOnly { get; set; }
    public bool? ScheduleTimingOnly { get; set; }
    public bool? ActionsChanged { get; set; }
    public bool? PrincipalChanged { get; set; }
    public bool? TriggersChanged { get; set; }
    public bool? EnabledChanged { get; set; }
    public bool? ComRegistrationChanged { get; set; }
    public bool? TargetContentChanged { get; set; }
    public List<string> ChangedFields { get; set; } = [];
    public List<string> PreviousActions { get; set; } = [];
    public List<string> CurrentActions { get; set; } = [];
    public List<string> PreviousComTargets { get; set; } = [];
    public List<string> CurrentComTargets { get; set; } = [];
}

public sealed class ProcessAttribution
{
    public bool Available { get; set; }
    public string? Source { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessPath { get; set; }
    public int? ParentProcessId { get; set; }
    public DateTime? ProcessStartUtc { get; set; }
    public string? ProcessSigner { get; set; }
    public string? CommandLine { get; set; }
    public string? User { get; set; }
    public string? Note { get; set; }
}

public sealed class TaskAssessment
{
    public int Score { get; set; }
    public Severity Severity { get; set; }
    public string Verdict { get; set; } = "";
    public List<RiskIndicator> Indicators { get; set; } = [];
    public string Basis { get; set; } = "";
    public string Explanation { get; set; } = "";
}

/// <summary>The full result attached to a scheduled-task event (serialized as JSON for the details window).</summary>
public sealed class TaskAnalysis
{
    public string Kind => "ScheduledTask";
    public string Task { get; set; } = "";
    public string Change { get; set; } = "";
    public string Trigger { get; set; } = "";
    public DateTime TimeUtc { get; set; } = DateTime.UtcNow;
    public string? TaskFile { get; set; }
    public string? TaskSha256 { get; set; }
    public TaskDefinition? Configuration { get; set; }
    public string? ParseError { get; set; }
    public List<ActionState> Actions { get; set; } = [];
    public TaskComparison Comparison { get; set; } = new();
    public ProcessAttribution ModifyingProcess { get; set; } = new();
    public TaskAssessment Assessment { get; set; } = new();
}
