namespace WinGuardian.Core.Analysis;

public enum AnalysisState
{
    /// <summary>The program (or something it started) is still running and being recorded.</summary>
    Running,

    /// <summary>Every recorded process has exited.</summary>
    Finished,

    /// <summary>The user stopped recording (the program may still be running).</summary>
    Stopped,
}

public enum FileOperation
{
    Created,
    FolderCreated,
    Modified,
    Deleted,
    Renamed,

    /// <summary>Opened without a recorded change (reading, loading a DLL, checking it exists...).</summary>
    Opened,
}

public enum RegistryOperation
{
    KeyCreated,
    ValueSet,
    ValueDeleted,
    KeyDeleted,

    /// <summary>Opened or read without a recorded change.</summary>
    KeyOpened,
}

/// <summary>Everything one monitored run of a program (and every process it started) did.</summary>
public sealed class AnalysisReport
{
    public string Id { get; set; } = "";
    public AnalysisState State { get; set; }
    public DateTime StartedUtc { get; set; }
    public DateTime? EndedUtc { get; set; }
    public int RootPid { get; set; }
    public string? ProgramPath { get; set; }
    public string? CommandLine { get; set; }

    /// <summary>Events seen for the monitored processes (before de-duplication).</summary>
    public long EventCount { get; set; }

    /// <summary>Some activity was not kept because a per-run limit was reached.</summary>
    public bool Truncated { get; set; }

    /// <summary>Read-only activity (files opened, registry keys opened) was left out of this response.</summary>
    public bool ReadsOmitted { get; set; }

    public List<AnalysisProcess> Processes { get; set; } = [];
    public List<FileActivity> Files { get; set; } = [];
    public List<RegistryActivity> Registry { get; set; } = [];
    public List<NetworkActivity> Network { get; set; } = [];
    public List<DnsActivity> Dns { get; set; } = [];

    /// <summary>
    /// Other WinGaurdian alerts raised while the program ran: changes made indirectly (through a service,
    /// WMI, the Task Scheduler...) do not happen inside the monitored processes, but are still caught here.
    /// </summary>
    public List<GuardianEvent> RelatedEvents { get; set; } = [];
}

public sealed class AnalysisProcess
{
    public int Pid { get; set; }
    public int ParentPid { get; set; }
    public string? ImagePath { get; set; }
    public string? CommandLine { get; set; }
    public DateTime StartedUtc { get; set; }
    public DateTime? ExitedUtc { get; set; }
    public int? ExitCode { get; set; }
    public bool Elevated { get; set; }
    public string? Signature { get; set; }
    public Severity Severity { get; set; }
    public string? Reason { get; set; }

    internal AnalysisProcess Copy() => (AnalysisProcess)MemberwiseClone();
}

/// <summary>Shared by every kind of recorded activity.</summary>
public abstract class ActivityBase
{
    public int Pid { get; set; }
    public string ProcessName { get; set; } = "";
    public DateTime FirstUtc { get; set; }
    public DateTime LastUtc { get; set; }
    public int Count { get; set; }
    public Severity Severity { get; set; }

    /// <summary>Why this was flagged (null for ordinary activity).</summary>
    public string? Reason { get; set; }

    internal ActivityBase Copy() => (ActivityBase)MemberwiseClone();
}

public sealed class FileActivity : ActivityBase
{
    public string Path { get; set; } = "";
    public FileOperation Operation { get; set; }

    /// <summary>Bytes written (Modified).</summary>
    public long Bytes { get; set; }

    /// <summary>The other name for a rename.</summary>
    public string? Detail { get; set; }
}

public sealed class RegistryActivity : ActivityBase
{
    /// <summary>Friendly key path, e.g. HKCU\Software\Microsoft\Windows\CurrentVersion\Run.</summary>
    public string Key { get; set; } = "";
    public string? ValueName { get; set; }
    public RegistryOperation Operation { get; set; }
    public string? ValueType { get; set; }

    /// <summary>The value written (most recent), formatted for display.</summary>
    public string? Data { get; set; }

    /// <summary>Set when Windows refused the change (e.g. "access denied").</summary>
    public string? Failure { get; set; }
}

public sealed class NetworkActivity : ActivityBase
{
    public string Protocol { get; set; } = "";
    public string RemoteAddress { get; set; } = "";

    /// <summary>The remote port; for <see cref="Inbound"/> connections, the program's own listening port.</summary>
    public int RemotePort { get; set; }

    /// <summary>Host name the program looked up that resolved to <see cref="RemoteAddress"/>.</summary>
    public string? HostName { get; set; }

    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public int Attempts { get; set; }
    public int Failures { get; set; }

    /// <summary>The remote side connected to the program (it is acting as a server).</summary>
    public bool Inbound { get; set; }
}

public sealed class DnsActivity : ActivityBase
{
    public string Name { get; set; } = "";
    public string QueryType { get; set; } = "";
    public string? Results { get; set; }
    public bool Failed { get; set; }
}
