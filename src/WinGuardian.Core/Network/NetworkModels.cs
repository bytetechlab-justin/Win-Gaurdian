namespace WinGuardian.Core.Network;

/// <summary>A socket from the Windows TCP/UDP tables, enriched with the owning process and services.</summary>
public sealed class NetworkEndpoint
{
    public string Protocol { get; set; } = "";
    public string LocalAddress { get; set; } = "";
    public int LocalPort { get; set; }
    public string? RemoteAddress { get; set; }
    public int? RemotePort { get; set; }
    public string? State { get; set; }
    public int Pid { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ProcessPath { get; set; }

    /// <summary>Windows services hosted in the owning process (e.g. several in one svchost.exe).</summary>
    public string? Services { get; set; }

    public string? Signature { get; set; }
    public string? Signer { get; set; }
    public bool SignedByMicrosoft { get; set; }
    public bool InUserWritableLocation { get; set; }

    /// <summary>For listeners: when this program was first seen listening on this port.</summary>
    public DateTime? FirstSeenUtc { get; set; }

    public bool IsLoopbackOnly => LocalAddress is "127.0.0.1" or "::1";
    public bool IsAllInterfaces => LocalAddress is "0.0.0.0" or "::";
}

/// <summary>A program talking to a remote address/port, aggregated over time.</summary>
public sealed class ConnectionHistoryEntry
{
    public string Protocol { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public string? ProcessPath { get; set; }
    public string? Services { get; set; }
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public int TimesSeen { get; set; }
}

public sealed class FirewallProfileState
{
    public string Name { get; set; } = "";
    public bool Enabled { get; set; }
    public bool SetByGroupPolicy { get; set; }
    public string DefaultInbound { get; set; } = "";
    public string DefaultOutbound { get; set; } = "";
}

public sealed class FirewallRule
{
    /// <summary>Registry value name (unique per source).</summary>
    public string Id { get; set; } = "";

    /// <summary>"Local" or "Group Policy".</summary>
    public string Source { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public string Direction { get; set; } = "";
    public string Action { get; set; } = "";
    public bool Enabled { get; set; }
    public string Protocol { get; set; } = "Any";
    public string? LocalPorts { get; set; }
    public string? RemotePorts { get; set; }
    public string? RemoteAddresses { get; set; }
    public string? Program { get; set; }
    public string? Service { get; set; }
    public string? Package { get; set; }
    public string Profiles { get; set; } = "All";
    public string Raw { get; set; } = "";

    public string Key => $"{Source}|{Id}";
    public bool AllowsInbound => Enabled && Action == "Allow" && Direction == "In";

    public string Describe() =>
        $"{(Enabled ? "" : "(disabled) ")}{Action} {Direction} {Protocol}" +
        (LocalPorts is null ? "" : $" local port {LocalPorts}") +
        (RemotePorts is null ? "" : $" remote port {RemotePorts}") +
        (Program is null ? "" : $" program {Program}") +
        (Service is null ? "" : $" service {Service}") +
        (Package is null ? "" : $" app package") +
        $" [{Profiles}]";
}

public sealed class FirewallStatus
{
    public bool ServiceRunning { get; set; }
    public List<FirewallProfileState> Profiles { get; set; } = [];
    public int RuleCount { get; set; }
    public int InboundAllowRuleCount { get; set; }
}

/// <summary>Everything the Firewall tab shows.</summary>
public sealed class NetworkSnapshot
{
    public DateTime CapturedUtc { get; set; } = DateTime.UtcNow;
    public FirewallStatus Firewall { get; set; } = new();
    public List<NetworkEndpoint> Listeners { get; set; } = [];
    public List<NetworkEndpoint> Connections { get; set; } = [];
    public List<ConnectionHistoryEntry> History { get; set; } = [];
    public List<FirewallRule> Rules { get; set; } = [];
}
