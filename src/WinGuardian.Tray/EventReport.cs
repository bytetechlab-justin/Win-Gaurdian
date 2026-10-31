using WinGuardian.Core;
using WinGuardian.Core.Network;
using WinGuardian.Core.Tasks;

namespace WinGuardian.Tray;

/// <summary>Readable text descriptions of events and Firewall-tab entries (details window, copy, Ask Gemini).</summary>
internal static class EventReport
{
    public static string Build(GuardianEvent e)
    {
        if (TaskAnalysisFormatter.TryParse(e.Analysis) is { } analysis)
            return TaskAnalysisFormatter.Format(e, analysis);

        return $"EVENT #{e.Id}\nSeverity: {e.Severity}\nType: {e.Category} {e.Change}\n\n" +
               $"Subject:\n  {e.Subject}\n\nTimestamp:\n  {e.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}\n\n" +
               $"Details:\n  {e.Details}\n" +
               (e.FilePath is null ? "" : $"\nFile:\n  {e.FilePath}\n") +
               (e.Signature is null ? "" : $"\nDigital Signature:\n  {e.Signature}\n") +
               (e.Sha256 is null ? "" : $"\nSHA-256:\n  {e.Sha256}\n");
    }

    public static string Build(NetworkEndpoint e) =>
        $"{(e.RemoteAddress is null ? "LISTENING PORT" : "NETWORK CONNECTION")}\n" +
        $"Protocol: {e.Protocol}\n" +
        $"Local: {e.LocalAddress}:{e.LocalPort}" +
        (e.RemoteAddress is null ? $" ({(e.IsLoopbackOnly ? "reachable from this computer only" : e.IsAllInterfaces ? "reachable on all network interfaces" : "one interface")})" : "") + "\n" +
        (e.RemoteAddress is null ? "" : $"Remote: {e.RemoteAddress}:{e.RemotePort}\nState: {e.State}\n") +
        $"Program: {e.ProcessName} (PID {e.Pid})\n" +
        $"Path: {e.ProcessPath ?? "(not available)"}\n" +
        $"Windows services in this process: {e.Services ?? "(none)"}\n" +
        $"Digital signature: {e.Signature ?? "(unknown)"}\n" +
        (e.InUserWritableLocation ? "Note: the program runs from a user-writable folder.\n" : "") +
        (e.FirstSeenUtc is { } seen ? $"First seen listening here: {seen.ToLocalTime():g}\n" : "");

    public static string Build(ConnectionHistoryEntry h) =>
        "CONNECTION HISTORY ENTRY\n" +
        $"Program: {h.ProcessName}\nPath: {h.ProcessPath ?? "(not available)"}\n" +
        $"Windows services in this process: {h.Services ?? "(none)"}\n" +
        $"Remote: {h.RemoteAddress}:{h.RemotePort} ({h.Protocol})\n" +
        $"First seen: {h.FirstSeenUtc.ToLocalTime():g}; last seen: {h.LastSeenUtc.ToLocalTime():g}; seen {h.TimesSeen} times\n";

    public static string Build(FirewallRule r) =>
        "WINDOWS FIREWALL RULE\n" +
        $"Name: {r.Name}\n" +
        (r.Description is null ? "" : $"Description: {r.Description}\n") +
        $"Summary: {r.Describe()}\n" +
        $"Allows inbound connections: {(r.AllowsInbound ? "yes" : "no")}\n" +
        $"Source: {r.Source} rule\n" +
        $"Rule definition: {r.Raw}\n";
}
