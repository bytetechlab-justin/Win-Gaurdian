using System.Text;

namespace WinGuardian.Core.Analysis;

/// <summary>Plain-text versions of a program analysis: the findings summary, exports, and Ask Gemini.</summary>
public static class AnalysisReportFormatter
{
    public sealed record Finding(Severity Severity, string Area, string Text, string Reason);

    /// <summary>Everything rated Medium or higher, most serious first, plus whole-run patterns.</summary>
    public static List<Finding> Findings(AnalysisReport r)
    {
        var findings = new List<Finding>();

        var damaged = r.Files
            .Where(f => f.Operation is FileOperation.Modified or FileOperation.Deleted or FileOperation.Renamed && BehaviorRules.IsUserDocument(f.Path))
            .Select(f => f.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        if (damaged >= BehaviorRules.RansomwareDocumentThreshold)
            findings.Add(new(Severity.High, "Files", $"Changed, renamed or deleted {damaged} of your documents/photos",
                "Mass changes to personal files is how ransomware behaves"));

        findings.AddRange(r.Processes.Where(p => p.Severity >= Severity.Medium)
            .Select(p => new Finding(p.Severity, "Process", $"{Name(p.ImagePath)} (PID {p.Pid}): {p.CommandLine ?? p.ImagePath}", p.Reason ?? "")));
        findings.AddRange(r.Registry.Where(a => a.Severity >= Severity.Medium)
            .Select(a => new Finding(a.Severity, "Registry", DescribeRegistry(a), a.Reason ?? "")));
        findings.AddRange(r.Files.Where(a => a.Severity >= Severity.Medium)
            .Select(a => new Finding(a.Severity, "File", $"{a.Operation} {a.Path}{(a.Detail is null ? "" : $" ({a.Detail})")}", a.Reason ?? "")));
        findings.AddRange(r.Network.Where(a => a.Severity >= Severity.Medium)
            .Select(a => new Finding(a.Severity, "Network", DescribeConnection(a), a.Reason ?? "")));
        findings.AddRange(r.Dns.Where(a => a.Severity >= Severity.Medium)
            .Select(a => new Finding(a.Severity, "DNS", $"Looked up {a.Name}", a.Reason ?? "")));
        findings.AddRange(r.RelatedEvents.Where(e => e.Severity >= Severity.Medium)
            .Select(e => new Finding(e.Severity, "Alert", $"#{e.Id} {e.Subject}", "WinGaurdian alert raised while the program ran")));

        return findings.OrderByDescending(f => f.Severity).ToList();
    }

    public static string DescribeRegistry(RegistryActivity a)
    {
        var text = a.Operation switch
        {
            RegistryOperation.ValueSet => $"Set {a.Key}\\{ValueLabel(a.ValueName)}" + (a.Data is null ? "" : $" = {a.Data}"),
            RegistryOperation.ValueDeleted => $"Deleted value {a.Key}\\{ValueLabel(a.ValueName)}",
            RegistryOperation.KeyCreated => $"Created key {a.Key}",
            RegistryOperation.KeyDeleted => $"Deleted key {a.Key}",
            _ => $"Opened {a.Key}",
        };
        return a.Failure is null ? text : $"{text}  [FAILED: {a.Failure}]";
    }

    public static string DescribeConnection(NetworkActivity a) =>
        (a.Inbound ? $"Accepted {a.Protocol} connection from {a.RemoteAddress} on local port {a.RemotePort}"
                   : $"{a.Protocol} to {a.HostName ?? a.RemoteAddress}{(a.HostName is null ? "" : $" ({a.RemoteAddress})")}:{a.RemotePort}") +
        $"  sent {Bytes(a.BytesSent)}, received {Bytes(a.BytesReceived)}";

    /// <summary>
    /// The whole report as text. When <paramref name="maxChars"/> is given (e.g. for Ask Gemini), the
    /// per-section lists are shortened until it fits; findings and the summary always come first.
    /// </summary>
    public static string Build(AnalysisReport r, int? maxChars = null)
    {
        var limit = maxChars ?? int.MaxValue;
        foreach (var perSection in new[] { int.MaxValue, 300, 120, 50, 20, 8 })
        {
            var text = Build(r, perSection);
            if (text.Length <= limit) return text;
        }
        var shortest = Build(r, 3);
        return shortest.Length <= limit ? shortest : shortest[..limit] + "\n[... truncated ...]";
    }

    private static string Build(AnalysisReport r, int perSection)
    {
        var sb = new StringBuilder();
        sb.AppendLine("WINGAURDIAN PROGRAM MONITOR REPORT");
        sb.AppendLine("(The program ran normally on this PC while WinGaurdian recorded what it did. It was NOT isolated.)");
        sb.AppendLine();
        sb.AppendLine($"Program:       {r.ProgramPath ?? "(unknown)"}");
        sb.AppendLine($"Command line:  {r.CommandLine ?? "(unknown)"}");
        sb.AppendLine($"Started:       {r.StartedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Ended:         {(r.EndedUtc is { } end ? end.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : "(still running)")}  ({StateText(r.State)})");
        sb.AppendLine($"Events:        {r.EventCount:N0} recorded");
        if (r.Truncated) sb.AppendLine("NOTE: the program did so much that some activity was not kept (per-run limits reached).");
        sb.AppendLine();

        var findings = Findings(r);
        sb.AppendLine($"FINDINGS ({findings.Count})");
        if (findings.Count == 0) sb.AppendLine("  Nothing rated Medium or High.");
        foreach (var f in findings.Take(Math.Max(perSection, 40)))
            sb.AppendLine($"  [{f.Severity}] {f.Area}: {f.Text}\n           -> {f.Reason}");
        sb.AppendLine();

        sb.AppendLine("SUMMARY");
        sb.AppendLine($"  Processes:   {r.Processes.Count} ({string.Join(", ", r.Processes.Select(p => Name(p.ImagePath)).Distinct().Take(15))})");
        sb.AppendLine("  Files:       " + Counts(r.Files.GroupBy(f => f.Operation).Select(g => (g.Key.ToString(), g.Count()))));
        sb.AppendLine("  Registry:    " + Counts(r.Registry.GroupBy(f => f.Operation).Select(g => (g.Key.ToString(), g.Count()))));
        sb.AppendLine($"  Network:     {r.Network.Count} connection(s) to {r.Network.Select(n => n.RemoteAddress).Distinct().Count()} address(es), " +
                      $"sent {Bytes(r.Network.Sum(n => n.BytesSent))}, received {Bytes(r.Network.Sum(n => n.BytesReceived))}");
        sb.AppendLine($"  DNS lookups: {r.Dns.Count} ({string.Join(", ", r.Dns.Select(d => d.Name).Distinct().Take(15))})");
        sb.AppendLine($"  Other WinGaurdian alerts while it ran: {r.RelatedEvents.Count}");
        sb.AppendLine();

        Section(sb, "PROCESSES", r.Processes, perSection, p =>
            $"  PID {p.Pid} (parent {p.ParentPid}) {p.ImagePath ?? "(unknown)"}{(p.Elevated ? "  [administrator]" : "")}\n" +
            $"      command line: {p.CommandLine ?? "(unknown)"}\n" +
            $"      signature: {p.Signature ?? "(not checked)"}; started {p.StartedUtc.ToLocalTime():HH:mm:ss}" +
            (p.ExitedUtc is { } x ? $", exited {x.ToLocalTime():HH:mm:ss} (code {p.ExitCode})" : ", still running") +
            Flag(p.Severity, p.Reason));
        Section(sb, "FILES", r.Files, perSection, f =>
            $"  {f.Operation,-13} {f.Path}{(f.Detail is null ? "" : $" ({f.Detail})")}{(f.Bytes > 0 ? $"  [{Bytes(f.Bytes)} written]" : "")}  by {f.ProcessName}" +
            Flag(f.Severity, f.Reason));
        Section(sb, "REGISTRY", r.Registry, perSection, a =>
            $"  {DescribeRegistry(a)}{(a.ValueType is null ? "" : $"  ({a.ValueType})")}  by {a.ProcessName}" + Flag(a.Severity, a.Reason));
        Section(sb, "NETWORK", r.Network, perSection, a => $"  {DescribeConnection(a)}  by {a.ProcessName}" + Flag(a.Severity, a.Reason));
        Section(sb, "DNS LOOKUPS", r.Dns, perSection, a =>
            $"  {a.Name} ({a.QueryType}) -> {a.Results ?? "(no answer)"}  by {a.ProcessName}" + Flag(a.Severity, a.Reason));
        Section(sb, "OTHER WINGAURDIAN ALERTS WHILE IT RAN", r.RelatedEvents, perSection, e =>
            $"  #{e.Id} [{e.Severity}] {e.Category} {e.Change}: {e.Subject}");
        if (r.ReadsOmitted)
            sb.AppendLine("(Files and registry keys the program only read are not included.)");
        return sb.ToString();
    }

    private static void Section<T>(StringBuilder sb, string title, List<T> items, int limit, Func<T, string> line)
    {
        sb.AppendLine($"{title} ({items.Count})");
        foreach (var item in items.Take(limit)) sb.AppendLine(line(item));
        if (items.Count > limit) sb.AppendLine($"  ... and {items.Count - limit} more");
        sb.AppendLine();
    }

    private static string Flag(Severity severity, string? reason) =>
        reason is null ? "" : $"\n      [{severity}] {reason}";

    private static string Counts(IEnumerable<(string Name, int Count)> groups)
    {
        var parts = groups.Select(g => $"{g.Count} {g.Name.ToLowerInvariant()}").ToList();
        return parts.Count == 0 ? "none" : string.Join(", ", parts);
    }

    private static string ValueLabel(string? name) => string.IsNullOrEmpty(name) ? "(Default)" : name;

    private static string Name(string? path) => path is null ? "(unknown)" : Path.GetFileName(path);

    public static string StateText(AnalysisState state) => state switch
    {
        AnalysisState.Running => "running",
        AnalysisState.Finished => "the program and everything it started have exited",
        _ => "monitoring was stopped",
    };

    public static string Bytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        _ => $"{bytes / (1024.0 * 1024):0.#} MB",
    };
}
