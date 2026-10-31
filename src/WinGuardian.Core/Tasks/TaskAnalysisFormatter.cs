using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinGuardian.Core.Tasks;

/// <summary>
/// Human-readable report for a scheduled-task event. Only states what was actually verified: unknown or
/// unverifiable results are labelled as such, and no comparison is claimed without a previous baseline.
/// </summary>
public static class TaskAnalysisFormatter
{
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static TaskAnalysis? TryParse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("Kind", out var kind) || kind.GetString() != "ScheduledTask") return null;
            return JsonSerializer.Deserialize<TaskAnalysis>(json, Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static string Format(GuardianEvent e, TaskAnalysis a)
    {
        var sb = new StringBuilder();
        void Line(string label, string? value) => sb.AppendLine($"{label}:").AppendLine($"  {value ?? "(none)"}");
        string YesNo(bool? value, string unknown) => value switch { true => "Yes", false => "No", null => unknown };
        const string noBaseline = "Unknown - No Previous Baseline";

        sb.AppendLine($"EVENT #{e.Id}");
        sb.AppendLine($"Severity: {e.Severity}");
        sb.AppendLine($"Type: Scheduled Task {a.Change}");
        sb.AppendLine();
        Line("Task", a.Task);
        Line("Timestamp", e.TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
        Line("Detected by", a.Trigger);

        if (a.Configuration is { } c)
        {
            Line("Execution Context", c.ExecutionAccount + (c.Enabled ? "" : " (task disabled)") + (c.Hidden ? " (hidden)" : ""));
            Line("Triggers", c.Triggers.Count == 0 ? "(none)" : string.Join("; ", c.Triggers));
        }
        else if (a.ParseError is not null)
        {
            Line("Task Definition", $"Could not be parsed: {a.ParseError}");
        }

        for (var i = 0; i < a.Actions.Count; i++)
        {
            var action = a.Actions[i];
            sb.AppendLine();
            sb.AppendLine(a.Actions.Count > 1 ? $"--- Action {i + 1} ---" : "--- Action ---");
            if (action.Action.Type == "ComHandler")
            {
                Line("Action Type", "COM Handler");
                Line("COM Class ID", action.Action.ClassId);
                var com = action.Com;
                if (com is null || !com.Resolved)
                {
                    Line("Resolved Component", $"Unresolved ({com?.Error ?? "not checked"})");
                }
                else
                {
                    Line("Resolved Component", action.ResolvedPath ?? com.Server?.RawValue ?? com.AppIdLocalService);
                    Line("Registration", $"{com.Server?.RegistrationType}, {com.RegistryView} view, {com.RegistryLocation}" +
                                         (com.Server?.ThreadingModel is { } tm ? $", threading model {tm}" : ""));
                    if (com.TreatAsChain.Count > 1) Line("TreatAs Redirection", string.Join(" -> ", com.TreatAsChain));
                    if (com.UserOverrides.Count > 0)
                        Line("Per-user Override", string.Join("; ", com.UserOverrides.Select(o => $"{o.Account}: {o.Server?.ServerPath ?? o.Server?.RawValue} ({o.RegistryLocation})")));
                }
            }
            else
            {
                Line("Action Type", action.Action.Type == "Exec" ? "Run program" : action.Action.Type);
                Line("Command", action.Action.Describe());
                Line("Resolved Program", action.ResolvedPath ?? "Unresolved (program could not be located)");
            }

            if (action.Target is { } t)
            {
                Line("File Exists", t.File.Exists ? "Yes" : "No");
                Line("Digital Signature", t.File.Exists ? t.Signature ?? "Not verified" : "Not verified (file missing)");
                Line("Component SHA-256", (t.File.Sha256 ?? (t.File.Exists ? "Could not be read" : "(file missing)")) +
                                         (t.File.Inconsistent ? " (file changed while reading)" : ""));
                if (t.WritableBy.Count > 0) Line("Modifiable by Non-admins", string.Join(", ", t.WritableBy));
                if (t.DirectoryWritableBy.Count > 0) Line("Can be Created by Non-admins", string.Join(", ", t.DirectoryWritableBy));
            }
        }

        sb.AppendLine();
        var cmp = a.Comparison;
        Line("Task SHA-256", a.TaskSha256);
        if (!cmp.BaselineAvailable)
        {
            Line("Task Definition Changed", a.Change == "Added" ? "New task (no earlier version on record)" : noBaseline);
        }
        else
        {
            Line("Task Content Changed", YesNo(cmp.TaskFileContentChanged, noBaseline));
            Line("Task Definition Changed", YesNo(cmp.DefinitionChanged, noBaseline) + (cmp.MetadataOnly == true ? " (descriptive/metadata changes only)" : ""));
            Line("Action Changed", YesNo(cmp.ActionsChanged, noBaseline));
            Line("COM Registration Changed", YesNo(cmp.ComRegistrationChanged, noBaseline));
            Line("Target File Changed", YesNo(cmp.TargetContentChanged, noBaseline));
            if (cmp.ChangedFields.Count > 0) Line("What Changed", string.Join(", ", cmp.ChangedFields));
            if (cmp.ActionsChanged == true)
            {
                Line("Previous Action", string.Join("; ", cmp.PreviousActions));
                Line("Current Action", string.Join("; ", cmp.CurrentActions));
            }
            if (cmp.ComRegistrationChanged == true)
            {
                Line("Previous COM Target", string.Join("; ", cmp.PreviousComTargets));
                Line("Current COM Target", string.Join("; ", cmp.CurrentComTargets));
            }
        }

        var p = a.ModifyingProcess;
        Line("Modifying Process", p.Available && p.ProcessId is not null
            ? $"{p.ProcessPath ?? "(path unknown)"} (PID {p.ProcessId}" + (p.ParentProcessId is { } pp ? $", parent PID {pp}" : "") + ")"
            : p.Available ? $"Unknown (user: {p.User ?? "unknown"})" : "Unknown");
        if (p.User is not null && p.ProcessId is not null) Line("User", p.User);
        if (p.ProcessSigner is not null) Line("Process Signature", p.ProcessSigner);
        if (p.CommandLine is not null) Line("Process Command Line", p.CommandLine);
        if (p.ProcessStartUtc is { } started) Line("Process Started", started.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
        if (p.Note is not null) Line("Attribution Note", $"{p.Note}{(p.Source is null ? "" : $" (source: {p.Source})")}");

        sb.AppendLine();
        Line("Threat Assessment", $"{a.Assessment.Verdict} (score {a.Assessment.Score})");
        if (a.Assessment.Indicators.Count > 0)
        {
            sb.AppendLine("Indicators:");
            foreach (var i in a.Assessment.Indicators)
                sb.AppendLine($"  {(i.Weight > 0 ? "+" : "")}{i.Weight}  {i.Id}");
        }
        Line("Explanation", a.Assessment.Explanation);
        Line("Basis", a.Assessment.Basis);
        return sb.ToString();
    }
}
