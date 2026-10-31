using WinGuardian.Core.Configuration;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Core.Tasks;

/// <summary>
/// Contextual scoring: each indicator adds (or subtracts) weight; the total maps to a severity.
/// No single weak signal makes a task "malicious" — e.g. a modification alone, or being unsigned.
/// Weights and thresholds are configurable under Guardian:TaskRisk in appsettings.json.
/// </summary>
public sealed class TaskRiskScorer(GuardianOptions options)
{
    public static readonly IReadOnlyDictionary<string, int> DefaultWeights = new Dictionary<string, int>
    {
        ["NewTask"] = 2,
        ["TaskRemoved"] = 1,
        ["SecurityTaskRemoved"] = 3,
        ["SecurityTaskDisabled"] = 3,
        ["DefinitionUnreadable"] = 3,
        ["ActionChanged"] = 3,
        ["PrivilegeIncreased"] = 3,
        ["TriggersChanged"] = 1,
        ["TaskHidden"] = 2,
        ["ComRegistrationChanged"] = 5,
        ["ComUserOverride"] = 4,
        ["ComUnresolved"] = 1,
        ["ComServerUnusualLocation"] = 3,
        ["TargetContentChanged"] = 2,
        ["TargetUnresolved"] = 1,
        ["TargetMissing"] = 2,
        ["TargetMissingWritableDirectory"] = 4,
        ["TargetUnsigned"] = 2,
        ["UnsignedInUserWritableLocation"] = 2,
        ["TargetSignatureBroken"] = 6,
        ["TargetSignatureUntrusted"] = 3,
        ["TargetWritableByUnprivileged"] = 4,
        ["ScriptHostAction"] = 2,
        ["SuspiciousCommandLine"] = 5,
        ["MicrosoftSignedTarget"] = -2,
        ["ThirdPartySignedTarget"] = -1,
    };

    private static readonly string[] SecurityTaskFolders =
        [@"\Microsoft\Windows\Windows Defender\", @"\Microsoft\Windows\WindowsUpdate\", @"\Microsoft\Windows\UpdateOrchestrator\"];

    private static readonly string[] StandardProgramRoots =
    [
        GuardianPaths.Normalize("%WINDIR%"),
        GuardianPaths.Normalize("%ProgramFiles%"),
        GuardianPaths.Normalize("%ProgramFiles(x86)%"),
    ];

    public TaskAssessment Assess(string change, TaskState? previous, TaskState? current, TaskComparison comparison)
    {
        var indicators = new List<RiskIndicator>();
        void Add(string id, string explanation)
        {
            var weight = Weight(id);
            if (weight != 0) indicators.Add(new RiskIndicator { Id = id, Weight = weight, Explanation = explanation });
        }

        var state = current ?? previous!;
        var path = state.Path;
        var isSecurityTask = SecurityTaskFolders.Any(f => path.StartsWith(f, StringComparison.OrdinalIgnoreCase));

        switch (change)
        {
            case "Removed":
                Add("TaskRemoved", "The task was deleted.");
                if (isSecurityTask) Add("SecurityTaskRemoved", "It is a Windows security/update task; malware deletes these to stay undetected.");
                break;
            case "Added":
                Add("NewTask", "A new scheduled task was registered.");
                break;
        }

        if (current is not null)
        {
            if (current.ParseError is not null)
                Add("DefinitionUnreadable", $"The task file could not be parsed ({current.ParseError}).");

            if (comparison.BaselineAvailable)
            {
                if (comparison.ActionsChanged == true) Add("ActionChanged", "What the task runs was changed.");
                if (comparison.PrincipalChanged == true && current.Definition?.RunsPrivileged == true && previous?.Definition?.RunsPrivileged != true)
                    Add("PrivilegeIncreased", $"The task now runs with elevated rights ({current.Definition.ExecutionAccount}).");
                if (comparison.TriggersChanged == true) Add("TriggersChanged", "When the task runs was changed.");
                if (comparison.EnabledChanged == true && current.Definition?.Enabled == false && isSecurityTask)
                    Add("SecurityTaskDisabled", "A Windows security/update task was disabled.");
                if (current.Definition?.Hidden == true && previous?.Definition?.Hidden == false)
                    Add("TaskHidden", "The task was changed to be hidden from the Task Scheduler UI.");
                if (comparison.ComRegistrationChanged == true)
                    Add("ComRegistrationChanged", "The COM registration this task uses now points to different code, even though the task itself may be unchanged.");
                if (comparison.TargetContentChanged == true)
                    Add("TargetContentChanged", "The program/DLL this task runs was modified.");
            }
            else if (change == "Added" && current.Definition?.Hidden == true)
            {
                Add("TaskHidden", "The task is hidden from the Task Scheduler UI.");
            }

            var microsoftTask = path.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
            foreach (var action in current.Actions)
                AssessAction(action, current.Definition, microsoftTask, Add);
        }

        var sum = indicators.Sum(i => i.Weight);
        var privileged = (current ?? previous)?.Definition?.RunsPrivileged == true;
        if (sum > 0 && privileged)
        {
            var multiplied = (int)Math.Ceiling(sum * options.TaskRiskPrivilegedMultiplierPercent / 100.0);
            if (multiplied != sum)
                indicators.Add(new RiskIndicator
                {
                    Id = "PrivilegedContext",
                    Weight = multiplied - sum,
                    Explanation = $"The task runs as {(current ?? previous)!.Definition!.ExecutionAccount}, which amplifies any risk.",
                });
            sum = multiplied;
        }

        var severity = sum >= options.TaskRiskHighThreshold ? Severity.High
            : sum >= options.TaskRiskMediumThreshold ? Severity.Medium
            : sum > 0 ? Severity.Low
            : Severity.Info;

        return new TaskAssessment
        {
            Score = sum,
            Severity = severity,
            Verdict = severity switch
            {
                Severity.High => "High risk",
                Severity.Medium => "Suspicious - review recommended",
                Severity.Low => "Low risk",
                _ => "No risk indicators",
            },
            Indicators = indicators,
            Basis = comparison.BaselineAvailable
                ? $"Compared with the version recorded at {previous!.AnalyzedUtc.ToLocalTime():g}."
                : "No previous record of this task: the assessment is based on its current configuration only.",
            Explanation = Explain(change, indicators, comparison),
        };
    }

    private void AssessAction(ActionState action, TaskDefinition? def, bool microsoftTask, Action<string, string> add)
    {
        var a = action.Action;
        if (a.Type == "ComHandler")
        {
            var com = action.Com;
            if (com is not null && com.UserOverrides.Count > 0)
                add("ComUserOverride", $"A per-user registration ({string.Join(", ", com.UserOverrides.Select(o => o.Account))}) " +
                                       (com.Resolved ? "shadows the machine-wide COM class" : "supplies this COM class") +
                                       " for that user, a known COM hijacking technique.");
            else if (com is null || !com.Resolved)
            {
                add("ComUnresolved", $"COM class {a.ClassId} could not be resolved ({com?.Error ?? "unknown"}).");
                return;
            }
            var server = action.ResolvedPath;
            if (server is not null && Path.IsPathRooted(server) &&
                !StandardProgramRoots.Any(r => server.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase)))
                add("ComServerUnusualLocation", $"The COM server is outside Windows/Program Files: {server}.");
        }
        else if (a.Type == "Exec")
        {
            if (action.ResolvedPath is null)
            {
                add("TargetUnresolved", $"The program '{a.Command}' could not be located.");
                return;
            }
            if (action.Target?.IsScriptHost == true && !microsoftTask)
                add("ScriptHostAction", $"The task runs a script host ({Path.GetFileName(action.ResolvedPath)}), which will execute whatever command it is given.");
            var commandLine = $"{a.Command} {a.Arguments}";
            if (CommandLineRules.Evaluate(action.ResolvedPath, commandLine) is { } rule)
                add("SuspiciousCommandLine", $"Its command line matches '{rule.Rule}'.");
        }
        else
        {
            return;
        }

        var target = action.Target;
        if (target is null) return;
        var name = Path.GetFileName(target.File.Path);

        if (!target.File.Exists)
        {
            if (target.DirectoryWritableBy.Count > 0)
                add("TargetMissingWritableDirectory", $"{name} does not exist and {string.Join(", ", target.DirectoryWritableBy)} can create it — anyone could plant code that this task will run.");
            else
                add("TargetMissing", $"{name} does not exist (broken or tampered task).");
            return;
        }

        switch (target.SignatureStatus)
        {
            case nameof(SignatureStatus.Tampered):
                add("TargetSignatureBroken", $"{name} has a broken signature: it was modified after being signed.");
                break;
            case nameof(SignatureStatus.Untrusted):
                add("TargetSignatureUntrusted", $"{name}'s signature is not trusted ({target.Signature}).");
                break;
            case nameof(SignatureStatus.Unsigned):
                add("TargetUnsigned", $"{name} is not digitally signed.");
                if (target.InUserWritableLocation)
                    add("UnsignedInUserWritableLocation", $"{name} is unsigned and lives in a user-writable folder.");
                break;
            case nameof(SignatureStatus.Valid) when target.SignedByMicrosoft && !target.IsScriptHost:
                add("MicrosoftSignedTarget", $"{name} carries a valid Microsoft signature.");
                break;
            case nameof(SignatureStatus.Valid) when !target.SignedByMicrosoft:
                add("ThirdPartySignedTarget", $"{name} is validly signed by {target.Signer} (a trust signal, not proof of safety).");
                break;
        }

        if (target.WritableBy.Count > 0 && def?.RunsPrivileged == true)
            add("TargetWritableByUnprivileged", $"{string.Join(", ", target.WritableBy)} can modify or replace {name}, yet the task runs as {def.ExecutionAccount} (privilege escalation risk).");
    }

    private static string Explain(string change, List<RiskIndicator> indicators, TaskComparison comparison)
    {
        var risks = indicators.Where(i => i.Weight > 0 && i.Id != "PrivilegedContext").ToList();
        if (risks.Count == 0 || (risks.Count == 1 && risks[0].Id is "NewTask" or "TaskRemoved"))
        {
            var lead = change switch
            {
                "Removed" => "The task was removed.",
                "Added" => "A new task was registered.",
                _ when comparison.MetadataOnly == true => "Only descriptive information or schedule timing changed; what the task runs and as whom is unchanged.",
                _ => "The task changed.",
            };
            var trust = indicators.Where(i => i.Weight < 0).Select(i => i.Explanation).ToList();
            return $"{lead} No suspicious indicators were found by the available checks." +
                   (trust.Count > 0 ? " " + string.Join(" ", trust) : "");
        }
        return string.Join(" ", indicators.Where(i => i.Id != "PrivilegedContext").Select(i => i.Explanation)) +
               (indicators.Any(i => i.Id == "PrivilegedContext") ? " " + indicators.First(i => i.Id == "PrivilegedContext").Explanation : "");
    }

    private int Weight(string id) =>
        options.TaskRiskWeights.TryGetValue(id, out var configured) ? configured : DefaultWeights.GetValueOrDefault(id);
}
