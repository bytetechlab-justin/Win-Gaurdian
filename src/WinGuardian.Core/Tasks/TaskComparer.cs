namespace WinGuardian.Core.Tasks;

/// <summary>Works out what actually changed between two recorded versions of a task.</summary>
public static class TaskComparer
{
    /// <param name="loadedUserSids">User hives loaded now; per-user COM overrides of other users are not compared.</param>
    public static TaskComparison Compare(TaskState? previous, TaskState? current, IReadOnlySet<string> loadedUserSids)
    {
        var result = new TaskComparison
        {
            BaselineAvailable = previous is not null,
            PreviousTaskSha256 = previous?.File.Sha256,
            PreviousActions = previous?.Definition?.Actions.Select(a => a.Describe()).ToList() ?? [],
            CurrentActions = current?.Definition?.Actions.Select(a => a.Describe()).ToList() ?? [],
            PreviousComTargets = previous?.Actions.Where(a => a.Com is not null).Select(a => a.Com!.Describe()).ToList() ?? [],
            CurrentComTargets = current?.Actions.Where(a => a.Com is not null).Select(a => a.Com!.Describe()).ToList() ?? [],
        };
        if (previous is null || current is null) return result;

        result.TaskFileContentChanged = !current.File.SameContentAs(previous.File);

        var a = previous.Definition;
        var b = current.Definition;
        if (a is not null && b is not null)
        {
            void Check(string field, string? x, string? y)
            {
                if (!string.Equals(x, y, StringComparison.Ordinal)) result.ChangedFields.Add(field);
            }

            Check("Description", a.Description, b.Description);
            Check("Author", a.Author, b.Author);
            Check("Source", a.Source, b.Source);
            Check("Registration date", a.RegistrationDate, b.RegistrationDate);
            var metadataChanged = result.ChangedFields.Count > 0;

            result.EnabledChanged = a.Enabled != b.Enabled;
            if (result.EnabledChanged == true) result.ChangedFields.Add(b.Enabled ? "Enabled" : "Disabled");
            var hiddenChanged = a.Hidden != b.Hidden;
            if (hiddenChanged) result.ChangedFields.Add(b.Hidden ? "Hidden" : "Unhidden");

            // Name the exact part of the run-as settings that changed (the friendly account name may look identical).
            var principalChanges = new List<string>();
            if (a.UserId != b.UserId || a.GroupId != b.GroupId)
                principalChanges.Add($"Run as: {a.ExecutionAccount} -> {b.ExecutionAccount}");
            if (a.LogonType != b.LogonType)
                principalChanges.Add($"Logon type: {a.LogonType ?? "(default)"} -> {b.LogonType ?? "(default)"}");
            if (a.RunLevel != b.RunLevel)
                principalChanges.Add($"Run level: {a.RunLevel ?? "(default)"} -> {b.RunLevel ?? "(default)"}");
            result.PrincipalChanged = principalChanges.Count > 0;
            result.ChangedFields.AddRange(principalChanges);

            result.TriggersChanged = !a.Triggers.SequenceEqual(b.Triggers);
            if (result.TriggersChanged == true) result.ChangedFields.Add("Triggers");

            var timingChanged = !a.TriggerBoundaries.SequenceEqual(b.TriggerBoundaries);
            if (timingChanged) result.ChangedFields.Add("Trigger start/end time");

            result.ActionsChanged = !a.Actions.Select(ActionKey).SequenceEqual(b.Actions.Select(ActionKey));
            if (result.ActionsChanged == true) result.ChangedFields.Add("Actions");

            result.DefinitionChanged = result.EnabledChanged == true || hiddenChanged || result.PrincipalChanged == true ||
                                       result.TriggersChanged == true || result.ActionsChanged == true;
            result.MetadataOnly = result.DefinitionChanged == false && (metadataChanged || timingChanged || result.TaskFileContentChanged == true);
            result.ScheduleTimingOnly = result.DefinitionChanged == false && timingChanged && !metadataChanged;
        }
        else
        {
            result.DefinitionChanged = (a is null) != (b is null) || result.TaskFileContentChanged == true;
        }

        // COM registrations and target files, matched action by action.
        var comChanged = false;
        var targetChanged = false;
        for (var i = 0; i < Math.Min(previous.Actions.Count, current.Actions.Count); i++)
        {
            var p = previous.Actions[i];
            var c = current.Actions[i];
            if (p.Com is not null && c.Com is not null && p.Com.ClassId == c.Com.ClassId && ComChanged(p.Com, c.Com, loadedUserSids))
                comChanged = true;
            if (p.ResolvedPath is not null && string.Equals(p.ResolvedPath, c.ResolvedPath, StringComparison.OrdinalIgnoreCase) &&
                p.Target is not null && c.Target is not null && !c.Target.File.SameContentAs(p.Target.File))
                targetChanged = true;
        }
        result.ComRegistrationChanged = comChanged;
        result.TargetContentChanged = targetChanged;
        if (comChanged) result.ChangedFields.Add("COM registration");
        if (targetChanged) result.ChangedFields.Add("Target file content");
        return result;
    }

    /// <summary>
    /// Machine-wide resolution must match exactly; per-user overrides are compared only for users whose
    /// registry hive is loaded now (an override "disappearing" at logoff is not a change).
    /// </summary>
    public static bool ComChanged(ComResolution previous, ComResolution current, IReadOnlySet<string> loadedUserSids)
    {
        if (MachineFingerprint(previous) != MachineFingerprint(current)) return true;
        foreach (var sid in loadedUserSids)
        {
            var p = previous.UserOverrides.FirstOrDefault(o => o.Sid == sid)?.Server?.ServerPath;
            var c = current.UserOverrides.FirstOrDefault(o => o.Sid == sid)?.Server?.ServerPath;
            if (!string.Equals(p, c, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static string MachineFingerprint(ComResolution r) =>
        string.Join("|", r.Resolved, r.RegistryView, string.Join(">", r.TreatAsChain), r.Server?.RegistrationType,
            r.Server?.ServerPath?.ToUpperInvariant(), r.Server?.ManagedAssembly, r.AppIdLocalService, r.AppIdDllSurrogate);

    private static string ActionKey(TaskAction a) => $"{a.Type}|{a.Command}|{a.Arguments}|{a.WorkingDirectory}|{a.ClassId}|{a.Data}";
}
