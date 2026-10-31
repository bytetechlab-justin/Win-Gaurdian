using WinGuardian.Core;
using WinGuardian.Core.Tasks;

namespace WinGuardian.Tests;

public class ScheduledTaskMonitorTests : IDisposable
{
    private readonly TaskTestEnvironment _env = new();

    public void Dispose() => _env.Dispose();

    private List<GuardianEvent> Run(string file, string reason = "Task file changed") => _env.Monitor.Analyze(file, reason);

    [Fact]
    public void New_task_running_unsigned_exe_from_user_folder_is_flagged()
    {
        _env.Monitor.CaptureBaseline();
        var exe = _env.MakeUnsignedExe();
        var file = _env.WriteTask(@"\Updater", TaskXml.Exec(exe, principal: TaskXml.UsersGroupPrincipal));

        var e = _env.Single(Run(file, "New task file"));
        var a = TaskTestEnvironment.AnalysisOf(e);

        Assert.Equal(EventCategory.ScheduledTask, e.Category);
        Assert.Equal(ChangeKind.Added, e.Change);
        Assert.Contains(a.Assessment.Indicators, i => i.Id == "NewTask");
        Assert.Contains(a.Assessment.Indicators, i => i.Id == "TargetUnsigned");
        Assert.Contains(a.Assessment.Indicators, i => i.Id == "UnsignedInUserWritableLocation");
        Assert.True(e.Severity >= Severity.Medium);
        Assert.Equal(exe, e.FilePath);
        Assert.False(a.Comparison.BaselineAvailable);
        Assert.Contains("current configuration only", a.Assessment.Basis);
    }

    [Fact]
    public void Task_running_microsoft_signed_program_is_low_noise()
    {
        _env.Monitor.CaptureBaseline();
        var file = _env.WriteTask(@"\Microsoft\Windows\Test\Notepad", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        var e = _env.Single(Run(file, "New task file"));
        Assert.Equal(Severity.Info, e.Severity);
        Assert.Contains("Signed by Microsoft", e.Signature);
    }

    [Fact]
    public void Description_only_change_is_metadata_only()
    {
        var file = _env.WriteTask(@"\Meta", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        _env.Monitor.CaptureBaseline();

        _env.WriteTask(@"\Meta", TaskXml.Exec(TestEnv.System32("notepad.exe"), description: "new wording"));
        var e = _env.Single(Run(file));
        var c = TaskTestEnvironment.AnalysisOf(e).Comparison;

        Assert.True(c.BaselineAvailable);
        Assert.True(c.TaskFileContentChanged);
        Assert.False(c.DefinitionChanged);
        Assert.True(c.MetadataOnly);
        Assert.False(c.ActionsChanged);
        Assert.True(e.Severity <= Severity.Low);
    }

    [Fact]
    public void Schedule_timing_rewrite_is_recorded_silently()
    {
        var file = _env.WriteTask(@"\Timing", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        _env.Monitor.CaptureBaseline();

        // What Windows does to repeating tasks on its own (the source of routine "task modified" noise).
        _env.WriteTask(@"\Timing", TaskXml.Exec(TestEnv.System32("notepad.exe"), startBoundary: "2026-10-31T06:14:43"));
        Assert.Empty(Run(file));
        Assert.Empty(_env.Monitor.Reconcile()); // and the new version became the baseline
    }

    [Fact]
    public void Unchanged_rewrite_produces_no_event()
    {
        var file = _env.WriteTask(@"\Same", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        _env.Monitor.CaptureBaseline();
        File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddMinutes(5));
        Assert.Empty(Run(file));
    }

    [Fact]
    public void Action_change_to_obfuscated_powershell_is_high()
    {
        var file = _env.WriteTask(@"\Action", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        _env.Monitor.CaptureBaseline();

        _env.WriteTask(@"\Action", TaskXml.Exec("powershell.exe",
            "-NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"));
        var e = _env.Single(Run(file));
        var a = TaskTestEnvironment.AnalysisOf(e);

        Assert.True(a.Comparison.ActionsChanged);
        Assert.Contains(a.Assessment.Indicators, i => i.Id == "ActionChanged");
        Assert.Contains(a.Assessment.Indicators, i => i.Id == "SuspiciousCommandLine");
        Assert.Contains(a.Assessment.Indicators, i => i.Id == "PrivilegedContext"); // runs as SYSTEM
        Assert.Equal(Severity.High, e.Severity);
        Assert.Single(a.Comparison.PreviousActions);
        Assert.Contains("EncodedCommand", a.Comparison.CurrentActions[0]);
    }

    [Fact]
    public void Missing_executable_is_reported()
    {
        _env.Monitor.CaptureBaseline();
        var missing = Path.Combine(_env.Work, "gone", "missing.exe");
        var file = _env.WriteTask(@"\Broken", TaskXml.Exec(missing, principal: TaskXml.UsersGroupPrincipal));
        var a = TaskTestEnvironment.AnalysisOf(_env.Single(Run(file, "New task file")));
        Assert.Contains(a.Assessment.Indicators, i => i.Id.StartsWith("TargetMissing"));
        Assert.False(a.Actions[0].Target!.File.Exists);
    }

    [Fact]
    public void Malformed_definition_is_reported_not_crashed()
    {
        _env.Monitor.CaptureBaseline();
        var file = Path.Combine(_env.Root, "Garbage");
        File.WriteAllText(file, "<Task><Actions>");
        var a = TaskTestEnvironment.AnalysisOf(_env.Single(Run(file, "New task file")));
        Assert.NotNull(a.ParseError);
        Assert.Contains(a.Assessment.Indicators, i => i.Id == "DefinitionUnreadable");
    }

    [Fact]
    public void Deleted_task_is_described_from_its_stored_configuration()
    {
        var file = _env.WriteTask(@"\ToDelete", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        _env.Monitor.CaptureBaseline();
        File.Delete(file);

        var e = _env.Single(Run(file));
        var a = TaskTestEnvironment.AnalysisOf(e);
        Assert.Equal(ChangeKind.Removed, e.Change);
        Assert.NotNull(a.Configuration);
        Assert.Contains("notepad.exe", a.Actions[0].Action.Command);
        Assert.Empty(_env.Monitor.Reconcile());
    }

    [Fact]
    public void Deletion_and_recreation_are_two_events()
    {
        var file = _env.WriteTask(@"\Again", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        _env.Monitor.CaptureBaseline();
        File.Delete(file);
        Assert.Equal(ChangeKind.Removed, _env.Single(Run(file)).Change);
        _env.WriteTask(@"\Again", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        Assert.Equal(ChangeKind.Added, _env.Single(Run(file)).Change);
    }

    [Fact]
    public void Renamed_task_file_is_one_rename_event()
    {
        var file = _env.WriteTask(@"\OldName", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        _env.Monitor.CaptureBaseline();
        var newFile = Path.Combine(_env.Root, "NewName");
        File.Move(file, newFile);

        var events = Run(newFile).Concat(Run(file)).ToList();
        var e = Assert.Single(events);
        Assert.Contains("renamed", e.Subject);
        Assert.Contains(@"\OldName", e.Subject);
        Assert.Empty(_env.Monitor.Reconcile());
    }

    [Fact]
    public void Reconcile_finds_new_changed_and_deleted_tasks()
    {
        var keep = _env.WriteTask(@"\Keep", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        var del = _env.WriteTask(@"\Delete", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        _env.Monitor.CaptureBaseline();
        Assert.Empty(_env.Monitor.Reconcile());

        _env.WriteTask(@"\Keep", TaskXml.Exec(TestEnv.System32("calc.exe")));
        File.Delete(del);
        _env.WriteTask(@"\Brand\New", TaskXml.Exec(TestEnv.System32("notepad.exe")));

        var work = _env.Monitor.Reconcile();
        Assert.Contains(work, w => w.File == keep && w.Reason == "Task file changed");
        Assert.Contains(work, w => w.File == del && w.Reason == "Task file deleted");
        Assert.Contains(work, w => w.File.EndsWith(@"Brand\New") && w.Reason == "New task file");
    }

    [Fact]
    public void Program_file_change_is_detected_without_task_change()
    {
        var exe = _env.MakeUnsignedExe();
        var file = _env.WriteTask(@"\Target", TaskXml.Exec(exe, principal: TaskXml.UsersGroupPrincipal));
        _env.Monitor.CaptureBaseline();

        File.WriteAllBytes(exe, [0x4D, 0x5A, 9, 9, 9, 9, 9]);
        File.SetLastWriteTimeUtc(exe, DateTime.UtcNow.AddMinutes(3));
        var work = Assert.Single(_env.Monitor.Reconcile());
        Assert.Equal("Program file changed", work.Reason);

        var a = TaskTestEnvironment.AnalysisOf(_env.Single(Run(file, work.Reason)));
        Assert.False(a.Comparison.TaskFileContentChanged);
        Assert.True(a.Comparison.TargetContentChanged);
    }

    [Fact]
    public async Task Rapid_repeated_writes_are_debounced_into_one_analysis()
    {
        _env.Monitor.CaptureBaseline();
        _env.Monitor.Start();
        var exe = _env.MakeUnsignedExe();
        for (var i = 0; i < 25; i++)
            _env.WriteTask(@"\Burst", TaskXml.Exec(exe, principal: TaskXml.UsersGroupPrincipal));

        var deadline = DateTime.UtcNow.AddSeconds(10);
        List<GuardianEvent> events;
        do
        {
            await Task.Delay(500, TestContext.Current.CancellationToken);
            events = _env.Db.GetEvents(null, 100, false).Where(e => e.Category == EventCategory.ScheduledTask).ToList();
        } while (events.Count == 0 && DateTime.UtcNow < deadline);

        await Task.Delay(1500, TestContext.Current.CancellationToken); // allow any duplicate to surface
        events = _env.Db.GetEvents(null, 100, false).Where(e => e.Category == EventCategory.ScheduledTask).ToList();
        Assert.Single(events);
    }

    [Fact]
    public void Com_redirection_without_task_change_is_high()
    {
        TestEnv.RequireElevation();
        using var com = new TestComClass().MachineInproc(TestEnv.System32("shell32.dll"));
        var file = _env.WriteTask(@"\ComTask", TaskXml.Com(com.Clsid));
        _env.Monitor.CaptureBaseline();
        Assert.Empty(_env.Monitor.Reconcile());

        // The attack from the spec: same task XML, COM class re-pointed at a DLL in a user-writable folder.
        var evil = Path.Combine(@"C:\Users\Public", $"wg-test-{Guid.NewGuid():N}.dll");
        File.WriteAllBytes(evil, [0x4D, 0x5A, 1, 2, 3]);
        try
        {
            com.SetMachineServer(evil);
            var work = Assert.Single(_env.Monitor.Reconcile());
            Assert.Equal("COM registration changed", work.Reason);

            var e = _env.Single(Run(file, work.Reason));
            var a = TaskTestEnvironment.AnalysisOf(e);
            Assert.False(a.Comparison.TaskFileContentChanged);
            Assert.True(a.Comparison.ComRegistrationChanged);
            Assert.Contains(a.Assessment.Indicators, i => i.Id == "ComRegistrationChanged");
            Assert.Contains(a.Assessment.Indicators, i => i.Id == "ComServerUnusualLocation");
            Assert.Equal(Severity.High, e.Severity);
            Assert.Contains("COM target changed", e.Subject);
            Assert.Equal(evil, e.FilePath);
        }
        finally
        {
            File.Delete(evil);
        }
    }

    [Fact]
    public void Per_user_com_override_for_interactive_task_is_flagged()
    {
        _env.Monitor.CaptureBaseline();
        using var com = new TestComClass().UserInproc(@"C:\Users\Public\hijack.dll");
        var file = _env.WriteTask(@"\UserCom", TaskXml.Com(com.Clsid, principal: TaskXml.UsersGroupPrincipal));
        var a = TaskTestEnvironment.AnalysisOf(_env.Single(Run(file, "New task file")));
        Assert.Contains(a.Assessment.Indicators, i => i.Id == "ComUserOverride");
        Assert.DoesNotContain(a.Assessment.Indicators, i => i.Id == "ComUnresolved");
        Assert.Equal(@"C:\Users\Public\hijack.dll", a.Actions[0].ResolvedPath);
    }

    [Fact]
    public void Real_RefreshCache_definition_resolves_to_signed_wosc_dll_with_low_noise()
    {
        var source = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            @"System32\Tasks\Microsoft\Windows\Flighting\OneSettings\RefreshCache");
        if (!File.Exists(source)) Assert.Skip("RefreshCache task not present on this machine.");
        byte[] bytes;
        try { bytes = File.ReadAllBytes(source); } // read-only use of the real task
        catch (UnauthorizedAccessException) { Assert.Skip("Task file not readable without elevation."); return; }

        _env.Monitor.CaptureBaseline();
        var copy = Path.Combine(_env.Root, @"Microsoft\Windows\Flighting\OneSettings\RefreshCache");
        Directory.CreateDirectory(Path.GetDirectoryName(copy)!);
        File.WriteAllBytes(copy, bytes);

        var e = _env.Single(Run(copy, "New task file"));
        var a = TaskTestEnvironment.AnalysisOf(e);
        var action = Assert.Single(a.Actions);
        Assert.Equal("{E07647F7-AED2-48D9-9720-939BC24A8A3C}", action.Action.ClassId);
        Assert.Equal(TestEnv.System32("wosc.dll"), action.ResolvedPath, ignoreCase: true);
        Assert.True(action.Target!.SignedByMicrosoft); // verified, not assumed from the file name
        Assert.Equal(Severity.Info, e.Severity);

        var report = TaskAnalysisFormatter.Format(e, a);
        Assert.Contains("COM Handler", report);
        Assert.Contains("wosc.dll", report);
        Assert.Contains("New task (no earlier version on record)", report);
    }

    [Fact]
    public void Report_never_claims_a_comparison_without_baseline()
    {
        var file = _env.WriteTask(@"\NoBaseline", TaskXml.Exec(TestEnv.System32("notepad.exe")));
        _env.Monitor.CaptureBaseline();
        _env.Db.DeleteTaskState(@"\NoBaseline"); // simulate a task that was never recorded
        _env.WriteTask(@"\NoBaseline", TaskXml.Exec(TestEnv.System32("calc.exe")));

        var e = _env.Single(Run(file));
        var a = TaskTestEnvironment.AnalysisOf(e);
        Assert.False(a.Comparison.BaselineAvailable);
        Assert.Null(a.Comparison.ActionsChanged);
        var report = TaskAnalysisFormatter.Format(e, a);
        Assert.DoesNotContain("Action Changed:", report);
    }
}
