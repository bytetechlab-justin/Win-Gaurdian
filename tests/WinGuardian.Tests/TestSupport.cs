using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using WinGuardian.Core;
using WinGuardian.Core.Configuration;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;
using WinGuardian.Core.Tasks;

namespace WinGuardian.Tests;

internal static class TestEnv
{
    public static bool IsElevated
    {
        get
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public static string CurrentUserSid => WindowsIdentity.GetCurrent().User!.Value;

    public static void RequireElevation()
    {
        if (!IsElevated) Assert.Skip("Requires an elevated (administrator) test run.");
    }

    public static string NewClsid() => Guid.NewGuid().ToString("B").ToUpperInvariant();

    public static string System32(string file) => Path.Combine(Environment.SystemDirectory, file);
}

/// <summary>Builds Task Scheduler XML like Windows writes it (UTF-16 with BOM).</summary>
internal static class TaskXml
{
    public const string SystemPrincipal = "<UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel>";
    public const string UsersGroupPrincipal = "<GroupId>S-1-5-32-545</GroupId><RunLevel>LeastPrivilege</RunLevel>";

    public static string Exec(string command, string? arguments = null, string principal = SystemPrincipal,
        string description = "WinGuardian test task", string startBoundary = "2026-01-01T00:00:00", bool hidden = false, bool enabled = true) =>
        Build($"<Exec><Command>{Escape(command)}</Command>{(arguments is null ? "" : $"<Arguments>{Escape(arguments)}</Arguments>")}</Exec>",
            principal, description, startBoundary, hidden, enabled);

    public static string Com(string clsid, string principal = SystemPrincipal, string description = "WinGuardian test task",
        string startBoundary = "2026-01-01T00:00:00") =>
        Build($"<ComHandler><ClassId>{clsid}</ClassId></ComHandler>", principal, description, startBoundary, false, true);

    private static string Build(string action, string principal, string description, string startBoundary, bool hidden, bool enabled) => $"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo>
            <Author>WinGuardian tests</Author>
            <Description>{Escape(description)}</Description>
          </RegistrationInfo>
          <Triggers>
            <TimeTrigger>
              <Repetition><Interval>PT4H</Interval></Repetition>
              <StartBoundary>{startBoundary}</StartBoundary>
              <Enabled>true</Enabled>
            </TimeTrigger>
          </Triggers>
          <Principals>
            <Principal id="Author">{principal}</Principal>
          </Principals>
          <Settings>
            <Enabled>{(enabled ? "true" : "false")}</Enabled>
            <Hidden>{(hidden ? "true" : "false")}</Hidden>
          </Settings>
          <Actions Context="Author">
            {action}
          </Actions>
        </Task>
        """;

    public static byte[] Bytes(string xml) => Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(xml)).ToArray();

    private static string Escape(string s) => System.Security.SecurityElement.Escape(s)!;
}

/// <summary>A throwaway tasks folder and database with a real ScheduledTaskMonitor (no attribution).</summary>
internal sealed class TaskTestEnvironment : IDisposable
{
    public string Root { get; }
    public string Work { get; }
    public GuardianDatabase Db { get; }
    public ScheduledTaskMonitor Monitor { get; }
    public GuardianOptions Options { get; }

    public TaskTestEnvironment(int debounceMs = 300)
    {
        Work = Path.Combine(Path.GetTempPath(), "wg-tests", Guid.NewGuid().ToString("N"));
        Root = Path.Combine(Work, "Tasks");
        Directory.CreateDirectory(Root);
        Db = new GuardianDatabase(Path.Combine(Work, "test.db"));
        Db.Initialize();
        Options = new GuardianOptions { ScheduledTasksRoot = Root, FileChangeDebounceMs = debounceMs };
        Options.ApplyDefaults();
        var events = new EventRecorder(Db, new TrustStore(Db), NullLogger<EventRecorder>.Instance);
        Monitor = new ScheduledTaskMonitor(Db, Options, events, new NullTaskAttributor(), NullLogger<ScheduledTaskMonitor>.Instance);
    }

    public string WriteTask(string taskPath, string xml)
    {
        var file = Path.Combine(Root, taskPath.TrimStart('\\'));
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllBytes(file, TaskXml.Bytes(xml));
        File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddSeconds(Random.Shared.Next(1, 1000))); // guarantee a visible timestamp change
        return file;
    }

    public GuardianEvent Single(List<GuardianEvent> events)
    {
        Assert.Single(events);
        return events[0];
    }

    public static TaskAnalysis AnalysisOf(GuardianEvent e) =>
        TaskAnalysisFormatter.TryParse(e.Analysis) ?? throw new Xunit.Sdk.XunitException("event has no task analysis");

    /// <summary>An unsigned "program" in a user-writable folder.</summary>
    public string MakeUnsignedExe(string name = "tool.exe")
    {
        var path = Path.Combine(Work, name);
        File.WriteAllBytes(path, [0x4D, 0x5A, 0x90, 0x00, 1, 2, 3, 4]);
        return path;
    }

    public void Dispose()
    {
        Monitor.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(Work, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}

/// <summary>A COM class registered for the duration of a test, then removed.</summary>
internal sealed class TestComClass : IDisposable
{
    private readonly List<(RegistryKey Base, string Path)> _created = [];
    public string Clsid { get; } = TestEnv.NewClsid();

    public TestComClass MachineInproc(string dll, RegistryView view = RegistryView.Registry64, string? clsid = null, string? treatAs = null)
    {
        var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
        var path = $@"SOFTWARE\Classes\CLSID\{clsid ?? Clsid}";
        using var key = baseKey.CreateSubKey(path);
        key.SetValue("", "WinGuardian test class");
        if (treatAs is not null)
        {
            using var t = key.CreateSubKey("TreatAs");
            t.SetValue("", treatAs);
        }
        else
        {
            using var inproc = key.CreateSubKey("InprocServer32");
            inproc.SetValue("", dll, RegistryValueKind.ExpandString);
            inproc.SetValue("ThreadingModel", "Both");
        }
        _created.Add((baseKey, path));
        return this;
    }

    public TestComClass MachineLocalServer(string commandLine)
    {
        var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        var path = $@"SOFTWARE\Classes\CLSID\{Clsid}";
        using var key = baseKey.CreateSubKey(path);
        using var local = key.CreateSubKey("LocalServer32");
        local.SetValue("", commandLine);
        _created.Add((baseKey, path));
        return this;
    }

    public TestComClass UserInproc(string dll)
    {
        var path = $@"{TestEnv.CurrentUserSid}_Classes\CLSID\{Clsid}";
        using var key = Registry.Users.CreateSubKey(path);
        using var inproc = key.CreateSubKey("InprocServer32");
        inproc.SetValue("", dll);
        _created.Add((Registry.Users, path));
        return this;
    }

    public void SetMachineServer(string dll, RegistryView view = RegistryView.Registry64)
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
        using var inproc = baseKey.OpenSubKey($@"SOFTWARE\Classes\CLSID\{Clsid}\InprocServer32", writable: true)!;
        inproc.SetValue("", dll, RegistryValueKind.ExpandString);
    }

    public void Dispose()
    {
        foreach (var (baseKey, path) in _created)
        {
            try { baseKey.DeleteSubKeyTree(path, throwOnMissingSubKey: false); } catch (UnauthorizedAccessException) { }
        }
    }
}
