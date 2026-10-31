using System.ComponentModel;
using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using WinGuardian.Core;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Tests;

public class ExecutionBlockerTests : IDisposable
{
    private readonly string _work = Path.Combine(Path.GetTempPath(), "wg-tests", Guid.NewGuid().ToString("N"));
    private readonly GuardianDatabase _db;
    private readonly ExecutionBlocker _blocker;

    public ExecutionBlockerTests()
    {
        Directory.CreateDirectory(_work);
        _db = new GuardianDatabase(Path.Combine(_work, "block.db"));
        _db.Initialize();
        _blocker = new ExecutionBlocker(_db, new EventRecorder(_db, new TrustStore(_db), NullLogger<EventRecorder>.Instance),
            NullLogger<ExecutionBlocker>.Instance);
    }

    public void Dispose()
    {
        foreach (var item in _blocker.List())
        {
            try { _blocker.Unblock(item.Id); } catch (Exception) { }
        }
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_work, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    /// <summary>A private copy of a harmless Windows program to block.</summary>
    private string CopyOfPing(string name = "blockme.exe")
    {
        var path = Path.Combine(_work, name);
        File.Copy(TestEnv.System32("PING.EXE"), path);
        return path;
    }

    private static Process Start(string exe, string args = "-n 30 127.0.0.1") =>
        Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;

    [Fact]
    public void Blocked_program_cannot_start_and_unblock_restores_it()
    {
        var exe = CopyOfPing();
        var item = _blocker.Block(exe, "test");

        Assert.True(item.AclApplied);
        Assert.True(ExecutionBlocker.HasDenyExecute(exe));
        Assert.True(_blocker.IsBlockedPath(exe));
        var ex = Assert.Throws<Win32Exception>(() => Start(exe, "-n 1 127.0.0.1"));
        Assert.Equal(5, ex.NativeErrorCode); // ERROR_ACCESS_DENIED: Windows refused to run it

        _blocker.Unblock(item.Id);
        Assert.False(ExecutionBlocker.HasDenyExecute(exe));
        Assert.False(_blocker.IsBlockedPath(exe));
        using var p = Start(exe, "-n 1 127.0.0.1");
        Assert.True(p.WaitForExit(10_000));
    }

    [Fact]
    public void Running_instance_is_terminated_when_blocked()
    {
        var exe = CopyOfPing();
        using var running = Start(exe);
        Thread.Sleep(300);
        Assert.False(running.HasExited);

        _blocker.Block(exe, "test");
        Assert.True(running.WaitForExit(5000));
        Assert.Contains(_db.GetEvents(null, 10, false), e => e.Subject.StartsWith("Program blocked") && e.Details!.Contains("terminated 1"));
    }

    [Fact]
    public void Renamed_copy_is_recognised_by_hash_and_terminated()
    {
        var original = CopyOfPing();
        _blocker.Block(original, "test");
        var renamed = CopyOfPing("innocent-name.exe");
        var hash = FileHasher.TryHash(renamed, long.MaxValue);
        Assert.False(_blocker.IsBlockedPath(renamed));
        Assert.True(_blocker.IsBlockedHash(hash));

        using var running = Start(renamed); // the copy has normal permissions, so it starts...
        var start = new ProcessStart(new ProcessSnapshot(running.Id, "innocent-name", renamed), Environment.ProcessId, null, null);
        Assert.True(_blocker.Enforce(start, hash)); // ...and is terminated as soon as WinGaurdian sees it
        Assert.True(running.WaitForExit(5000));
        Assert.Contains(_db.GetEvents(null, 10, false), e => e.Subject.Contains("renamed copy"));
    }

    [Fact]
    public void Unrelated_program_is_not_touched()
    {
        _blocker.Block(CopyOfPing(), "test");
        var other = new ProcessStart(new ProcessSnapshot(Environment.ProcessId, "self", Environment.ProcessPath), 0, null, null);
        Assert.False(_blocker.Enforce(other, FileHasher.TryHash(Environment.ProcessPath!, long.MaxValue)));
    }

    [Fact]
    public void Core_windows_files_and_runtime_are_refused()
    {
        Assert.Throws<InvalidOperationException>(() => _blocker.Block(TestEnv.System32("lsass.exe"), "test"));
        Assert.Throws<InvalidOperationException>(() => _blocker.Block(TestEnv.System32("svchost.exe"), "test"));
        var coreclr = Directory.GetFiles(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet"),
            "coreclr.dll", SearchOption.AllDirectories).FirstOrDefault();
        if (coreclr is not null) Assert.Throws<InvalidOperationException>(() => _blocker.Block(coreclr, "test"));
        Assert.Empty(_blocker.List());
    }

    [Fact]
    public void Removed_block_is_reapplied()
    {
        var exe = CopyOfPing();
        _blocker.Block(exe, "test");
        // Someone strips the deny entry:
        var info = new FileInfo(exe);
        var acl = info.GetAccessControl();
        acl.RemoveAccessRuleAll(new System.Security.AccessControl.FileSystemAccessRule(
            new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.WorldSid, null),
            System.Security.AccessControl.FileSystemRights.ExecuteFile, System.Security.AccessControl.AccessControlType.Deny));
        info.SetAccessControl(acl);
        Assert.False(ExecutionBlocker.HasDenyExecute(exe));

        _blocker.Verify();
        Assert.True(ExecutionBlocker.HasDenyExecute(exe));
        Assert.Contains(_db.GetEvents(null, 10, false), e => e.Category == EventCategory.Tamper && e.Subject.Contains("re-applied"));
    }

    [Fact]
    public void Service_running_the_file_is_disabled_and_restored()
    {
        TestEnv.RequireElevation();
        var exe = CopyOfPing();
        var name = $"WGTestSvc{Guid.NewGuid():N}"[..20];
        Sc($"create {name} binPath= \"{exe}\" start= demand");
        try
        {
            Assert.Contains(name, ExecutionBlocker.ServicesUsing(exe));
            var item = _blocker.Block(exe, "test");
            Assert.Equal(name, Assert.Single(item.Services).Name);
            Assert.Equal(4, StartType(name)); // disabled

            _blocker.Unblock(item.Id);
            Assert.Equal(3, StartType(name)); // back to manual
        }
        finally
        {
            Sc($"delete {name}");
        }
    }

    private static int StartType(string service)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{service}");
        return (int)key!.GetValue("Start")!;
    }

    private static void Sc(string args)
    {
        using var p = Process.Start(new ProcessStartInfo("sc.exe", args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;
        p.WaitForExit(15_000);
    }
}
