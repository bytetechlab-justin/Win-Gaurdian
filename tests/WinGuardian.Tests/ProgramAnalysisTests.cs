using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using WinGuardian.Core;
using WinGuardian.Core.Analysis;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Tests;

public class BehaviorRulesTests
{
    private const string Sid = "S-1-5-21-1-2-3-1001";

    [Theory]
    [InlineData(@"\REGISTRY\MACHINE\SOFTWARE\Foo", @"HKLM\SOFTWARE\Foo")]
    [InlineData(@"\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\Foo", @"HKCU\Software\Foo")]
    [InlineData(@"\REGISTRY\USER\S-1-5-21-1-2-3-1001_Classes\CLSID\{X}", @"HKCU\Software\Classes\CLSID\{X}")]
    [InlineData(@"\REGISTRY\USER\S-1-5-21-9-9-9-500\Software", @"HKU\S-1-5-21-9-9-9-500\Software")]
    [InlineData(@"\REGISTRY\USER\S-1-5-21-1-2-3-1001", "HKCU")]
    [InlineData(@"(unknown key)\Foo", @"(unknown key)\Foo")]
    public void FriendlyKey_UsesFamiliarHiveNames(string kernel, string expected) =>
        Assert.Equal(expected, BehaviorRules.FriendlyKey(kernel, Sid));

    [Theory]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Updater", Severity.High)]
    [InlineData(@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "x", Severity.High)]
    [InlineData(@"HKLM\SYSTEM\ControlSet001\Services\EvilSvc", "ImagePath", Severity.High)]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "Debugger", Severity.High)]
    [InlineData(@"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", Severity.High)]
    [InlineData(@"HKCU\Software\Classes\ms-settings\shell\open\command", "", Severity.High)]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", Severity.High)]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "LastUsedUsername", Severity.Low)]
    [InlineData(@"HKCU\Software\Classes\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32", "", Severity.Medium)]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer", Severity.Medium)]
    [InlineData(@"HKCU\Software\SomeVendor\App", "WindowPos", Severity.Info)]
    [InlineData(@"HKLM\SOFTWARE\SomeVendor\App", "InstallDir", Severity.Low)]
    public void ForRegistry_FlagsSensitiveLocations(string key, string value, Severity expected) =>
        Assert.Equal(expected, BehaviorRules.ForRegistry(key, value, RegistryOperation.ValueSet, failed: false).Severity);

    [Fact]
    public void ForRegistry_RemovingAnAutostartIsReportedAsRemoval()
    {
        var verdict = BehaviorRules.ForRegistry(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Updater", RegistryOperation.ValueDeleted, false);
        Assert.Equal(Severity.Medium, verdict.Severity);
        Assert.StartsWith("Removes", verdict.Reason);
    }

    [Fact]
    public void ForRegistry_RefusedChangeIsStillFlaggedButSaysSo()
    {
        var verdict = BehaviorRules.ForRegistry(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "x", RegistryOperation.ValueSet, failed: true);
        Assert.Equal(Severity.High, verdict.Severity);
        Assert.Contains("refused", verdict.Reason);
    }

    [Fact]
    public void ForRegistry_ReadsAreNeverFlagged() =>
        Assert.Equal(Severity.Info,
            BehaviorRules.ForRegistry(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", null, RegistryOperation.KeyOpened, false).Severity);

    [Fact]
    public void ForFile_FlagsAutostartSystemAndCredentialLocations()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        Assert.Equal(Severity.High, BehaviorRules.ForFile(Path.Combine(startup, "evil.lnk"), FileOperation.Created, "setup").Severity);
        Assert.Equal(Severity.High, BehaviorRules.ForFile(Path.Combine(windows, @"System32\evil.dll"), FileOperation.Created, "setup").Severity);
        Assert.Equal(Severity.High, BehaviorRules.ForFile(Path.Combine(windows, @"System32\drivers\etc\hosts"), FileOperation.Modified, "setup").Severity);
        Assert.Equal(Severity.Low, BehaviorRules.ForFile(Path.Combine(windows, @"Temp\x.tmp"), FileOperation.Created, "setup").Severity);
        Assert.Equal(Severity.Medium, BehaviorRules.ForFile(Path.Combine(appData, @"Temp\payload.exe"), FileOperation.Created, "setup").Severity);
        Assert.Equal(Severity.Info, BehaviorRules.ForFile(Path.Combine(appData, @"Temp\notes.txt"), FileOperation.Created, "setup").Severity);
        Assert.Equal(Severity.Info, BehaviorRules.ForFile(Path.Combine(windows, @"System32\kernel32.dll"), FileOperation.Opened, "setup").Severity);

        var chromeLogins = Path.Combine(appData, @"Google\Chrome\User Data\Default\Login Data");
        Assert.Equal(Severity.High, BehaviorRules.ForFile(chromeLogins, FileOperation.Opened, "freegame").Severity);
        Assert.Equal(Severity.Info, BehaviorRules.ForFile(chromeLogins, FileOperation.Opened, "chrome").Severity);
    }

    [Fact]
    public void ForProcess_FlagsToolsAndDangerousCommandLines()
    {
        var system = Environment.SystemDirectory;
        Assert.Equal(Severity.High, BehaviorRules.ForProcess(Path.Combine(system, "schtasks.exe"),
            @"schtasks /create /tn Updater /tr C:\Users\me\AppData\x.exe /sc onlogon", isRoot: false, null).Severity);
        Assert.Equal(Severity.High, BehaviorRules.ForProcess(Path.Combine(system, "vssadmin.exe"),
            "vssadmin delete shadows /all /quiet", isRoot: false, null).Severity);
        Assert.Equal(Severity.Medium, BehaviorRules.ForProcess(Path.Combine(system, "cmd.exe"), "cmd /c dir", isRoot: false, null).Severity);
        Assert.Equal(Severity.Info, BehaviorRules.ForProcess(Path.Combine(system, "cmd.exe"), "cmd /c dir", isRoot: true, null).Severity);
    }

    [Theory]
    [InlineData("93.184.216.34", 443, "example.com", Severity.Info)]
    [InlineData("93.184.216.34", 443, null, Severity.Low)]
    [InlineData("93.184.216.34", 4444, "example.com", Severity.Medium)]
    [InlineData("1.2.3.4", 443, "myhost.duckdns.org", Severity.Medium)]
    [InlineData("192.168.1.10", 445, null, Severity.Info)]
    public void ForConnection_FlagsUnusualDestinations(string address, int port, string? host, Severity expected) =>
        Assert.Equal(expected, BehaviorRules.ForConnection(address, port, inbound: false, host).Severity);

    [Fact]
    public void ForConnection_InboundIsFlaggedUnlessFromThisPC()
    {
        Assert.Equal(Severity.Medium, BehaviorRules.ForConnection("8.8.8.8", 8080, inbound: true, null).Severity);
        Assert.Equal(Severity.Info, BehaviorRules.ForConnection("127.0.0.1", 63421, inbound: true, null).Severity);
        Assert.Equal(Severity.Info, BehaviorRules.ForConnection("::1", 63421, inbound: true, null).Severity);
    }
}

public class AnalysisFormattingTests
{
    [Fact]
    public void KernelNetworkFields_AreDecodedFromNetworkByteOrder()
    {
        // Values exactly as Microsoft-Windows-Kernel-Network reported a connection to 172.66.147.243:443.
        Assert.Equal("172.66.147.243", ProgramAnalyzer.Address(-208452948));
        Assert.Equal(443, ProgramAnalyzer.Port(-17663));
        Assert.Equal("2606:4700:10::6814:179a",
            ProgramAnalyzer.Address(System.Net.IPAddress.Parse("2606:4700:10::6814:179a").GetAddressBytes()));
        Assert.Null(ProgramAnalyzer.Address(null));
    }

    [Fact]
    public void RegistryValues_AreFormattedByType()
    {
        Assert.Equal(@"C:\x.exe", RegistryValueFormatter.Format(1, System.Text.Encoding.Unicode.GetBytes("C:\\x.exe\0"), 18));
        Assert.Equal("42 (0x2A)", RegistryValueFormatter.Format(4, BitConverter.GetBytes(42), 4));
        Assert.Equal("a | b", RegistryValueFormatter.Format(7, System.Text.Encoding.Unicode.GetBytes("a\0b\0\0"), 10));
        Assert.Equal("0102 ... (100 bytes in total)", RegistryValueFormatter.Format(3, [1, 2], 100));
        Assert.Equal("REG_EXPAND_SZ", RegistryValueFormatter.TypeName(2));
    }

    [Theory]
    [InlineData(@"C:\a\setup.exe", "-q", @"C:\a\setup.exe", "\"C:\\a\\setup.exe\" -q")]
    [InlineData(@"C:\a\run.bat", "", "cmd.exe", "cmd.exe /c \"\"C:\\a\\run.bat\"\"")]
    [InlineData(@"C:\a\x.ps1", "", "powershell.exe", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"C:\\a\\x.ps1\"")]
    [InlineData(@"C:\a\pkg.msi", "/qn", "msiexec.exe", "msiexec.exe /i \"C:\\a\\pkg.msi\" /qn")]
    public void Launcher_StartsScriptsThroughTheirHost(string path, string args, string expectedExe, string expectedCommand)
    {
        var (exe, command) = SuspendedLauncher.BuildCommand(path, args);
        Assert.EndsWith(expectedExe, exe, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(expectedCommand, command);
    }

    [Fact]
    public void Launcher_RejectsDocuments() =>
        Assert.Throws<NotSupportedException>(() => SuspendedLauncher.BuildCommand(@"C:\a\letter.docx", ""));

    [Fact]
    public void Findings_DetectRansomwareLikeDamageAndOrderBySeverity()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var report = new AnalysisReport
        {
            Files = Enumerable.Range(0, BehaviorRules.RansomwareDocumentThreshold)
                .Select(i => new FileActivity { Path = Path.Combine(profile, $@"Documents\file{i}.docx"), Operation = FileOperation.Renamed })
                .ToList(),
            Network = [new NetworkActivity { Protocol = "TCP", RemoteAddress = "1.2.3.4", RemotePort = 4444, Severity = Severity.Medium, Reason = "port" }],
        };
        var findings = AnalysisReportFormatter.Findings(report);
        Assert.Equal(2, findings.Count);
        Assert.Equal(Severity.High, findings[0].Severity);
        Assert.Contains("documents", findings[0].Text);

        var text = AnalysisReportFormatter.Build(report, maxChars: 1500);
        Assert.True(text.Length <= 1500 + 30);
        Assert.Contains("FINDINGS (2)", text);
    }
}

/// <summary>Runs a real program under the analyzer (needs administrator rights for kernel tracing).</summary>
public class ProgramAnalyzerIntegrationTests : IDisposable
{
    private readonly string _work = Path.Combine(Path.GetTempPath(), "wg-tests", Guid.NewGuid().ToString("N"));
    private readonly string _key = @"Software\WinGuardianTests\" + Guid.NewGuid().ToString("N");

    public void Dispose()
    {
        try { Directory.Delete(_work, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        Registry.CurrentUser.DeleteSubKeyTree(_key, throwOnMissingSubKey: false);
    }

    [Fact]
    public async Task RecordsFilesRegistryAndChildProcesses()
    {
        TestEnv.RequireElevation();
        Directory.CreateDirectory(_work);
        var script = Path.Combine(_work, "behave.cmd");
        var output = Path.Combine(_work, "dropped.exe");
        File.WriteAllText(script,
            "@echo off\r\n" +
            $"echo MZ> \"{output}\"\r\n" +
            $"reg add \"HKCU\\{_key}\" /v Marker /d WinGuardianTestValue /f >nul\r\n" +
            "ping -n 3 127.0.0.1 >nul\r\n");

        var db = new GuardianDatabase(Path.Combine(_work, "analysis.db"));
        db.Initialize();
        using var analyzer = new ProgramAnalyzer(db, new ProcessHistory(), NullLogger<ProgramAnalyzer>.Instance);
        using var launcher = SuspendedLauncher.Start(script, null, _work);
        var id = analyzer.Start(launcher.ProcessId, Environment.ProcessId, TestEnv.CurrentUserSid);
        launcher.Resume();

        AnalysisReport? report = null;
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(30))
        {
            await Task.Delay(500, TestContext.Current.CancellationToken);
            report = analyzer.GetReport(id, includeReads: false, TestEnv.CurrentUserSid, requesterIsAdmin: false);
            if (report?.State == AnalysisState.Finished) break;
        }

        Assert.NotNull(report);
        Assert.Equal(AnalysisState.Finished, report.State);
        Assert.Contains(report.Processes, p => p.ImagePath?.EndsWith("reg.exe", StringComparison.OrdinalIgnoreCase) == true);
        Assert.Contains(report.Files, f => f.Operation == FileOperation.Created && f.Path.Equals(output, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Registry, r => r.Operation == RegistryOperation.ValueSet && r.Key == @"HKCU\" + _key &&
                                              r.ValueName == "Marker" && r.Data == "WinGuardianTestValue");

        // Someone else's analysis is not readable.
        Assert.Null(analyzer.GetReport(id, false, "S-1-5-21-0-0-0-9999", requesterIsAdmin: false));
    }

    [Fact]
    public void RefusesToMonitorAProcessTheCallerDidNotStart()
    {
        TestEnv.RequireElevation();
        Directory.CreateDirectory(_work);
        var db = new GuardianDatabase(Path.Combine(_work, "analysis.db"));
        db.Initialize();
        using var analyzer = new ProgramAnalyzer(db, new ProcessHistory(), NullLogger<ProgramAnalyzer>.Instance);
        var explorer = Process.GetProcessesByName("explorer").FirstOrDefault()?.Id ?? Process.GetProcessesByName("winlogon")[0].Id;
        Assert.Throws<InvalidOperationException>(() => analyzer.Start(explorer, Environment.ProcessId, TestEnv.CurrentUserSid));
    }
}
