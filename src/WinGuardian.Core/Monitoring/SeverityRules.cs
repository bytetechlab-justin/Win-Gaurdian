namespace WinGuardian.Core.Monitoring;

/// <summary>
/// Risk scoring. Location sets the starting point; the file's Authenticode signature then moves it:
/// Microsoft-signed content is routine (e.g. Windows Update), other valid publishers are less alarming,
/// unsigned content keeps its score, and a broken signature (file modified after signing) is always High.
/// </summary>
public static class SeverityRules
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".scr", ".com", ".efi", ".msi", ".msp",
        ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar",
    };

    private static readonly string WindowsDir = GuardianPaths.Normalize("%WINDIR%");
    private static readonly string[] SystemBinaryDirs =
    [
        Path.Combine(WindowsDir, "System32"),
        Path.Combine(WindowsDir, "SysWOW64"),
    ];

    private static readonly string[] UserWritableMarkers =
        [@"\Users\", @"\ProgramData\", @"\Temp\", @"\AppData\", @"\Downloads\", @"\$Recycle.Bin\"];

    public static bool IsExecutable(string path) => ExecutableExtensions.Contains(Path.GetExtension(path));

    public static Severity ForFile(string path, ChangeKind change, SignatureInfo? signature = null)
    {
        if (!IsExecutable(path)) return Severity.Low;
        if (change == ChangeKind.Removed) return Severity.Medium;

        var baseline = IsUnder(path, SystemBinaryDirs) || IsDirectChild(path, WindowsDir) ? Severity.High : Severity.Medium;
        return signature?.Status switch
        {
            SignatureStatus.Tampered => Severity.High,
            SignatureStatus.Valid when signature.IsMicrosoft => Severity.Low,
            SignatureStatus.Valid => Min(baseline, Severity.Medium),
            _ => baseline,
        };
    }

    public static Severity ForNewProcess(string? imagePath, SignatureInfo? signature = null)
    {
        if (imagePath is null) return Severity.Low;
        if (signature?.Status == SignatureStatus.Tampered) return Severity.High;
        var signed = signature?.IsValid == true;

        // Note: a renamed copy of a Microsoft binary is still validly signed (catalog signing is by content),
        // so a valid signature never makes a program running from a user folder fully routine.
        if (IsUserWritable(imagePath))
            return signed ? Severity.Medium : Severity.High;
        if (IsUnder(imagePath, [WindowsDir]))
            return signature?.IsMicrosoft == true ? Severity.Info : signed ? Severity.Low : Severity.Medium;
        if (imagePath.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase))
            return signed ? Severity.Info : Severity.Low;
        return signed ? Severity.Low : Severity.Medium;
    }

    /// <summary>Signed Microsoft programs that run arbitrary code given to them on the command line.</summary>
    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "conhost.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "forfiles.exe", "schtasks.exe",
    };

    /// <summary>
    /// For new or changed services and autostart entries, scored by the binary they launch. A trusted
    /// signature on a script host (e.g. "cmd.exe /c ...") says nothing about what it will run, so those are
    /// never downgraded, and a change to an existing entry never drops below Medium.
    /// </summary>
    public static Severity ForLaunchTarget(Severity baseline, ChangeKind change, string? target, SignatureInfo? signature)
    {
        if (signature?.Status == SignatureStatus.Tampered) return Severity.High;
        if (signature?.IsValid != true || (target is not null && ScriptHosts.Contains(Path.GetFileName(target))))
            return baseline;
        var floor = change == ChangeKind.Modified ? Severity.Medium : Severity.Low;
        var reduced = signature.IsMicrosoft ? Severity.Low : Severity.Medium;
        return Min(baseline, reduced < floor ? floor : reduced);
    }

    public static bool IsUserWritable(string path) =>
        UserWritableMarkers.Any(m => path.Contains(m, StringComparison.OrdinalIgnoreCase));

    /// <summary>Verifies the event's file (if it is an executable that still exists) and records the result on the event.</summary>
    public static SignatureInfo? Sign(GuardianEvent e)
    {
        if (e.FilePath is null || !IsExecutable(e.FilePath) || !File.Exists(e.FilePath)) return null;
        var signature = SignatureVerifier.Verify(e.FilePath);
        e.Signature = signature.Describe();
        e.Signer = signature.IsValid ? signature.Signer : null;
        return signature;
    }

    private static Severity Min(Severity a, Severity b) => a < b ? a : b;

    private static bool IsUnder(string path, IEnumerable<string> dirs) =>
        dirs.Any(d => path.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase));

    private static bool IsDirectChild(string path, string dir) =>
        string.Equals(Path.GetDirectoryName(path), dir, StringComparison.OrdinalIgnoreCase);
}
