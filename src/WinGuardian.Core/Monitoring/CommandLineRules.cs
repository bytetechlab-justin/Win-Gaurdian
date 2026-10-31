using System.Text.RegularExpressions;

namespace WinGuardian.Core.Monitoring;

/// <summary>
/// A small set of high-signal patterns for "living off the land" abuse: legitimate Windows tools
/// started with arguments commonly used by malware. Applied to every process start seen via ETW,
/// including processes that are already in the baseline.
/// </summary>
public static class CommandLineRules
{
    public sealed record Match(string Rule, Severity Severity);

    private sealed record Rule(string Name, Severity Severity, string[]? Images, Regex Pattern);

    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;

    private static readonly string[] PowerShell = ["powershell.exe", "pwsh.exe", "powershell_ise.exe"];

    private static readonly Rule[] Rules =
    [
        new("PowerShell download-and-execute", Severity.High, PowerShell,
            new Regex(@"(\biex\b|invoke-expression).*(downloadstring|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b)|(downloadstring|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b).*(\biex\b|invoke-expression)", Opts)),
        new("Encoded PowerShell command", Severity.Medium, PowerShell,
            new Regex(@"\s[-/]e[a-z]*\s+[A-Za-z0-9+/=]{40,}", Opts)),
        new("Microsoft Defender settings tampering", Severity.High, PowerShell,
            new Regex(@"(set|add)-mppreference\s.*-(disable\w*|exclusion\w*)", Opts)),
        new("certutil used to download or decode a file", Severity.High, ["certutil.exe"],
            new Regex(@"[-/](urlcache|decode|decodehex)\b", Opts)),
        new("mshta running remote or inline script", Severity.High, ["mshta.exe"],
            new Regex(@"(https?://|javascript:|vbscript:)", Opts)),
        new("regsvr32 loading a remote scriptlet", Severity.High, ["regsvr32.exe"],
            new Regex(@"/i:\s*(https?|ftp)://|scrobj\.dll", Opts)),
        new("rundll32 running inline script", Severity.High, ["rundll32.exe"],
            new Regex(@"javascript:|mshtml,RunHTMLApplication", Opts)),
        new("bitsadmin file transfer", Severity.Medium, ["bitsadmin.exe"],
            new Regex(@"/(transfer|addfile)\b", Opts)),
        new("Backup / shadow copy destruction (ransomware behaviour)", Severity.High, null,
            new Regex(@"vssadmin(\.exe)?\s+.*delete\s+shadows|shadowcopy\s+delete|wbadmin(\.exe)?\s+.*delete\s+(catalog|systemstatebackup)|bcdedit(\.exe)?\s+.*recoveryenabled\s+no", Opts)),
        new("Event log clearing", Severity.High, ["wevtutil.exe"],
            new Regex(@"\s(cl|clear-log)\s", Opts)),
    ];

    public static Match? Evaluate(string? imagePath, string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var image = imagePath is null ? null : Path.GetFileName(imagePath);

        foreach (var rule in Rules)
        {
            if (rule.Images is not null &&
                (image is null || !rule.Images.Contains(image, StringComparer.OrdinalIgnoreCase)))
                continue;
            if (rule.Pattern.IsMatch(commandLine))
                return new Match(rule.Name, rule.Severity);
        }
        return null;
    }
}
