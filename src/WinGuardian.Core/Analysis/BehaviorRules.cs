using System.Text.RegularExpressions;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Core.Analysis;

/// <summary>
/// Scores what a monitored program did. Most activity is ordinary (Info); these rules flag the places
/// malware goes: autostart locations, Windows system files and settings, security software settings,
/// saved passwords and cookies, ransomware-like file damage, and unusual network destinations.
/// </summary>
public static class BehaviorRules
{
    public sealed record Verdict(Severity Severity, string? Reason)
    {
        public static readonly Verdict Ordinary = new(Severity.Info, null);
    }

    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;

    // ------------------------------------------------------------------ registry

    private sealed record KeyRule(Regex Key, Regex? Value, Severity Severity, string Reason);

    // Matched against the normalized key (see NormalizeKeyForRules), first match wins.
    private static readonly KeyRule[] KeyRules =
    [
        new(new(@"\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce)(\\|$)", Opts), null,
            Severity.High, "Autostart: makes a program run automatically at sign-in"),
        new(new(@"\\Policies\\Explorer\\Run(\\|$)", Opts), null, Severity.High, "Autostart: makes a program run automatically at sign-in (policy)"),
        new(new(@"\\Windows NT\\CurrentVersion\\Winlogon(\\|$)", Opts), new(@"^(Shell|Userinit|Taskman|AppSetup|Notify)$", Opts),
            Severity.High, "Autostart: changes what Windows runs at sign-in (Winlogon)"),
        new(new(@"\\Windows NT\\CurrentVersion\\Windows$", Opts), new(@"^(AppInit_DLLs|LoadAppInit_DLLs|Load|Run)$", Opts),
            Severity.High, "Autostart: loads a DLL into programs / runs at sign-in"),
        new(new(@"\\Image File Execution Options\\", Opts), null, Severity.High, "Hijacks another program's start-up (Image File Execution Options)"),
        new(new(@"\\SilentProcessExit\\", Opts), null, Severity.High, "Runs a program when another program exits (SilentProcessExit)"),
        new(new(@"\\Schedule\\TaskCache\\", Opts), null, Severity.High, "Creates or changes a scheduled task"),
        new(new(@"\\Services\\SharedAccess\\Parameters\\FirewallPolicy(\\|$)", Opts), null, Severity.High, "Changes Windows Firewall settings or rules"),
        new(new(@"\\CurrentControlSet\\Services\\", Opts), null, Severity.High, "Installs or changes a Windows service or driver"),
        new(new(@"\\CurrentControlSet\\Control\\Session Manager(\\|$)", Opts), new(@"^(BootExecute|SetupExecute|Execute|PendingFileRenameOperations|AppCertDlls)$", Opts),
            Severity.High, "Runs or replaces something during Windows start-up (Session Manager)"),
        new(new(@"\\CurrentControlSet\\Control\\Session Manager\\(AppCertDlls|KnownDLLs)(\\|$)", Opts), null,
            Severity.High, "Changes which DLLs Windows loads into programs"),
        new(new(@"\\CurrentControlSet\\Control\\(Lsa|SecurityProviders|SafeBoot|Print\\Monitors|NetworkProvider)(\\|$)", Opts), null,
            Severity.High, "Changes a Windows security or start-up component (credential theft / persistence location)"),
        new(new(@"\\(Policies\\)?Microsoft\\Windows Defender(\\|$)", Opts), null, Severity.High, "Changes Microsoft Defender settings (e.g. exclusions or turning it off)"),
        new(new(@"\\Active Setup\\Installed Components\\", Opts), null, Severity.High, "Autostart: runs a command when users sign in (Active Setup)"),
        new(new(@"\\Microsoft\\Command Processor$", Opts), new(@"^AutoRun$", Opts), Severity.High, "Runs a command every time cmd.exe starts"),
        new(new(@"^HKCU\\Environment$", Opts), new(@"^UserInitMprLogonScript$", Opts), Severity.High, "Autostart: logon script"),
        new(new(@"\\Policies\\System(\\|$)", Opts), null, Severity.High, "Changes Windows security policy (UAC, Task Manager, registry editor...)"),
        new(new(@"\\Classes\\(ms-settings|mscfile|exefile|batfile|cmdfile|comfile|htafile|vbsfile|jsfile|piffile|scrfile|Folder|\.exe|\.bat|\.cmd)\\shell\\", Opts), null,
            Severity.High, "Hijacks how Windows opens programs or system tools (also a known UAC bypass)"),
        new(new(@"\\Classes\\CLSID\\[^\\]+\\(InprocServer32|LocalServer32|TreatAs)(\\|$)", Opts), null,
            Severity.Medium, "Registers or redirects a COM component (can be used to load code into other programs)"),
        new(new(@"\\Classes\\[^\\]+\\shell\\[^\\]+\\command(\\|$)", Opts), null, Severity.Medium, "Changes which program opens a type of file"),
        new(new(@"\\Explorer\\(User )?Shell Folders$", Opts), new(@"Startup", Opts), Severity.High, "Moves the Startup folder"),
        new(new(@"\\Internet Settings(\\|$)", Opts), new(@"^(ProxyServer|ProxyEnable|AutoConfigURL|ProxyOverride)$", Opts),
            Severity.Medium, "Changes the proxy settings (can redirect web traffic)"),
        new(new(@"\\SystemCertificates\\(Root|AuthRoot|CA|TrustedPublisher)\\Certificates\\", Opts), null,
            Severity.Medium, "Adds or changes a trusted certificate (can be used to intercept HTTPS)"),
        new(new(@"\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\", Opts), null, Severity.Info, "Registers itself as an installed program"),
    ];

    /// <summary>
    /// Turns a kernel registry path (\REGISTRY\MACHINE\..., \REGISTRY\USER\S-1-5-...\...) into the familiar
    /// HKLM / HKCU / HKU form. Keys of <paramref name="userSid"/> become HKCU.
    /// </summary>
    public static string FriendlyKey(string kernelPath, string? userSid)
    {
        var path = kernelPath.TrimEnd('\\');
        const string machine = @"\REGISTRY\MACHINE";
        const string user = @"\REGISTRY\USER";
        if (path.StartsWith(machine, StringComparison.OrdinalIgnoreCase))
            return "HKLM" + path[machine.Length..];
        if (!path.StartsWith(user, StringComparison.OrdinalIgnoreCase))
            return path;

        var rest = path[user.Length..].TrimStart('\\'); // "<sid>[_Classes][\...]"
        var slash = rest.IndexOf('\\');
        var hive = slash < 0 ? rest : rest[..slash];
        var tail = slash < 0 ? "" : rest[slash..];
        if (userSid is not null)
        {
            if (hive.Equals(userSid, StringComparison.OrdinalIgnoreCase)) return "HKCU" + tail;
            if (hive.Equals(userSid + "_Classes", StringComparison.OrdinalIgnoreCase)) return @"HKCU\Software\Classes" + tail;
        }
        return @"HKU\" + rest;
    }

    /// <summary>ControlSet001 → CurrentControlSet, drops WOW6432Node, so one rule covers every spelling.</summary>
    public static string NormalizeKeyForRules(string friendlyKey)
    {
        var key = Regex.Replace(friendlyKey, @"\\ControlSet\d{3}\\", @"\CurrentControlSet\", RegexOptions.IgnoreCase);
        return key.Replace(@"\WOW6432Node", "", StringComparison.OrdinalIgnoreCase);
    }

    public static Verdict ForRegistry(string friendlyKey, string? valueName, RegistryOperation operation, bool failed)
    {
        if (operation == RegistryOperation.KeyOpened) return Verdict.Ordinary;

        var key = NormalizeKeyForRules(friendlyKey);
        foreach (var rule in KeyRules)
        {
            if (!rule.Key.IsMatch(key)) continue;
            // Value-specific rules only apply to value changes; creating/deleting the key itself still counts.
            if (rule.Value is not null && valueName is not null && !rule.Value.IsMatch(valueName)) continue;
            if (rule.Value is not null && valueName is null && operation is not (RegistryOperation.KeyDeleted or RegistryOperation.KeyCreated)) continue;
            var (severity, reason) = operation is RegistryOperation.ValueDeleted or RegistryOperation.KeyDeleted
                ? (rule.Severity == Severity.High ? Severity.Medium : rule.Severity, "Removes an entry from a sensitive location: " + rule.Reason)
                : (rule.Severity, rule.Reason);
            return new(severity, failed ? reason + " (Windows refused the change)" : reason);
        }

        if (failed) return new(Severity.Info, "Windows refused the change");
        return key.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase)
            ? new(Severity.Low, "Machine-wide setting (affects all users)")
            : Verdict.Ordinary;
    }

    // ---------------------------------------------------------------------- files

    private static readonly string WindowsDir = GuardianPaths.Normalize("%WINDIR%").TrimEnd('\\') + "\\";

    private static readonly Regex StartupFolder = new(@"\\Start Menu\\Programs\\Startup\\", Opts);
    private static readonly Regex Hosts = new(@"\\System32\\drivers\\etc\\hosts$", Opts);
    private static readonly Regex Tasks = new(@"\\Windows\\(System32\\|SysWOW64\\)?Tasks\\", Opts);
    private static readonly Regex HarmlessWindowsAreas = new(@"\\Windows\\(Temp|Prefetch|Logs|SoftwareDistribution|ServiceProfiles|Installer|Panther|INF\\setupapi)", Opts);

    /// <summary>Saved passwords, cookies, keys and wallets: reading these is how info-stealers work.</summary>
    private static readonly Regex Secrets = new(
        @"\\User Data\\[^\\]+\\(Login Data|Cookies|Web Data|Network\\Cookies)$|\\User Data\\Local State$" +
        @"|\\Firefox\\Profiles\\[^\\]+\\(logins\.json|key4\.db|cookies\.sqlite|cert9\.db)$" +
        @"|\\Microsoft\\(Credentials|Protect|Vault)\\" +
        @"|\\wallet\.dat$|\\(Exodus|Electrum|atomic|Ethereum)\\" +
        @"|\\Telegram Desktop\\tdata\\|\\discord\\Local Storage\\leveldb\\" +
        @"|\\\.ssh\\id_|\\FileZilla\\(recentservers|sitemanager)\.xml$", Opts);

    /// <summary>Programs that legitimately read their own saved logins/cookies.</summary>
    private static readonly HashSet<string> SecretOwners = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "discord", "telegram", "filezilla", "ssh", "git", "lsass", "svchost",
        "msedgewebview2", "searchprotocolhost", "searchindexer", "msmpeng",
    };

    public static Verdict ForFile(string path, FileOperation operation, string processName)
    {
        if (Secrets.IsMatch(path) && !SecretOwners.Contains(processName))
            return new(Severity.High, "Accesses saved passwords, cookies or keys (how password-stealing malware works)");
        if (operation == FileOperation.Opened) return Verdict.Ordinary;

        var changed = operation is FileOperation.Created or FileOperation.Modified or FileOperation.Renamed;
        if (StartupFolder.IsMatch(path))
            return new(changed ? Severity.High : Severity.Medium, "Autostart: Startup folder (runs at sign-in)");
        if (Hosts.IsMatch(path))
            return new(Severity.High, "Changes the hosts file (can redirect websites)");
        if (Tasks.IsMatch(path))
            return new(Severity.High, "Creates or changes a scheduled task");
        if (path.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase) && operation != FileOperation.FolderCreated)
            return HarmlessWindowsAreas.IsMatch(path)
                ? new(Severity.Low, "Windows folder (working/cache area)")
                : new(Severity.High, "Changes a file in the Windows folder");
        if (SeverityRules.IsExecutable(path) && changed)
        {
            if (path.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase))
                return new(Severity.Low, "Installs a program file");
            return SeverityRules.IsUserWritable(path)
                ? new(Severity.Medium, "Drops a program or script file in a user-writable folder")
                : new(Severity.Medium, "Drops a program or script file");
        }
        return Verdict.Ordinary;
    }

    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".odt", ".ods", ".csv",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".heic", ".mp3", ".mp4", ".mov", ".zip", ".7z", ".rar", ".psd",
    };

    public static bool IsUserDocument(string path) =>
        DocumentExtensions.Contains(Path.GetExtension(path)) &&
        path.Contains(@"\Users\", StringComparison.OrdinalIgnoreCase) &&
        !path.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase);

    /// <summary>Changing or removing this many existing user documents in one run looks like ransomware.</summary>
    public const int RansomwareDocumentThreshold = 25;

    // -------------------------------------------------------------------- processes

    private static readonly HashSet<string> SystemTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
        "schtasks.exe", "sc.exe", "reg.exe", "netsh.exe", "bcdedit.exe", "vssadmin.exe", "wmic.exe", "certutil.exe",
        "bitsadmin.exe", "wevtutil.exe", "net.exe", "net1.exe", "taskkill.exe", "icacls.exe", "takeown.exe", "attrib.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "cmstp.exe", "whoami.exe", "systeminfo.exe", "nltest.exe",
    };

    private static readonly (Regex Pattern, string Reason)[] HighRiskCommands =
    [
        (new(@"schtasks(\.exe)?\s.*/create", Opts), "Creates a scheduled task"),
        (new(@"\bsc(\.exe)?\s+(\\\\\S+\s+)?(create|config)\b", Opts), "Creates or reconfigures a Windows service"),
        (new(@"\breg(\.exe)?\s+add\s+.*\\(Run|RunOnce|Winlogon|Image File Execution Options)\b", Opts), "Adds an autostart registry entry"),
        (new(@"netsh(\.exe)?\s+.*(advfirewall|firewall)\s+.*(add|set|delete)", Opts), "Changes Windows Firewall"),
        (new(@"\bnet1?(\.exe)?\s+(user|localgroup)\s+.*/add", Opts), "Creates a user account or adds to a group"),
        (new(@"\b(icacls|takeown)(\.exe)?\s.*\\Windows\\", Opts), "Takes ownership of / changes permissions on Windows files"),
        (new(@"\battrib(\.exe)?\s.*\+[sh]", Opts), "Hides files"),
    ];

    public static Verdict ForProcess(string? imagePath, string? commandLine, bool isRoot, SignatureInfo? signature)
    {
        if (CommandLineRules.Evaluate(imagePath, commandLine) is { } match)
            return new(match.Severity, match.Rule);
        if (commandLine is not null)
        {
            foreach (var (pattern, reason) in HighRiskCommands)
                if (pattern.IsMatch(commandLine)) return new(Severity.High, reason);
        }
        if (signature?.Status == SignatureStatus.Tampered)
            return new(Severity.High, "Its digital signature is broken (the file was modified after signing)");
        if (!isRoot && imagePath is not null && SystemTools.Contains(Path.GetFileName(imagePath)))
            return new(Severity.Medium, "Starts a Windows command-line tool");
        if (!isRoot && imagePath is not null && signature is { IsValid: false } && SeverityRules.IsUserWritable(imagePath))
            return new(Severity.Medium, "Starts an unsigned program from a user-writable folder");
        return Verdict.Ordinary;
    }

    // ---------------------------------------------------------------------- network

    private static readonly HashSet<int> CommonPorts = [53, 80, 443, 123, 853, 5353, 5355, 1900, 3478, 137, 138];

    /// <summary>Ports associated with remote-control tools, IRC botnets, Tor and similar.</summary>
    private static readonly HashSet<int> SuspiciousPorts = [4444, 4445, 1337, 31337, 6666, 6667, 6668, 6669, 9001, 9030, 9050, 9150, 5555, 8888, 1604, 3460];

    private static readonly Regex AbusedServices = new(
        @"(^|\.)(duckdns\.org|no-ip\.(com|org|biz)|ddns\.net|hopto\.org|zapto\.org|ngrok(-free)?\.(io|app)|trycloudflare\.com|pastebin\.com|" +
        @"paste\.ee|transfer\.sh|anonfiles\.com|api\.telegram\.org|discord(app)?\.com|cdn\.discordapp\.com|raw\.githubusercontent\.com|" +
        @"ipify\.org|ipinfo\.io|ip-api\.com|icanhazip\.com|checkip\.amazonaws\.com|myexternalip\.com|portmap\.io)$", Opts);

    public static Verdict ForConnection(string remoteAddress, int remotePort, bool inbound, string? hostName)
    {
        if (inbound)
        {
            // Many programs connect to themselves over 127.0.0.1 (e.g. curl's internal wake-up socket); only the
            // network counts.
            return System.Net.IPAddress.TryParse(remoteAddress, out var peer) && System.Net.IPAddress.IsLoopback(peer)
                ? Verdict.Ordinary
                : new(Severity.Medium, "Accepts incoming connections from the network");
        }
        if (SuspiciousPorts.Contains(remotePort))
            return new(Severity.Medium, $"Port {remotePort} is commonly used by remote-control malware, botnets or Tor");
        if (hostName is not null && AbusedServices.IsMatch(hostName))
            return new(Severity.Medium, "A service often abused by malware (file sharing, chat bots, IP lookup, dynamic DNS, tunnels)");
        if (hostName is null && !IsLocal(remoteAddress))
            return new(Severity.Low, CommonPorts.Contains(remotePort)
                ? "Connects to an IP address without looking up a name first"
                : $"Connects to an IP address without looking up a name, on unusual port {remotePort}");
        if (!CommonPorts.Contains(remotePort) && !IsLocal(remoteAddress))
            return new(Severity.Low, $"Unusual port {remotePort}");
        return Verdict.Ordinary;
    }

    public static Verdict ForDnsName(string name) =>
        AbusedServices.IsMatch(name.TrimEnd('.'))
            ? new(Severity.Medium, "A service often abused by malware (file sharing, chat bots, IP lookup, dynamic DNS, tunnels)")
            : Verdict.Ordinary;

    public static bool IsLocal(string address) =>
        System.Net.IPAddress.TryParse(address, out var ip) &&
        (System.Net.IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal ||
         (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && ip.GetAddressBytes() is var b &&
          (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254))));
}
