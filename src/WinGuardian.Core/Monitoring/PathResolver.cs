using System.Runtime.InteropServices;
using System.Text;

namespace WinGuardian.Core.Monitoring;

/// <summary>Turns command lines, service image paths and NT device paths into real file paths.</summary>
public static class PathResolver
{
    private static readonly string WindowsDir = GuardianPaths.Normalize("%WINDIR%");
    private static readonly string System32 = Path.Combine(WindowsDir, "System32");
    private static readonly string[] HostBinaries = ["rundll32.exe", "regsvr32.exe"];

    /// <summary>
    /// Best-effort extraction of the executable (or, for rundll32/regsvr32, the DLL) that a command line runs.
    /// Handles quoting, unquoted paths with spaces, environment variables, \SystemRoot\ and \??\ prefixes,
    /// and bare names found in System32. Returns null if no existing file can be identified.
    /// </summary>
    public static string? ExtractExecutablePath(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var text = NormalizePrefixes(Environment.ExpandEnvironmentVariables(commandLine.Trim()));

        string? exe;
        string rest;
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            exe = end > 0 ? text[1..end] : text[1..];
            rest = end > 0 ? text[(end + 1)..] : "";
            exe = ResolveFile(exe);
        }
        else
        {
            // Unquoted: try the longest prefix (at a space boundary) that names an existing file.
            exe = null;
            rest = "";
            var spaces = AllIndexesOf(text, ' ').Append(text.Length).Reverse();
            foreach (var cut in spaces)
            {
                if (ResolveFile(text[..cut]) is { } found)
                {
                    exe = found;
                    rest = text[cut..];
                    break;
                }
            }
        }

        if (exe is null) return null;

        // rundll32 "x.dll",Entry  /  regsvr32 /s x.dll: what matters is the DLL.
        if (HostBinaries.Contains(Path.GetFileName(exe), StringComparer.OrdinalIgnoreCase))
        {
            var args = rest.Trim();
            foreach (var token in Tokenize(args))
            {
                if (token.StartsWith('/') || token.StartsWith('-')) continue;
                var candidate = token.Split(',')[0].Trim();
                if (ResolveFile(candidate) is { } dll) return dll;
                break;
            }
        }
        return exe;
    }

    /// <summary>
    /// The program path as written at the start of a command line, even if the file no longer exists
    /// (e.g. a process that deleted itself or was already quarantined). Only absolute paths are returned.
    /// </summary>
    public static string? FirstTokenPath(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var text = commandLine.Trim();
        string token;
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            token = end > 0 ? text[1..end] : text[1..];
        }
        else
        {
            var exe = text.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            token = exe > 0 ? text[..(exe + 4)] : text.Split(' ')[0];
        }
        token = NormalizePrefixes(token);
        return token.Length > 2 && token[1] == ':' ? token : null;
    }

    /// <summary>Converts \Device\HarddiskVolumeN\... (as reported by the kernel) to C:\...</summary>
    public static string? FromNtPath(string? ntPath)
    {
        if (string.IsNullOrEmpty(ntPath)) return null;
        var normalized = NormalizePrefixes(ntPath);
        if (normalized.Length > 2 && normalized[1] == ':') return normalized;

        foreach (var (device, drive) in DeviceMap.Value)
        {
            if (ntPath.StartsWith(device + "\\", StringComparison.OrdinalIgnoreCase))
                return drive + ntPath[device.Length..];
        }
        return null;
    }

    private static string NormalizePrefixes(string path)
    {
        if (path.StartsWith(@"\??\")) path = path[4..];
        if (path.StartsWith(@"\\?\")) path = path[4..];
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) path = WindowsDir + path[11..];
        else if (path.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase)) path = WindowsDir + "\\" + path[11..];
        else if (path.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)) path = Path.Combine(WindowsDir, path);
        return path;
    }

    private static string? ResolveFile(string candidate)
    {
        candidate = candidate.Trim().Trim('"');
        if (candidate.Length == 0 || candidate.IndexOfAny(Path.GetInvalidPathChars()) >= 0) return null;
        try
        {
            string[] attempts = Path.IsPathRooted(candidate)
                ? [candidate, candidate + ".exe"]
                : [Path.Combine(System32, candidate), Path.Combine(System32, candidate + ".exe"), Path.Combine(WindowsDir, candidate)];
            foreach (var attempt in attempts)
            {
                if (File.Exists(attempt)) return Path.GetFullPath(attempt);
            }
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
        }
        return null;
    }

    private static IEnumerable<int> AllIndexesOf(string s, char c)
    {
        for (var i = s.IndexOf(c); i >= 0; i = s.IndexOf(c, i + 1)) yield return i;
    }

    private static IEnumerable<string> Tokenize(string args)
    {
        var current = new StringBuilder();
        var quoted = false;
        foreach (var ch in args)
        {
            if (ch == '"') { quoted = !quoted; continue; }
            if (ch == ' ' && !quoted)
            {
                if (current.Length > 0) { yield return current.ToString(); current.Clear(); }
                continue;
            }
            current.Append(ch);
        }
        if (current.Length > 0) yield return current.ToString();
    }

    private static readonly Lazy<List<(string Device, string Drive)>> DeviceMap = new(() =>
    {
        var map = new List<(string, string)>();
        var buffer = new StringBuilder(1024);
        foreach (var drive in Environment.GetLogicalDrives())
        {
            var letter = drive.TrimEnd('\\');
            if (QueryDosDeviceW(letter, buffer, buffer.Capacity) > 0)
                map.Add((buffer.ToString(), letter));
        }
        return map;
    });

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int QueryDosDeviceW(string deviceName, StringBuilder targetPath, int max);
}
