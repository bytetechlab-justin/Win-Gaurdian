using System.Text;

namespace WinGuardian.Core.Monitoring;

public sealed record InspectionNote(Severity Severity, string Text);

/// <summary>What WinGaurdian can tell about a file without sending it anywhere.</summary>
public sealed class FileInspection
{
    public string Path { get; init; } = "";
    public long Size { get; init; }
    public string? Sha256 { get; init; }

    /// <summary>What the content really is, from its first bytes (e.g. "Windows program"), regardless of the extension.</summary>
    public string ContentType { get; init; } = "";
    public bool IsProgram { get; init; }
    public SignatureInfo? Signature { get; init; }

    /// <summary>Mark of the Web: the zone it was downloaded from (3 = Internet) and the address, if Windows recorded them.</summary>
    public int? Zone { get; init; }
    public string? DownloadedFrom { get; init; }
    public string? Referrer { get; init; }

    public List<InspectionNote> Notes { get; init; } = [];
    public Severity Severity => Notes.Count == 0 ? Severity.Info : Notes.Max(n => n.Severity);
}

/// <summary>
/// Local checks for "Scan with WG": hash, digital signature, real file type vs. extension (disguised programs,
/// double extensions, right-to-left name tricks), and where it was downloaded from.
/// </summary>
public static class FileInspector
{
    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".mp3", ".mp4", ".avi", ".mov", ".zip", ".rar", ".7z", ".csv", ".html", ".htm",
    };

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".url", ".scr", ".pif", ".msi", ".iso", ".img",
    };

    public static FileInspection Inspect(string path, CancellationToken ct = default)
    {
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("The file does not exist.", path);

        var header = ReadHeader(path);
        var contentType = DescribeContent(header);
        var isProgram = header.Length >= 2 && header[0] == 'M' && header[1] == 'Z';
        var extension = System.IO.Path.GetExtension(path);
        var notes = new List<InspectionNote>();

        ct.ThrowIfCancellationRequested();
        var sha256 = FileHasher.TryHash(path, long.MaxValue);
        ct.ThrowIfCancellationRequested();

        SignatureInfo? signature = null;
        if (isProgram || SeverityRules.IsExecutable(path))
        {
            signature = SignatureVerifier.Verify(path);
            switch (signature.Status)
            {
                case SignatureStatus.Tampered:
                    notes.Add(new(Severity.High, "Its digital signature is broken: the file was modified after it was signed."));
                    break;
                case SignatureStatus.Unsigned when isProgram:
                    notes.Add(new(Severity.Low, "The program is not digitally signed, so its publisher can't be verified."));
                    break;
                case SignatureStatus.Untrusted:
                    notes.Add(new(Severity.Medium, $"It is signed, but the signature is not trusted ({signature.Detail})."));
                    break;
            }
        }

        var name = System.IO.Path.GetFileName(path);
        if (name.Contains('‮'))
            notes.Add(new(Severity.High, "The name contains a hidden right-to-left character, a trick to disguise the real extension."));
        if (isProgram && DocumentExtensions.Contains(extension))
            notes.Add(new(Severity.High, $"This is a Windows program disguised as a {extension} file."));
        var inner = System.IO.Path.GetExtension(System.IO.Path.GetFileNameWithoutExtension(name));
        if (inner.Length > 1 && DocumentExtensions.Contains(inner) && (SeverityRules.IsExecutable(path) || ScriptExtensions.Contains(extension)))
            notes.Add(new(Severity.High, $"Double extension \"{inner}{extension}\": it looks like a document but runs as a program."));
        if (ScriptExtensions.Contains(extension) && !SeverityRules.IsExecutable(path))
            notes.Add(new(Severity.Low, $"{extension} files can run commands when opened."));

        var (zone, host, referrer) = ReadMarkOfTheWeb(path);
        if (zone is 3 or 4)
        {
            var from = host ?? referrer;
            notes.Add(new(Severity.Low, "Downloaded from the internet" + (from is null ? "." : $": {from}")));
        }

        return new FileInspection
        {
            Path = info.FullName,
            Size = info.Length,
            Sha256 = sha256,
            ContentType = contentType,
            IsProgram = isProgram,
            Signature = signature,
            Zone = zone,
            DownloadedFrom = host,
            Referrer = referrer,
            Notes = notes.OrderByDescending(n => n.Severity).ToList(),
        };
    }

    private static byte[] ReadHeader(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[8];
            var read = stream.Read(buffer, 0, buffer.Length);
            return buffer[..read];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    public static string DescribeContent(byte[] h)
    {
        bool Starts(params byte[] magic) => h.Length >= magic.Length && h.AsSpan(0, magic.Length).SequenceEqual(magic);
        if (Starts((byte)'M', (byte)'Z')) return "Windows program (executable / DLL)";
        if (Starts((byte)'%', (byte)'P', (byte)'D', (byte)'F')) return "PDF document";
        if (Starts(0x50, 0x4B, 0x03, 0x04)) return "ZIP archive (also Office documents, JAR, APPX)";
        if (Starts(0xD0, 0xCF, 0x11, 0xE0)) return "Compound file (old Office document or MSI installer)";
        if (Starts((byte)'R', (byte)'a', (byte)'r', (byte)'!')) return "RAR archive";
        if (Starts((byte)'7', (byte)'z', 0xBC, 0xAF)) return "7-Zip archive";
        if (Starts(0x4C, 0x00, 0x00, 0x00)) return "Windows shortcut";
        if (Starts(0x89, (byte)'P', (byte)'N', (byte)'G')) return "PNG image";
        if (Starts(0xFF, 0xD8, 0xFF)) return "JPEG image";
        if (Starts((byte)'#', (byte)'!')) return "Script";
        if (h.Length == 0) return "Empty or unreadable";
        return "Other / text";
    }

    /// <summary>Reads the Zone.Identifier stream Windows attaches to downloaded files.</summary>
    public static (int? Zone, string? HostUrl, string? ReferrerUrl) ReadMarkOfTheWeb(string path)
    {
        try
        {
            var text = File.ReadAllText(path + ":Zone.Identifier", Encoding.UTF8);
            return ParseZoneIdentifier(text);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            return (null, null, null);
        }
    }

    public static (int? Zone, string? HostUrl, string? ReferrerUrl) ParseZoneIdentifier(string text)
    {
        int? zone = null;
        string? host = null, referrer = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var (key, value) = (line[..eq].Trim(), line[(eq + 1)..].Trim());
            if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase) && int.TryParse(value, out var z)) zone = z;
            else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase) && value.Length > 0) host = value;
            else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase) && value.Length > 0) referrer = value;
        }
        return (zone, host, referrer);
    }
}
