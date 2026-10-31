using WinGuardian.Core.Data;

namespace WinGuardian.Core.Monitoring;

/// <summary>
/// The user's allowlist. Events matching a trusted item are not recorded (the baseline is still updated).
/// Path/Folder trust applies to file and process events; Service and Persistence trust apply by name/key;
/// Hash trust applies everywhere. Tamper events are never suppressed.
/// </summary>
public sealed class TrustStore(GuardianDatabase db)
{
    private readonly Lock _gate = new();
    private Snapshot? _snapshot;

    private sealed record Snapshot(
        HashSet<string> Paths, List<string> Folders, HashSet<string> Hashes,
        HashSet<string> Services, HashSet<string> Persistence, HashSet<string> Behaviors, HashSet<string> Publishers);

    public bool Suppresses(GuardianEvent e)
    {
        if (e.Category is EventCategory.Tamper or EventCategory.System) return false;
        var s = Current();

        if (e.Sha256 is not null && s.Hashes.Contains(e.Sha256)) return true;

        // Command-line detections are trusted per rule + parent program, never by trusting the
        // interpreter (e.g. powershell.exe) itself.
        if (e.Category == EventCategory.Process && e.Change == ChangeKind.Detected)
            return e.TrustKey is not null && s.Behaviors.Contains(e.TrustKey);

        // Signer is only set when the signature is valid, so a tampered or forged file never matches.
        if (e.Signer is not null && s.Publishers.Contains(e.Signer) &&
            e.Category is EventCategory.File or EventCategory.Process or EventCategory.Service or EventCategory.Persistence or EventCategory.ScheduledTask)
            return true;

        return e.Category switch
        {
            EventCategory.File or EventCategory.Process => e.FilePath is not null && IsTrustedPath(s, e.FilePath),
            EventCategory.Service => e.TrustKey is not null && s.Services.Contains(e.TrustKey),
            EventCategory.Persistence or EventCategory.ScheduledTask => e.TrustKey is not null && s.Persistence.Contains(e.TrustKey),
            _ => false,
        };
    }

    public bool IsTrustedFile(string? path, string? sha256)
    {
        var s = Current();
        return (sha256 is not null && s.Hashes.Contains(sha256)) || (path is not null && IsTrustedPath(s, path));
    }

    /// <summary>Call after the trusted table changes.</summary>
    public void Invalidate()
    {
        lock (_gate) _snapshot = null;
    }

    private static bool IsTrustedPath(Snapshot s, string path) =>
        s.Paths.Contains(path) ||
        s.Folders.Any(f => path.StartsWith(f + "\\", StringComparison.OrdinalIgnoreCase));

    private Snapshot Current()
    {
        lock (_gate)
        {
            if (_snapshot is not null) return _snapshot;
            var all = db.GetTrusted();
            HashSet<string> Set(TrustKind k) =>
                new(all.Where(t => t.Kind == k).Select(t => t.Value), StringComparer.OrdinalIgnoreCase);
            _snapshot = new Snapshot(
                Set(TrustKind.Path),
                all.Where(t => t.Kind == TrustKind.Folder).Select(t => t.Value.TrimEnd('\\')).ToList(),
                Set(TrustKind.Hash),
                Set(TrustKind.Service),
                Set(TrustKind.Persistence),
                Set(TrustKind.Behavior),
                Set(TrustKind.Publisher));
            return _snapshot;
        }
    }
}
