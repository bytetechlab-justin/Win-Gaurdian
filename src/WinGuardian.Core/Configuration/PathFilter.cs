namespace WinGuardian.Core.Configuration;

/// <summary>Decides whether a path is excluded from scanning and monitoring.</summary>
public sealed class PathFilter
{
    private readonly string[] _excludedPrefixes;
    private readonly HashSet<string> _excludedExtensions;

    public PathFilter(GuardianOptions options)
    {
        _excludedPrefixes = options.ExcludedPaths.Select(GuardianPaths.Normalize).ToArray();
        _excludedExtensions = new HashSet<string>(
            options.ExcludedExtensions.Select(e => e.StartsWith('.') ? e : "." + e),
            StringComparer.OrdinalIgnoreCase);
    }

    public bool IsExcluded(string path)
    {
        if (_excludedExtensions.Contains(Path.GetExtension(path)))
            return true;

        foreach (var prefix in _excludedPrefixes)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                (path.Length == prefix.Length || path[prefix.Length] == '\\'))
                return true;
        }
        return false;
    }
}
