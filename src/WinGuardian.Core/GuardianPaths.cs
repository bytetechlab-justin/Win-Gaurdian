namespace WinGuardian.Core;

public static class GuardianPaths
{
    public const string ServiceName = "WinGuardian";

    /// <summary>
    /// C:\ProgramData\WinGuardian - locked down to SYSTEM and Administrators by the service.
    /// Can be redirected with the WINGUARDIAN_DATA_DIR environment variable for development/testing.
    /// </summary>
    public static string DataDirectory { get; } =
        Environment.GetEnvironmentVariable("WINGUARDIAN_DATA_DIR") is { Length: > 0 } overridden
            ? Path.GetFullPath(overridden)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WinGuardian");

    public static string DatabasePath { get; } = Path.Combine(DataDirectory, "winguardian.db");

    /// <summary>Expands environment variables and normalizes a configured path (no trailing slash).</summary>
    public static string Normalize(string path)
    {
        var expanded = Environment.ExpandEnvironmentVariables(path.Trim());
        var full = Path.GetFullPath(expanded);
        return full.Length > 3 ? full.TrimEnd('\\') : full;
    }
}
