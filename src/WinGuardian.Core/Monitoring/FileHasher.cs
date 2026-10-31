using System.Security.Cryptography;

namespace WinGuardian.Core.Monitoring;

public static class FileHasher
{
    /// <summary>SHA-256 of the file as uppercase hex, or null if it is too large or cannot be read (e.g. locked).</summary>
    public static string? TryHash(string path, long maxBytes)
    {
        try
        {
            using var stream = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.ReadWrite | FileShare.Delete,
                Options = FileOptions.SequentialScan,
                BufferSize = 1 << 16,
            });
            if (stream.Length > maxBytes) return null;
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
