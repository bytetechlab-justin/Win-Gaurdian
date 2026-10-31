using WinGuardian.Core.Configuration;

namespace WinGuardian.Core.Monitoring;

public static class FileEnumerator
{
    private static readonly EnumerationOptions Options = new()
    {
        RecurseSubdirectories = false,
        IgnoreInaccessible = true,
        AttributesToSkip = 0, // the default skips Hidden|System, which is most of C:\Windows
        ReturnSpecialDirectories = false,
    };

    /// <summary>
    /// Walks directory trees depth-first without following junctions/symlinks (avoids loops and
    /// double-counting), skipping excluded paths and silently passing over unreadable directories.
    /// </summary>
    public static IEnumerable<FileInfo> Enumerate(IEnumerable<string> roots, PathFilter filter)
    {
        var pending = new Stack<DirectoryInfo>();
        foreach (var root in roots)
        {
            if (!filter.IsExcluded(root) && Directory.Exists(root))
                pending.Push(new DirectoryInfo(root));
        }

        while (pending.Count > 0)
        {
            var dir = pending.Pop();
            FileSystemInfo[] entries;
            try
            {
                entries = dir.GetFileSystemInfos("*", Options);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var entry in entries)
            {
                if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint) && entry is DirectoryInfo)
                    continue;
                if (filter.IsExcluded(entry.FullName))
                    continue;

                if (entry is DirectoryInfo sub)
                    pending.Push(sub);
                else if (entry is FileInfo file)
                    yield return file;
            }
        }
    }
}
