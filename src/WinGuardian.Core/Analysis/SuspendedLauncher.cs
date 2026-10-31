using System.ComponentModel;
using System.Runtime.InteropServices;

namespace WinGuardian.Core.Analysis;

/// <summary>
/// Starts a program with its first thread suspended, so monitoring can begin before it runs a single
/// instruction, then lets it go. Scripts and installers are started through their usual Windows host.
/// </summary>
public sealed class SuspendedLauncher : IDisposable
{
    public const int ErrorElevationRequired = 740;

    private IntPtr _process;
    private IntPtr _thread;

    public int ProcessId { get; }

    /// <summary>The program actually started (e.g. powershell.exe for a .ps1) and its full command line.</summary>
    public string Executable { get; }
    public string CommandLine { get; }

    private SuspendedLauncher(int pid, IntPtr process, IntPtr thread, string executable, string commandLine)
    {
        ProcessId = pid;
        _process = process;
        _thread = thread;
        Executable = executable;
        CommandLine = commandLine;
    }

    /// <exception cref="Win32Exception">Native error 740 (<see cref="ErrorElevationRequired"/>) if the program needs administrator rights.</exception>
    /// <exception cref="NotSupportedException">The file type cannot be started directly.</exception>
    public static SuspendedLauncher Start(string path, string? arguments, string? workingDirectory)
    {
        var (executable, commandLine) = BuildCommand(path, arguments ?? "");
        var startup = new StartupInfo { cb = Marshal.SizeOf<StartupInfo>() };
        var buffer = new char[commandLine.Length + 1];
        commandLine.CopyTo(0, buffer, 0, commandLine.Length);
        if (!CreateProcessW(executable, buffer, IntPtr.Zero, IntPtr.Zero, false, CreateSuspended | CreateNewConsole, IntPtr.Zero,
                string.IsNullOrWhiteSpace(workingDirectory) ? Path.GetDirectoryName(path) : workingDirectory, ref startup, out var info))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return new SuspendedLauncher(info.dwProcessId, info.hProcess, info.hThread, executable, commandLine);
    }

    /// <summary>File types that can be run and monitored (also where install.ps1 adds "Run Through WG").</summary>
    public static readonly string[] SupportedExtensions =
        [".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".msi", ".hta"];

    /// <summary>How Windows would start <paramref name="path"/>: the host program and its command line.</summary>
    public static (string Executable, string CommandLine) BuildCommand(string path, string arguments)
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var quoted = $"\"{path}\"";
        var args = arguments.Trim();
        string Join(params string[] parts) => string.Join(" ", parts.Where(p => p.Length > 0));

        return Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".exe" or ".com" or ".scr" => (path, Join(quoted, args)),
            ".bat" or ".cmd" => (Path.Combine(system, "cmd.exe"), Join("cmd.exe /c \"" + quoted, args) + "\""),
            ".ps1" => (Path.Combine(system, @"WindowsPowerShell\v1.0\powershell.exe"),
                Join("powershell.exe -NoProfile -ExecutionPolicy Bypass -File", quoted, args)),
            ".vbs" or ".vbe" or ".js" or ".jse" or ".wsf" => (Path.Combine(system, "wscript.exe"), Join("wscript.exe", quoted, args)),
            ".msi" => (Path.Combine(system, "msiexec.exe"), Join("msiexec.exe /i", quoted, args)),
            ".hta" => (Path.Combine(system, "mshta.exe"), Join("mshta.exe", quoted, args)),
            var ext => throw new NotSupportedException(
                $"WinGaurdian can't start {(ext.Length == 0 ? "files without an extension" : $"{ext} files")} directly. " +
                "Choose a program (.exe), script (.bat, .cmd, .ps1, .vbs, .js) or installer (.msi)."),
        };
    }

    public void Resume()
    {
        if (_thread != IntPtr.Zero && ResumeThread(_thread) == uint.MaxValue)
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public void Terminate()
    {
        if (_process != IntPtr.Zero) TerminateProcess(_process, 1);
    }

    public void Dispose()
    {
        if (_thread != IntPtr.Zero) CloseHandle(_thread);
        if (_process != IntPtr.Zero) CloseHandle(_process);
        _thread = _process = IntPtr.Zero;
    }

    private const uint CreateSuspended = 0x00000004;
    private const uint CreateNewConsole = 0x00000010;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public string? lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(string applicationName, char[] commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        bool inheritHandles, uint creationFlags, IntPtr environment, string? currentDirectory, ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
