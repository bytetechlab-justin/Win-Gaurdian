using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinGuardian.Core.Analysis;

/// <summary>Process queries used by program analysis. All work for protected/elevated processes when running as SYSTEM.</summary>
internal static class AnalysisNative
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint ProcessTerminate = 0x0001;
    private const int ProcessBasicInformation = 0;
    private const int ProcessCommandLineInformation = 60;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(SafeProcessHandle process, int infoClass, IntPtr info, int length, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    private const uint StillActive = 259;

    private static SafeProcessHandle? Open(int pid, uint access)
    {
        var handle = OpenProcess(access, false, pid);
        if (!handle.IsInvalid) return handle;
        handle.Dispose();
        return null;
    }

    /// <summary>The process that created <paramref name="pid"/>.</summary>
    public static int? GetParentPid(int pid)
    {
        using var handle = Open(pid, ProcessQueryLimitedInformation);
        if (handle is null) return null;
        var size = IntPtr.Size * 6; // PROCESS_BASIC_INFORMATION: six pointer-sized fields
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (NtQueryInformationProcess(handle, ProcessBasicInformation, buffer, size, out _) != 0) return null;
            return (int)Marshal.ReadIntPtr(buffer, IntPtr.Size * 5); // InheritedFromUniqueProcessId
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static string? GetCommandLine(int pid)
    {
        using var handle = Open(pid, ProcessQueryLimitedInformation);
        if (handle is null) return null;
        NtQueryInformationProcess(handle, ProcessCommandLineInformation, IntPtr.Zero, 0, out var needed);
        if (needed <= 0 || needed > 1 << 20) return null;
        var buffer = Marshal.AllocHGlobal(needed);
        try
        {
            var status = NtQueryInformationProcess(handle, ProcessCommandLineInformation, buffer, needed, out _);
            if (status == StatusInfoLengthMismatch || status != 0) return null;
            // UNICODE_STRING { ushort Length; ushort MaximumLength; PWSTR Buffer; } followed by the text.
            var length = (ushort)Marshal.ReadInt16(buffer);
            var text = Marshal.ReadIntPtr(buffer, IntPtr.Size);
            return length == 0 || text == IntPtr.Zero ? null : Marshal.PtrToStringUni(text, length / 2);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int infoClass, out int info, int length, out int returned);

    /// <summary>Whether the process runs with a full administrator token (TokenElevation).</summary>
    public static bool IsElevated(int pid)
    {
        using var handle = Open(pid, ProcessQueryLimitedInformation);
        if (handle is null || !OpenProcessToken(handle, 0x0008 /* TOKEN_QUERY */, out var token)) return false;
        using (token)
            return GetTokenInformation(token, 20 /* TokenElevation */, out var elevated, sizeof(int), out _) && elevated != 0;
    }

    public static DateTime? GetCreationTimeUtc(int pid)
    {
        using var handle = Open(pid, ProcessQueryLimitedInformation);
        return handle is not null && GetProcessTimes(handle, out var created, out _, out _, out _)
            ? DateTime.FromFileTimeUtc(created)
            : null;
    }

    /// <summary>
    /// True if <paramref name="pid"/> is still the same process (same creation time, so a reused PID never
    /// matches) and has not exited.
    /// </summary>
    public static bool IsRunning(int pid, DateTime createdUtc)
    {
        using var handle = Open(pid, ProcessQueryLimitedInformation);
        return handle is not null && SameProcess(handle, createdUtc) &&
               GetExitCodeProcess(handle, out var code) && code == StillActive;
    }

    /// <summary>Terminates <paramref name="pid"/> only if it is still the process that started at <paramref name="createdUtc"/>.</summary>
    public static bool Terminate(int pid, DateTime createdUtc)
    {
        using var handle = Open(pid, ProcessTerminate | ProcessQueryLimitedInformation);
        return handle is not null && SameProcess(handle, createdUtc) && TerminateProcess(handle, 1);
    }

    private static bool SameProcess(SafeProcessHandle handle, DateTime createdUtc) =>
        GetProcessTimes(handle, out var created, out _, out _, out _) &&
        Math.Abs((DateTime.FromFileTimeUtc(created) - createdUtc).TotalSeconds) < 1;
}
