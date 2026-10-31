using System.Runtime.InteropServices;

namespace WinGuardian.Core.Network;

/// <summary>Which running services live in which process (several services often share one svchost.exe).</summary>
public static class ServiceProcessMap
{
    private const uint ScManagerEnumerateService = 0x0004;
    private const int ScEnumProcessInfo = 0;
    private const uint ServiceWin32 = 0x30;
    private const uint ServiceActive = 0x1;
    private const int ErrorMoreData = 234;

    [StructLayout(LayoutKind.Sequential)]
    private struct EnumServiceStatusProcess
    {
        public IntPtr ServiceName;
        public IntPtr DisplayName;
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    /// <summary>PID → service names (display names in parentheses).</summary>
    public static Dictionary<int, List<string>> Capture()
    {
        var map = new Dictionary<int, List<string>>();
        var scm = OpenSCManagerW(null, null, ScManagerEnumerateService);
        if (scm == IntPtr.Zero) return map;
        try
        {
            uint resume = 0;
            var size = 64 * 1024;
            for (var attempt = 0; attempt < 6; attempt++)
            {
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    var ok = EnumServicesStatusExW(scm, ScEnumProcessInfo, ServiceWin32, ServiceActive, buffer, size,
                        out var needed, out var returned, ref resume, null);
                    var error = Marshal.GetLastWin32Error();
                    var stride = Marshal.SizeOf<EnumServiceStatusProcess>();
                    for (var i = 0; i < returned; i++)
                    {
                        var entry = Marshal.PtrToStructure<EnumServiceStatusProcess>(buffer + i * stride);
                        if (entry.ProcessId == 0) continue;
                        var name = Marshal.PtrToStringUni(entry.ServiceName) ?? "";
                        var display = Marshal.PtrToStringUni(entry.DisplayName);
                        if (!map.TryGetValue((int)entry.ProcessId, out var list)) map[(int)entry.ProcessId] = list = [];
                        list.Add(display is null || display == name ? name : $"{name} ({display})");
                    }
                    if (ok) break;
                    if (error != ErrorMoreData) break;
                    size = Math.Max(size, (int)needed + 1024);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
        return map;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool EnumServicesStatusExW(IntPtr scm, int infoLevel, uint serviceType, uint serviceState, IntPtr services,
        int bufferSize, out uint bytesNeeded, out uint servicesReturned, ref uint resumeHandle, string? groupName);

    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
