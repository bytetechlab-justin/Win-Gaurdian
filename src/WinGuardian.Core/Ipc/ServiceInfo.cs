using System.Runtime.InteropServices;

namespace WinGuardian.Core.Ipc;

/// <summary>Queries the Service Control Manager (works without admin rights).</summary>
public static class ServiceInfo
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const uint ServiceRunning = 4;

    public enum State { NotInstalled, Stopped, Running, Other }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
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

    /// <summary>The PID of the running service, or null if it is not installed or not running.</summary>
    public static uint? GetProcessId(string serviceName) =>
        Query(serviceName) is { CurrentState: ServiceRunning } s && s.ProcessId != 0 ? s.ProcessId : null;

    public static State GetState(string serviceName) => Query(serviceName) switch
    {
        null => State.NotInstalled,
        { CurrentState: ServiceRunning } => State.Running,
        { CurrentState: 1 } => State.Stopped,
        _ => State.Other,
    };

    private static ServiceStatusProcess? Query(string serviceName)
    {
        var scm = OpenSCManagerW(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero) return null;
        try
        {
            var service = OpenServiceW(scm, serviceName, ServiceQueryStatus);
            if (service == IntPtr.Zero) return null;
            try
            {
                var size = Marshal.SizeOf<ServiceStatusProcess>();
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (!QueryServiceStatusEx(service, ScStatusProcessInfo, buffer, size, out _)) return null;
                    return Marshal.PtrToStructure<ServiceStatusProcess>(buffer);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, IntPtr buffer, int size, out int needed);

    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
