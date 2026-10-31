using System.Diagnostics;
using System.Runtime.InteropServices;

namespace WinGuardian.Core.Tasks;

/// <summary>
/// Controls Windows' "Other Object Access Events" success auditing, which makes Windows write Security
/// events 4698-4702 (task created/deleted/enabled/disabled/updated) including the requesting process ID.
/// It is off by default, so it is only enabled when the user opts in from Settings.
/// </summary>
public static class TaskAuditing
{
    public static readonly Guid OtherObjectAccessEvents = new("0CCE9227-69AE-11D9-BED3-505054503030");
    private const uint PolicyAuditEventSuccess = 0x1;

    /// <summary>True if success auditing is on; null if it cannot be determined.</summary>
    public static bool? IsEnabled()
    {
        var guids = new[] { OtherObjectAccessEvents };
        if (!AuditQuerySystemPolicy(guids, 1, out var buffer)) return null;
        try
        {
            var info = Marshal.PtrToStructure<AuditPolicyInformation>(buffer);
            return (info.AuditingInformation & PolicyAuditEventSuccess) != 0;
        }
        finally
        {
            AuditFree(buffer);
        }
    }

    /// <summary>Turns success auditing on or off (auditpol handles the required privilege).</summary>
    public static bool SetEnabled(bool enabled)
    {
        using var p = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "auditpol.exe"),
            Arguments = $"/set /subcategory:{OtherObjectAccessEvents:B} /success:{(enabled ? "enable" : "disable")}",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        p.WaitForExit(15_000);
        return p.HasExited && p.ExitCode == 0 && IsEnabled() == enabled;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] subCategoryGuids, uint count, out IntPtr policies);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);
}
