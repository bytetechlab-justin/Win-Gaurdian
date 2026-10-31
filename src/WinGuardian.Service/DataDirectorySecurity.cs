using System.Security.AccessControl;
using System.Security.Principal;

namespace WinGuardian.Service;

internal static class DataDirectorySecurity
{
    /// <summary>
    /// Restricts the data directory (baseline database) to SYSTEM and Administrators so a
    /// non-elevated process cannot tamper with the baseline or erase alerts.
    /// </summary>
    public static void EnsureLockedDown(string path)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(sid, null),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        var dir = new DirectoryInfo(path);
        if (dir.Exists)
            dir.SetAccessControl(security);
        else
            dir.Create(security);
    }
}
