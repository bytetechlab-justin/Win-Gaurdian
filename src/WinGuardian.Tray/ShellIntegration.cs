using System.Diagnostics;
using Microsoft.Win32;

namespace WinGuardian.Tray;

/// <summary>
/// Windows 11's right-click menu shows a short list first and hides the full one (where "Scan with WG" and
/// "Run Through WG" live) behind "Show more options". Windows supports turning the short menu off per user:
/// an empty COM registration for the new menu's class makes Explorer fall back to the full menu.
/// </summary>
internal static class ShellIntegration
{
    private const string NewMenuClass = @"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}";

    public static bool FullMenuEnabled
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(NewMenuClass + @"\InprocServer32");
            return key is not null;
        }
    }

    public static void SetFullMenu(bool enabled)
    {
        if (enabled)
        {
            using var key = Registry.CurrentUser.CreateSubKey(NewMenuClass + @"\InprocServer32");
            key.SetValue("", ""); // an empty default value is what disables the new menu
        }
        else
        {
            Registry.CurrentUser.DeleteSubKeyTree(NewMenuClass, throwOnMissingSubKey: false);
        }
    }

    /// <summary>Explorer reads the setting at start-up. Restarts it in this session (open folder windows close).</summary>
    public static void RestartExplorer()
    {
        var session = Process.GetCurrentProcess().SessionId;
        foreach (var explorer in Process.GetProcessesByName("explorer").Where(p => p.SessionId == session))
        {
            try
            {
                explorer.Kill();
                explorer.WaitForExit(5000);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
            }
            finally
            {
                explorer.Dispose();
            }
        }
        // Windows usually restarts the shell by itself; start it if it hasn't.
        Thread.Sleep(1500);
        if (!Process.GetProcessesByName("explorer").Any(p => p.SessionId == session))
            Process.Start(new ProcessStartInfo("explorer.exe") { UseShellExecute = true })?.Dispose();
    }
}
