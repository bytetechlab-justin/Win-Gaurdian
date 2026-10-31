using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using WinGuardian.Core.Ipc;

namespace WinGuardian.Tray;

internal static class ServiceCommands
{
    public static bool IsElevated
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public static Task SendAsync(string command, IWin32Window? owner = null) =>
        SendAsync(new PipeRequest { Command = command }, owner);

    /// <summary>
    /// Sends a request and shows the outcome. If the service says it needs admin rights, relaunches this
    /// exe elevated (UAC prompt) with "--request" to send it again from the elevated copy.
    /// </summary>
    /// <returns>True if the request completed here; false if it failed or was handed to an elevated copy.</returns>
    public static async Task<bool> SendAsync(PipeRequest request, IWin32Window? owner, bool showSuccess = true)
    {
        try
        {
            var response = await PipeClient.SendAsync(request);
            if (response.AccessDenied)
            {
                RelaunchElevated("--request " + Encode(request));
                return false;
            }
            if (!response.Ok || showSuccess)
                ShowResult(owner, response);
            return response.Ok;
        }
        catch (ServerVerificationException ex)
        {
            MessageBox.Show(owner, ex.Message, "WinGuardian - service could not be verified", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
        catch (Exception ex)
        {
            MessageBox.Show(owner, "Could not reach the WinGuardian service.\n\n" + ex.Message, "WinGuardian",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    public static void ShowResult(IWin32Window? owner, PipeResponse response) =>
        MessageBox.Show(owner, response.Ok ? response.Message ?? "Done." : response.Error ?? "The request failed.",
            "WinGuardian", MessageBoxButtons.OK, response.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);

    public static void OpenSettings()
    {
        if (IsElevated)
        {
            using var form = new SettingsForm();
            form.ShowDialog();
        }
        else
        {
            RelaunchElevated("--settings");
        }
    }

    public static string Encode(PipeRequest request) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request, PipeProtocol.Json)));

    public static PipeRequest? Decode(string encoded) =>
        JsonSerializer.Deserialize<PipeRequest>(Encoding.UTF8.GetString(Convert.FromBase64String(encoded)), PipeProtocol.Json);

    private static void RelaunchElevated(string arguments)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = Environment.ProcessPath!,
                Arguments = arguments,
                Verb = "runas",
                UseShellExecute = true,
            });
        }
        catch (Win32Exception)
        {
            // User declined the UAC prompt.
        }
    }
}
