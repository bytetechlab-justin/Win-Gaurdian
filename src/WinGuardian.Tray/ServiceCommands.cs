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
            MessageBox.Show(owner, ex.Message, "WinGaurdian - service could not be verified", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
        catch (Exception ex)
        {
            MessageBox.Show(owner, "Could not reach the WinGaurdian service.\n\n" + ex.Message, "WinGaurdian",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    public static void ShowResult(IWin32Window? owner, PipeResponse response) =>
        MessageBox.Show(owner, response.Ok ? response.Message ?? "Done." : response.Error ?? "The request failed.",
            "WinGaurdian", MessageBoxButtons.OK, response.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);

    /// <summary>Asks for confirmation (with extra warnings for Windows files) and blocks the program.</summary>
    public static Task<bool> ConfirmAndBlockAsync(IWin32Window? owner, string path, string note, List<long>? eventIds = null) =>
        ConfirmAndBlockAsync(owner, [path], note, eventIds);

    /// <summary>Blocks one or more programs after a single confirmation (and at most one UAC prompt).</summary>
    public static async Task<bool> ConfirmAndBlockAsync(IWin32Window? owner, IReadOnlyList<string> paths, string note, List<long>? eventIds = null)
    {
        if (paths.Count == 0) return false;
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\";
        var inWindows = paths.Where(p => p.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase)).ToList();
        var list = string.Join("\n", paths.Take(15)) + (paths.Count > 15 ? $"\n... and {paths.Count - 15} more" : "");
        var message =
            (paths.Count == 1 ? "Block this program?" : $"Block these {paths.Count} programs?") + $"\n\n{list}\n\n" +
            "WinGaurdian will:\n" +
            "  - deny permission to run it (Windows will refuse to start it or load it as a DLL),\n" +
            "  - terminate it now and whenever it (or a renamed copy) starts,\n" +
            "  - stop and disable any Windows service that runs it.\n\n" +
            "You can undo this from the Blocked tab.";
        if (inWindows.Count > 0)
            message += $"\n\nWARNING: {(paths.Count == 1 ? "this file is" : $"{inWindows.Count} of these files are")} in the Windows folder. " +
                       "Blocking a legitimate Windows component can break features or Windows itself.";
        if (MessageBox.Show(owner, message, "WinGaurdian - Block Executable", MessageBoxButtons.YesNo,
                inWindows.Count > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return false;
        return await SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Block, Paths = [.. paths], Note = note, Ids = eventIds }, owner);
    }
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
