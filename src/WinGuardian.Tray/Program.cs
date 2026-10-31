using WinGuardian.Core.Ipc;

namespace WinGuardian.Tray;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Theme.Initialize();

        // Modes used when the tray relaunches itself elevated (UAC) for an admin-only action.
        if (args.Length == 2 && args[0] == "--request")
            return RunElevatedRequest(args[1]);
        if (args.Length == 2 && args[0] == "--event" && long.TryParse(args[1], out var eventId))
        {
            using var host = new Form { ShowInTaskbar = false, Opacity = 0 };
            host.Shown += async (_, _) =>
            {
                await EventDetailsForm.ShowAsync(host, eventId);
                host.Close();
            };
            Application.Run(host);
            return 0;
        }
        if (args.Length >= 1 && args[0] == "--dashboard")
        {
            // Opens just the dashboard (e.g. from a shortcut); "--dashboard firewall" selects that tab.
            Application.Run(new DashboardForm(args.Length > 1 ? args[1] : null));
            return 0;
        }
        if (args.Length == 2 && args[0] == "--analyze")
        {
            // Reopened as administrator to run and monitor a program that needs administrator rights.
            if (ProgramMonitorPanel.DecodeLaunch(args[1]) is not { } launch) return 1;
            Application.Run(new DashboardForm(DashboardForm.ProgramMonitorTab, launch, autoRun: true));
            return 0;
        }
        // Explorer right-click menu ("Scan with WG" / "Run Through WG"); Explorer passes the file as "%1".
        if (args.Length == 2 && args[0] == "--scan")
        {
            Application.Run(new ScanFileForm(Path.GetFullPath(args[1])));
            return 0;
        }
        if (args.Length == 2 && args[0] == "--run")
        {
            Application.Run(new DashboardForm(DashboardForm.ProgramMonitorTab, (Path.GetFullPath(args[1]), ""), autoRun: true));
            return 0;
        }
        if (args.Length == 1 && args[0] == "--settings")
        {
            using var form = new SettingsForm();
            form.ShowDialog();
            return 0;
        }

        using (var mutex = new Mutex(true, @"Local\WinGuardian.Tray", out var isFirstInstance))
        {
            if (!isFirstInstance) return 0;
            Application.Run(new TrayApplicationContext());
        }

        // Theme changed: start again (after releasing the single-instance mutex) so every window uses it.
        if (TrayApplicationContext.RestartRequested)
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false })?.Dispose();
        return 0;
    }

    private static int RunElevatedRequest(string encoded)
    {
        try
        {
            var request = ServiceCommands.Decode(encoded) ?? throw new ArgumentException("Invalid request.");
            var response = PipeClient.SendAsync(request).GetAwaiter().GetResult();
            ServiceCommands.ShowResult(null, response);
            return response.Ok ? 0 : 1;
        }
        catch (Exception ex)
        {
            MessageBox.Show("Could not complete the request.\n\n" + ex.Message, "WinGaurdian",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
