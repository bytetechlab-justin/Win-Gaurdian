using WinGuardian.Core;
using WinGuardian.Core.Ipc;

namespace WinGuardian.Tray;

/// <summary>Notification-area icon: polls the service, reflects its state in the icon, and pops balloon alerts.</summary>
internal sealed class TrayApplicationContext : ApplicationContext
{
    private const Severity NotifyThreshold = Severity.Medium;

    private readonly Icon _iconOk = IconFactory.CreateShield(Color.FromArgb(46, 160, 67));
    private readonly Icon _iconBusy = IconFactory.CreateShield(Color.FromArgb(31, 111, 235), "…");
    private readonly Icon _iconWarn = IconFactory.CreateShield(Color.FromArgb(210, 153, 34), "!");
    private readonly Icon _iconAlert = IconFactory.CreateShield(Color.FromArgb(207, 34, 46), "!");
    private readonly Icon _iconOffline = IconFactory.CreateShield(Color.Gray, "?");

    private readonly NotifyIcon _notifyIcon;
    private readonly System.Windows.Forms.Timer _pollTimer;
    private DashboardForm? _dashboard;
    private long? _lastSeenEventId;
    private bool _polling;
    private bool _wasConnected = true;

    public TrayApplicationContext()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Dashboard", null, (_, _) => ShowDashboard());
        menu.Items.Add("Run Full Scan Now", null, async (_, _) => await ServiceCommands.SendAsync(PipeProtocol.Commands.Scan));
        menu.Items.Add("Acknowledge All Alerts", null, async (_, _) => await ServiceCommands.SendAsync(PipeProtocol.Commands.Acknowledge));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Settings...", null, (_, _) => ServiceCommands.OpenSettings());
        menu.Items.Add("Rebuild Baseline...", null, async (_, _) => await ConfirmRebuildAsync(null));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit Tray Icon", null, (_, _) => ExitThread());

        _notifyIcon = new NotifyIcon
        {
            Icon = _iconOffline,
            Text = "WinGuardian - connecting...",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _notifyIcon.DoubleClick += (_, _) => ShowDashboard();
        _notifyIcon.BalloonTipClicked += (_, _) => ShowDashboard();

        _pollTimer = new System.Windows.Forms.Timer { Interval = 3000 };
        _pollTimer.Tick += async (_, _) => await PollAsync();
        _pollTimer.Start();
        _ = PollAsync();
    }

    internal static async Task ConfirmRebuildAsync(IWin32Window? owner)
    {
        var answer = MessageBox.Show(owner,
            "Rebuilding the baseline accepts the current state of the system as trusted and rescans every file.\n\n" +
            "Only do this if you are confident the system is clean. Continue?",
            "WinGuardian - Rebuild Baseline", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (answer == DialogResult.Yes)
            await ServiceCommands.SendAsync(PipeProtocol.Commands.Rebuild, owner);
    }

    private async Task PollAsync()
    {
        if (_polling) return;
        _polling = true;
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Status }, timeoutMs: 1500);
            if (response.Status is not { } status) throw new IOException(response.Error ?? "No status returned.");

            _wasConnected = true;
            UpdateIcon(status);
            await NotifyNewEventsAsync(status);
            _dashboard?.ApplyStatus(status);
        }
        catch (ServerVerificationException ex)
        {
            // Something other than the real service is answering on our pipe: treat as an attack.
            _notifyIcon.Icon = _iconAlert;
            SetTooltip("WinGuardian - WARNING: service identity could not be verified");
            if (_wasConnected)
            {
                _wasConnected = false;
                _dashboard?.ApplyDisconnected(ex.Message);
                _notifyIcon.ShowBalloonTip(15000, "WinGuardian: possible tampering", ex.Message, ToolTipIcon.Error);
            }
        }
        catch (Exception)
        {
            _notifyIcon.Icon = _iconOffline;
            var state = ServiceInfo.GetState(GuardianPaths.ServiceName);
            var text = state switch
            {
                ServiceInfo.State.NotInstalled => "WinGuardian - service is not installed",
                ServiceInfo.State.Stopped => "WinGuardian - PROTECTION IS OFF (service stopped)",
                _ => "WinGuardian - service is not responding",
            };
            SetTooltip(text);
            if (_wasConnected)
            {
                _wasConnected = false;
                _dashboard?.ApplyDisconnected(text);
                _notifyIcon.ShowBalloonTip(15000, "WinGuardian protection is OFF",
                    text + ". Changes to your system are not being monitored.", ToolTipIcon.Error);
            }
        }
        finally
        {
            _polling = false;
        }
    }

    private void UpdateIcon(GuardianStatus status)
    {
        if (status.UnacknowledgedCount > 0 && status.HighestUnacknowledgedSeverity >= Severity.High)
            _notifyIcon.Icon = _iconAlert;
        else if (status.UnacknowledgedCount > 0 && status.HighestUnacknowledgedSeverity >= NotifyThreshold)
            _notifyIcon.Icon = _iconWarn;
        else if (status.ScanInProgress)
            _notifyIcon.Icon = _iconBusy;
        else
            _notifyIcon.Icon = _iconOk;

        var text = status.ScanInProgress
            ? $"WinGuardian - {status.Phase} ({status.ScanFilesProcessed:N0} files)"
            : $"WinGuardian - {status.Phase}";
        if (status.UnacknowledgedCount > 0)
            text += $"\n{status.UnacknowledgedCount:N0} unacknowledged alert(s)";
        SetTooltip(text);
    }

    private async Task NotifyNewEventsAsync(GuardianStatus status)
    {
        if (_lastSeenEventId is null)
        {
            // First contact: summarize what is already waiting instead of replaying history.
            _lastSeenEventId = status.LatestEventId;
            if (status.UnacknowledgedCount > 0 && status.HighestUnacknowledgedSeverity >= NotifyThreshold)
                _notifyIcon.ShowBalloonTip(5000, "WinGuardian",
                    $"{status.UnacknowledgedCount:N0} alert(s) waiting for review.", ToolTipIcon.Warning);
            return;
        }
        if (status.LatestEventId <= _lastSeenEventId) return;

        var response = await PipeClient.SendAsync(new PipeRequest
        {
            Command = PipeProtocol.Commands.Events,
            SinceId = _lastSeenEventId,
            Limit = 500,
        });
        var fresh = response.Events ?? [];
        _lastSeenEventId = status.LatestEventId;
        _dashboard?.RefreshEventsSoon();

        var important = fresh.Where(e => e.Severity >= NotifyThreshold).ToList();
        if (important.Count == 0) return;

        var top = important.OrderByDescending(e => e.Severity).First();
        var title = important.Count == 1 ? $"WinGuardian: {top.Category} {top.Change}" : $"WinGuardian: {important.Count} new alerts";
        var body = important.Count == 1 ? top.Subject : $"Most severe: {top.Category} {top.Change} - {top.Subject}";
        _notifyIcon.ShowBalloonTip(8000, title, Truncate(body, 250),
            top.Severity >= Severity.High ? ToolTipIcon.Error : ToolTipIcon.Warning);
    }

    private void ShowDashboard()
    {
        if (_dashboard is null || _dashboard.IsDisposed)
        {
            _dashboard = new DashboardForm();
            _dashboard.FormClosed += (_, _) => _dashboard = null;
        }
        _dashboard.Show();
        _dashboard.WindowState = FormWindowState.Normal;
        _dashboard.Activate();
    }

    // NotifyIcon.Text is limited to 127 characters.
    private void SetTooltip(string text) => _notifyIcon.Text = Truncate(text, 127);

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

    protected override void ExitThreadCore()
    {
        _pollTimer.Stop();
        _notifyIcon.Visible = false;
        _dashboard?.Close();
        base.ExitThreadCore();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _pollTimer.Dispose();
            _notifyIcon.Dispose();
            foreach (var icon in new[] { _iconOk, _iconBusy, _iconWarn, _iconAlert, _iconOffline })
                icon.Dispose();
        }
        base.Dispose(disposing);
    }
}
