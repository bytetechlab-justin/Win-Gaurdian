using WinGuardian.Core;
using WinGuardian.Core.Ipc;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Tray;

/// <summary>
/// Pop-up shown, centered on the screen and on top of other windows, whenever WinGaurdian wants to do something to a
/// file (see <see cref="GuardianEvent.PendingAction"/>). Nothing has been changed yet: it shows everything known about
/// the file and lets the user quarantine it, block it, add it to Trusted Items, or decide later.
/// Closes itself once the event is acknowledged (by an action here, an elevated copy after a UAC prompt, or the dashboard).
/// </summary>
internal sealed class ThreatPromptForm : Form
{
    private readonly GuardianEvent _event;
    private readonly string _path;
    private readonly ListView _details = ListViews.MakeSortable(("", 150), ("", 640));
    private readonly TextBox _reputation = new()
    {
        Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 9f),
    };
    private readonly Button _quarantine = new() { Text = "Quarantine", AutoSize = true };
    private readonly Button _block = new() { Text = "Block Executable...", AutoSize = true };
    private readonly Button _trust = new() { Text = "Add to Trusted Items ▾", AutoSize = true };
    private readonly Button _location = new() { Text = "Open File Location", AutoSize = true };
    private readonly Button _eventDetails = new() { Text = "Event Details...", AutoSize = true };
    private readonly Button _later = new() { Text = "Decide Later", AutoSize = true, DialogResult = DialogResult.Cancel };
    private readonly System.Windows.Forms.Timer _watch = new() { Interval = 2000 };
    private bool _checking;

    public ThreatPromptForm(GuardianEvent e)
    {
        _event = e;
        _path = e.FilePath ?? "";
        Text = $"WinGaurdian - Action needed: {Path.GetFileName(_path)}";
        Width = 860;
        Height = 620;
        MinimumSize = new Size(640, 480);
        StartPosition = FormStartPosition.CenterScreen;
        TopMost = true;
        ShowInTaskbar = true;
        Icon = Branding.AppIcon;
        Font = new Font("Segoe UI", 9f);

        var banner = new Label
        {
            Dock = DockStyle.Top, Height = 54, Padding = new Padding(12, 8, 12, 4), Font = new Font("Segoe UI", 13f, FontStyle.Bold),
            BackColor = e.Severity >= Severity.High ? Theme.P.BannerDanger : Theme.P.BannerSuspicious,
            Text = e.Severity >= Severity.High ? "WinGaurdian found known malware" : "WinGaurdian found a suspicious file",
        };
        var subtitle = new Label
        {
            Dock = DockStyle.Top, Height = 44, Padding = new Padding(14, 4, 12, 4),
            Text = $"WinGaurdian recommends: {Describe(e.PendingAction)}. Nothing has been changed yet: choose what to do, " +
                   "or Decide Later to leave the file as it is (the alert stays in the dashboard).",
        };

        _details.HeaderStyle = ColumnHeaderStyle.None;
        _details.Dock = DockStyle.Top;
        _details.Height = 230;
        _details.ContextMenuStrip = new ContextMenuStrip();
        _details.ContextMenuStrip.Items.Add("Copy", null, (_, _) => ListViews.CopySelected(_details));
        Theme.StyleMenu(_details.ContextMenuStrip);

        _reputation.Text = (e.Details ?? "").Replace("\n", Environment.NewLine);
        _reputation.BackColor = Theme.P.Surface;
        var reputationBox = new Panel { Dock = DockStyle.Fill, Padding = new Padding(4) };
        reputationBox.Controls.Add(_reputation);
        reputationBox.Controls.Add(new Label { Text = "Why WinGaurdian flagged it", Dock = DockStyle.Top, Height = 20 });

        var trustMenu = new ContextMenuStrip();
        trustMenu.Items.Add("Trust This File (this path)", null, async (_, _) => await TrustAsync(TrustKind.Path, _path));
        if (e.Sha256 is not null)
            trustMenu.Items.Add("Trust This File Content (hash, wherever it is)", null, async (_, _) => await TrustAsync(TrustKind.Hash, e.Sha256));
        Theme.StyleMenu(trustMenu);

        Theme.Primary(_quarantine);
        _quarantine.Click += async (_, _) => await QuarantineAsync();
        _block.Click += async (_, _) => await RunAsync(() => ServiceCommands.ConfirmAndBlockAsync(this, _path, $"From alert #{e.Id}", [e.Id]));
        _trust.Click += (_, _) => trustMenu.Show(_trust, new Point(0, _trust.Height));
        _location.Click += (_, _) => OpenLocation();
        _eventDetails.Click += async (_, _) => await EventDetailsForm.ShowAsync(this, e.Id);
        _later.Click += (_, _) => Close();
        _block.Visible = SeverityRules.IsExecutable(_path);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 42, Padding = new Padding(6) };
        buttons.Controls.AddRange([_quarantine, _block, _trust, _location, _eventDetails, _later]);

        Controls.Add(reputationBox);
        Controls.Add(_details);
        Controls.Add(subtitle);
        Controls.Add(banner);
        Controls.Add(buttons);
        CancelButton = _later;
        AcceptButton = null; // a stray Enter key must not quarantine anything

        Theme.Apply(this);
        AddBasicRows();
        Shown += async (_, _) =>
        {
            BringToFront();
            Activate();
            _later.Focus();
            _watch.Tick += async (_, _) => await CloseIfHandledAsync();
            _watch.Start();
            await InspectAsync();
        };
        FormClosed += (_, _) => _watch.Dispose();
    }

    private static string Describe(string? action) => action switch
    {
        PendingActions.Quarantine => "move this file to quarantine (you can restore it later)",
        null => "review this file",
        var other => other.ToLowerInvariant(),
    };

    private void Row(string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) _details.Items.Add(new ListViewItem([name, value]));
    }

    private void AddBasicRows()
    {
        _details.Items.Clear();
        Row("Detected", _event.TimeUtc.ToLocalTime().ToString("F"));
        Row("Alert", _event.Subject);
        Row("File name", Path.GetFileName(_path));
        Row("Folder", Path.GetDirectoryName(_path));
        Row("SHA-256", _event.Sha256);
        Row("Signature", _event.Signature);
    }

    /// <summary>Reads the file as the signed-in user for size, dates, signature, real type and download origin.</summary>
    private async Task InspectAsync()
    {
        if (!File.Exists(_path))
        {
            Row("Status", "The file no longer exists at this location.");
            _quarantine.Enabled = _block.Enabled = _location.Enabled = false;
            return;
        }

        FileInspection? f = null;
        string? error = null;
        DateTime created = default, modified = default;
        FileAttributes attributes = default;
        try
        {
            (f, created, modified, attributes) = await Task.Run(() =>
            {
                var info = new FileInfo(_path);
                return (FileInspector.Inspect(_path), info.CreationTime, info.LastWriteTime, info.Attributes);
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error = ex.Message;
        }
        if (IsDisposed) return;

        if (f is null)
        {
            Row("File", $"Could not be read from this account ({error}). WinGaurdian's service can still quarantine or block it.");
            return;
        }

        _details.BeginUpdate();
        AddBasicRows();
        Row("Size", $"{f.Size:N0} bytes");
        Row("Created", created.ToString("F"));
        Row("Modified", modified.ToString("F"));
        Row("Attributes", attributes.ToString());
        Row("Content", f.ContentType);
        if (_event.Signature is null) Row("Signature", f.Signature?.Describe());
        Row("Downloaded from", f.DownloadedFrom ?? f.Referrer);
        if (f.Sha256 is not null && _event.Sha256 is not null && !string.Equals(f.Sha256, _event.Sha256, StringComparison.OrdinalIgnoreCase))
            Row("Note", $"The file has changed since it was flagged (now SHA-256 {f.Sha256}).");
        foreach (var note in f.Notes.OrderByDescending(n => n.Severity))
            Row($"Finding ({note.Severity})", note.Text);
        _details.EndUpdate();
    }

    private async Task QuarantineAsync()
    {
        var inWindows = _path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\", StringComparison.OrdinalIgnoreCase);
        if (inWindows && MessageBox.Show(this,
                $"This file is in the Windows folder:\n\n{_path}\n\nRemoving a legitimate system file can break Windows. Quarantine it anyway?",
                "WinGaurdian - Quarantine", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return;
        await RunAsync(() => ServiceCommands.SendAsync(new PipeRequest
        {
            Command = PipeProtocol.Commands.Quarantine,
            Path = _path,
            Note = $"Chosen in the pop-up for alert #{_event.Id}",
            Ids = [_event.Id],
        }, this));
    }

    private async Task TrustAsync(TrustKind kind, string value)
    {
        var what = kind == TrustKind.Hash ? $"this exact file content wherever it appears:\nSHA256 {value}" : $"this file:\n{value}";
        if (MessageBox.Show(this,
                $"Add {what}\n\nto Trusted Items? WinGaurdian will leave it alone and stop alerting on it. " +
                "Only do this if you are sure the detection is wrong.",
                "WinGaurdian - Trust", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.OK)
            return;
        await RunAsync(() => ServiceCommands.SendAsync(new PipeRequest
        {
            Command = PipeProtocol.Commands.Trust,
            TrustKind = kind,
            Value = value,
            Note = $"From the pop-up for alert #{_event.Id}: {_event.Subject}",
            Ids = [_event.Id],
        }, this));
    }

    /// <summary>
    /// Runs an action and closes when it completed here. If it needed a UAC prompt, an elevated copy finishes it
    /// and <see cref="CloseIfHandledAsync"/> notices the acknowledged event.
    /// </summary>
    private async Task RunAsync(Func<Task<bool>> action)
    {
        SetButtonsEnabled(false);
        try
        {
            if (await action()) Close();
        }
        finally
        {
            if (!IsDisposed) SetButtonsEnabled(true);
        }
    }

    private void SetButtonsEnabled(bool enabled)
    {
        var exists = File.Exists(_path);
        _quarantine.Enabled = _block.Enabled = enabled && exists;
        _trust.Enabled = enabled;
    }

    private async Task CloseIfHandledAsync()
    {
        if (_checking || IsDisposed) return;
        _checking = true;
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Event, Id = _event.Id.ToString() }, 1500);
            if (!IsDisposed && response.Events is [{ Acknowledged: true }]) Close();
        }
        catch (Exception)
        {
            // Service briefly unreachable: keep the window; the user can still choose.
        }
        finally
        {
            _checking = false;
        }
    }

    private void OpenLocation()
    {
        try
        {
            var start = new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"))
            {
                UseShellExecute = false,
                Arguments = $"/select,\"{_path}\"", // Explorer's own syntax: the quotes go around the path only
            };
            System.Diagnostics.Process.Start(start)?.Dispose();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException)
        {
            MessageBox.Show(this, ex.Message, "WinGaurdian", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
