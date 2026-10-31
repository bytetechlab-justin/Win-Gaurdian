using WinGuardian.Core;
using WinGuardian.Core.Ipc;

namespace WinGuardian.Tray;

/// <summary>Runtime settings (API keys etc.). Only usable elevated: the service requires admin to read or change them.</summary>
internal sealed class SettingsForm : Form
{
    private readonly TextBox _malwareBazaarKey = new() { Width = 420, UseSystemPasswordChar = true };
    private readonly TextBox _virusTotalKey = new() { Width = 420, UseSystemPasswordChar = true };
    private readonly NumericUpDown _virusTotalLimit = new() { Minimum = 0, Maximum = 1_000_000, Width = 100 };
    private readonly NumericUpDown _retentionDays = new() { Minimum = 1, Maximum = 3650, Width = 100 };
    private readonly CheckBox _autoQuarantine = new() { Text = "Automatically quarantine files confirmed as known malware", AutoSize = true };
    private readonly CheckBox _showKeys = new() { Text = "Show keys", AutoSize = true };

    public SettingsForm()
    {
        Text = "WinGuardian Settings";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Font = new Font("Segoe UI", 9f);
        Padding = new Padding(12);

        var layout = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Fill };
        void Row(string label, Control control)
        {
            layout.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 8, 0) });
            layout.Controls.Add(control);
        }

        Row("MalwareBazaar API key:", _malwareBazaarKey);
        Row("", new LinkLabel { Text = "Get a free key at auth.abuse.ch", AutoSize = true, Tag = "https://auth.abuse.ch/" });
        Row("VirusTotal API key:", _virusTotalKey);
        Row("", new LinkLabel { Text = "Get a free key at virustotal.com (account → API key)", AutoSize = true, Tag = "https://www.virustotal.com/gui/my-apikey" });
        Row("VirusTotal lookups per day:", _virusTotalLimit);
        Row("Keep acknowledged events (days):", _retentionDays);
        Row("", _autoQuarantine);
        Row("", _showKeys);

        foreach (var link in layout.Controls.OfType<LinkLabel>())
            link.LinkClicked += (s, _) => OpenUrl((string)((LinkLabel)s!).Tag!);
        _showKeys.CheckedChanged += (_, _) =>
            _malwareBazaarKey.UseSystemPasswordChar = _virusTotalKey.UseSystemPasswordChar = !_showKeys.Checked;

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill };
        var save = new Button { Text = "Save", AutoSize = true };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        save.Click += async (_, _) => await SaveAsync();
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(save);
        layout.Controls.Add(new Label());
        layout.Controls.Add(buttons);

        Controls.Add(layout);
        AcceptButton = save;
        CancelButton = cancel;
        Shown += async (_, _) => await LoadAsync();
    }

    private async Task LoadAsync()
    {
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.GetSettings });
            if (response.Settings is not { } s)
            {
                MessageBox.Show(this, response.Error ?? "Could not load settings.", "WinGuardian", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                Close();
                return;
            }
            _malwareBazaarKey.Text = s.MalwareBazaarApiKey ?? "";
            _virusTotalKey.Text = s.VirusTotalApiKey ?? "";
            _virusTotalLimit.Value = Math.Clamp(s.VirusTotalDailyLimit, 0, 1_000_000);
            _retentionDays.Value = Math.Clamp(s.EventRetentionDays, 1, 3650);
            _autoQuarantine.Checked = s.AutoQuarantineMalicious;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Could not reach the WinGuardian service.\n\n" + ex.Message, "WinGuardian", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Close();
        }
    }

    private async Task SaveAsync()
    {
        var settings = new RuntimeSettings
        {
            MalwareBazaarApiKey = _malwareBazaarKey.Text,
            VirusTotalApiKey = _virusTotalKey.Text,
            VirusTotalDailyLimit = (int)_virusTotalLimit.Value,
            EventRetentionDays = (int)_retentionDays.Value,
            AutoQuarantineMalicious = _autoQuarantine.Checked,
        };
        if (await ServiceCommands.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.SetSettings, Settings = settings }, this, showSuccess: false))
        {
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    internal static void OpenUrl(string url) =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
}
