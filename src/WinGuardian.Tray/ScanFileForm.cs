using System.Text;
using WinGuardian.Core;
using WinGuardian.Core.Ipc;
using WinGuardian.Core.Monitoring;
using WinGuardian.Core.Reputation;

namespace WinGuardian.Tray;

/// <summary>
/// "Scan with WG" (Explorer right-click): checks one file locally (hash, signature, disguised type, where it was
/// downloaded from) and online through the service (MalwareBazaar / VirusTotal), and offers the usual actions.
/// The file is read here, as the signed-in user; only its hash and path are sent to the service.
/// </summary>
internal sealed class ScanFileForm : Form
{
    private readonly string _path;
    private readonly Label _verdict = new()
    {
        Dock = DockStyle.Top, Height = 54, Padding = new Padding(12, 8, 12, 4), Font = new Font("Segoe UI", 13f, FontStyle.Bold),
        BackColor = Theme.P.BannerNeutral, Text = "Scanning...",
    };
    private readonly Label _subtitle = new() { Dock = DockStyle.Top, Height = 26, Padding = new Padding(14, 2, 12, 4) };
    private readonly ListView _details = ListViews.MakeSortable(("", 150), ("", 620));
    private readonly ListView _findings = ListViews.MakeSortable(("Severity", 75), ("Finding", 690));
    private readonly Button _run = new() { Text = "Run Through WG...", AutoSize = true, Enabled = false };
    private readonly Button _block = new() { Text = "Block...", AutoSize = true, Enabled = false };
    private readonly Button _quarantine = new() { Text = "Quarantine...", AutoSize = true, Enabled = false };
    private readonly Button _virusTotal = new() { Text = "Open in VirusTotal", AutoSize = true, Enabled = false };
    private readonly Button _askGemini = new() { Text = "Ask Gemini...", AutoSize = true, Enabled = false };
    private readonly Button _copy = new() { Text = "Copy Report", AutoSize = true, Enabled = false };
    private FileInspection? _inspection;
    private FileScanResult? _scan;
    private string? _onlineError;

    public ScanFileForm(string path)
    {
        _path = path;
        Text = $"WinGaurdian - Scan: {Path.GetFileName(path)}";
        Width = 860;
        Height = 600;
        StartPosition = FormStartPosition.CenterScreen;
        Icon = Branding.AppIcon;
        Font = new Font("Segoe UI", 9f);

        _details.HeaderStyle = ColumnHeaderStyle.None;
        _details.Dock = DockStyle.Top;
        _details.Height = 150;
        _details.ContextMenuStrip = CopyMenu(_details);
        _findings.ContextMenuStrip = CopyMenu(_findings);

        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        close.Click += (_, _) => Close();
        _run.Click += (_, _) => RunThroughWg();
        _block.Click += async (_, _) => await ServiceCommands.ConfirmAndBlockAsync(this, _path, "From Scan with WG");
        _quarantine.Click += async (_, _) => await QuarantineAsync();
        _virusTotal.Click += (_, _) => { if (_inspection?.Sha256 is { } h) SettingsForm.OpenUrl($"https://www.virustotal.com/gui/file/{h}"); };
        _askGemini.Click += (_, _) => AskGeminiForm.Show(this, Path.GetFileName(_path), "whether this file on their PC is safe (a WinGaurdian file scan)", BuildReport());
        _copy.Click += (_, _) => Clipboard.SetText(BuildReport());

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 40, Padding = new Padding(6) };
        buttons.Controls.AddRange([_run, _block, _quarantine, _virusTotal, _askGemini, _copy, close]);

        var findingsLabel = new Label { Text = "Findings", Dock = DockStyle.Top, Height = 20, Padding = new Padding(4, 4, 0, 0) };
        Controls.Add(_findings);
        Controls.Add(findingsLabel);
        Controls.Add(_details);
        Controls.Add(_subtitle);
        Controls.Add(_verdict);
        Controls.Add(buttons);
        CancelButton = close;

        Theme.Apply(this);
        Shown += async (_, _) => await ScanAsync();
    }

    private async Task ScanAsync()
    {
        _subtitle.Text = "Reading the file...";
        try
        {
            _inspection = await Task.Run(() => FileInspector.Inspect(_path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            SetVerdict("Could not read the file", ex.Message, Theme.P.BannerNeutral);
            return;
        }
        Render();

        if (_inspection.Sha256 is null)
        {
            _onlineError = "The file could not be hashed.";
        }
        else
        {
            _subtitle.Text = "Checking online reputation through the WinGaurdian service...";
            try
            {
                var response = await PipeClient.SendAsync(new PipeRequest
                {
                    Command = PipeProtocol.Commands.ScanFile, Sha256 = _inspection.Sha256, Path = _inspection.Path,
                }, 5000);
                if (response.FileScan is { } scan) _scan = scan;
                else _onlineError = response.Error ?? "No answer from the service.";
            }
            catch (Exception ex)
            {
                _onlineError = "Could not reach the WinGaurdian service: " + ex.Message;
            }
        }
        Render();
    }

    private void Render()
    {
        if (_inspection is not { } f) return;
        var exists = File.Exists(_path);
        _run.Enabled = exists && IsRunnable(_path);
        _block.Enabled = exists && (f.IsProgram || SeverityRules.IsExecutable(_path));
        _quarantine.Enabled = exists;
        _virusTotal.Enabled = _askGemini.Enabled = _copy.Enabled = f.Sha256 is not null;

        _details.Items.Clear();
        void Row(string name, string? value) { if (value is not null) _details.Items.Add(new ListViewItem([name, value])); }
        Row("File", f.Path);
        Row("Size", $"{f.Size:N0} bytes");
        Row("Content", f.ContentType);
        Row("SHA-256", f.Sha256 ?? "(could not read)");
        Row("Signature", f.Signature?.Describe() ?? (f.IsProgram ? null : "(not a program)"));
        Row("Downloaded from", f.DownloadedFrom ?? f.Referrer);

        var findings = Findings();
        _findings.Items.Clear();
        foreach (var (severity, text) in findings)
        {
            _findings.Items.Add(new ListViewItem([severity.ToString(), text])
            {
                BackColor = severity switch
                {
                    Severity.High or Severity.Medium => Theme.SeverityRow(severity),
                    _ => Theme.P.Surface,
                },
            });
        }

        var malicious = _scan?.Reputation.FirstOrDefault(r => r.Verdict == ReputationVerdict.Malicious);
        var worst = findings.Count == 0 ? Severity.Info : findings.Max(x => x.Severity);
        if (malicious is not null)
            SetVerdict($"Known malware{(malicious.Label is null ? "" : $": {malicious.Label}")}",
                $"{malicious.Provider} identifies this file as malicious. Don't open it; quarantine or delete it.", Theme.P.BannerDanger);
        else if (worst == Severity.High || _scan?.Reputation.Any(r => r.Verdict == ReputationVerdict.Suspicious) == true)
            SetVerdict("Suspicious", "See the findings below before opening this file.", Theme.P.BannerSuspicious);
        else if (_scan is null && _onlineError is null)
            SetVerdict("Scanning...", _subtitle.Text, Theme.P.BannerNeutral);
        else if (_scan is { ReputationConfigured: true } && _scan.Reputation.Any(r => r.Verdict != ReputationVerdict.Error))
            SetVerdict(worst == Severity.Medium ? "No known threats, but see the findings" : "No known threats found",
                _scan.Reputation.Any(r => r.Verdict == ReputationVerdict.Clean)
                    ? "Online scanners consider this file clean."
                    : "Not in any malware database. Unknown files aren't necessarily safe: Run Through WG shows what it does.",
                worst == Severity.Medium ? Theme.P.BannerWarning : Theme.P.BannerSuccess);
        else
            SetVerdict("Checked on this PC only", _onlineError ?? "Add a MalwareBazaar or VirusTotal API key in Settings to also check online.",
                Theme.P.BannerInfo);
    }

    private List<(Severity Severity, string Text)> Findings()
    {
        var list = _inspection!.Notes.Select(n => (n.Severity, n.Text)).ToList();
        if (_scan is { } s)
        {
            foreach (var r in s.Reputation)
            {
                var severity = r.Verdict switch
                {
                    ReputationVerdict.Malicious => Severity.High,
                    ReputationVerdict.Suspicious => Severity.Medium,
                    _ => Severity.Info,
                };
                var verdict = r.Verdict switch
                {
                    ReputationVerdict.NotFound => "not in its database",
                    ReputationVerdict.Error => "lookup failed",
                    var v => v.ToString().ToLowerInvariant(),
                };
                list.Add((severity, $"{r.Provider}: {verdict}{(r.Label is null ? "" : $" ({r.Label})")}{(string.IsNullOrWhiteSpace(r.Detail) || r.Verdict == ReputationVerdict.NotFound ? "" : $". {r.Detail}")}"));
            }
            if (s.VirusTotalQuotaReached) list.Add((Severity.Info, "VirusTotal skipped: today's lookup limit is used up."));
            if (s.Blocked) list.Add((Severity.Medium, "This program is on WinGaurdian's Blocked list."));
            if (s.PreviouslyQuarantined) list.Add((Severity.Medium, "A file with this exact content was quarantined by WinGaurdian before."));
            if (s.Trusted) list.Add((Severity.Info, "This file is on WinGaurdian's trusted list."));
        }
        if (_onlineError is not null) list.Add((Severity.Info, _onlineError));
        return list.OrderByDescending(x => x.Severity).ToList();
    }

    private void SetVerdict(string title, string subtitle, Color color)
    {
        _verdict.Text = title;
        _verdict.BackColor = color;
        _subtitle.Text = subtitle;
    }

    private string BuildReport()
    {
        var sb = new StringBuilder("WINGAURDIAN FILE SCAN\n");
        foreach (ListViewItem row in _details.Items) sb.AppendLine($"{row.SubItems[0].Text}: {row.SubItems[1].Text}");
        sb.AppendLine($"\nVerdict: {_verdict.Text} - {_subtitle.Text}\n\nFindings:");
        foreach (var (severity, text) in Findings()) sb.AppendLine($"  [{severity}] {text}");
        return sb.ToString();
    }

    private static bool IsRunnable(string path)
    {
        try
        {
            Core.Analysis.SuspendedLauncher.BuildCommand(path, "");
            return true;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>Opens the Program Monitor in its own window (process), so closing this scan window doesn't close it.</summary>
    private void RunThroughWg()
    {
        var start = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
        start.ArgumentList.Add("--run");
        start.ArgumentList.Add(_path);
        System.Diagnostics.Process.Start(start)?.Dispose();
    }

    private async Task QuarantineAsync()
    {
        var inWindows = _path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\", StringComparison.OrdinalIgnoreCase);
        if (MessageBox.Show(this,
                $"Quarantine this file?\n\n{_path}\n\nAny process running it will be ended and the file moved to quarantine. You can restore it from the dashboard." +
                (inWindows ? "\n\nWARNING: this file is in the Windows folder. Removing a legitimate system file can break Windows." : ""),
                "WinGaurdian - Quarantine", MessageBoxButtons.YesNo, inWindows ? MessageBoxIcon.Warning : MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return;
        if (await ServiceCommands.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Quarantine, Path = _path, Note = "From Scan with WG" }, this))
            Render();
    }

    private static ContextMenuStrip CopyMenu(ListView list)
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Copy", null, (_, _) => ListViews.CopySelected(list));
        return menu;
    }
}
