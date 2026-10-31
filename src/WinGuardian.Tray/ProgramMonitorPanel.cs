using System.ComponentModel;
using System.Text;
using System.Text.Json;
using WinGuardian.Core;
using WinGuardian.Core.Analysis;
using WinGuardian.Core.Ipc;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Tray;

/// <summary>
/// The dashboard's Program Monitor tab: run a program and watch everything it (and anything it starts) does:
/// files, registry, processes, network connections and DNS lookups. Monitoring only: the program is not
/// isolated, so its changes are real. The service does the recording; this tab starts the program suspended,
/// asks the service to record it, lets it run, and shows the results.
/// </summary>
internal sealed class ProgramMonitorPanel : UserControl
{
    private readonly TextBox _path = new() { Width = 430, PlaceholderText = "Program, script or installer to run" };
    private readonly TextBox _arguments = new() { Width = 220, PlaceholderText = "Arguments (optional)" };
    private readonly Button _run = new() { Text = "Run && Monitor", AutoSize = true };
    private readonly Button _stop = new() { Text = "Stop Monitoring", AutoSize = true, Enabled = false };
    private readonly Button _end = new() { Text = "End Program", AutoSize = true, Enabled = false };
    private readonly Label _status = new() { AutoSize = true, UseMnemonic = false, Margin = new Padding(6, 8, 6, 0), Text = "Choose a program and click Run & Monitor." };
    private readonly TextBox _filter = new() { Width = 220, PlaceholderText = "Filter (path, key, address...)" };
    private readonly CheckBox _showReads = new() { Text = "Include files/keys it only read", AutoSize = true, Margin = new Padding(10, 6, 0, 0) };
    private readonly Button _export = new() { Text = "Export Report...", AutoSize = true, Enabled = false };
    private readonly Button _askGemini = new() { Text = "Ask Gemini...", AutoSize = true, Enabled = false };

    private readonly ListView _findings = ListViews.MakeSortable(("Severity", 70), ("Area", 70), ("What it did", 700), ("Why it matters", 420));
    private readonly ListView _processes = ListViews.MakeSortable(("Severity", 70), ("PID", 60), ("Parent", 60), ("Program", 160), ("Command line", 420),
        ("Started", 75), ("Exited", 75), ("Exit code", 65), ("Admin", 50), ("Signature", 220), ("Why flagged", 300), ("Path", 360));
    private readonly ListView _files = ListViews.MakeSortable(("Severity", 70), ("Operation", 95), ("Path", 520), ("By", 120), ("Written", 75),
        ("Times", 50), ("First", 75), ("Details", 260), ("Why flagged", 320));
    private readonly ListView _registry = ListViews.MakeSortable(("Severity", 70), ("Operation", 95), ("Key", 480), ("Value", 160), ("Data", 300),
        ("Type", 90), ("By", 120), ("Times", 50), ("Result", 110), ("Why flagged", 320));
    private readonly ListView _network = ListViews.MakeSortable(("Severity", 70), ("Protocol", 60), ("Direction", 70), ("Host", 220), ("Address", 200),
        ("Port", 55), ("By", 120), ("Sent", 75), ("Received", 75), ("Attempts", 60), ("First", 75), ("Why flagged", 320));
    private readonly ListView _dns = ListViews.MakeSortable(("Severity", 70), ("Name", 300), ("Type", 60), ("Answer", 400), ("By", 120), ("Times", 50),
        ("Why flagged", 320));
    private readonly ListView _alerts = ListViews.MakeSortable(("ID", 60), ("Time", 130), ("Severity", 70), ("Category", 90), ("Change", 80), ("Subject", 600));
    private readonly ThemedTabControl _views = new() { Dock = DockStyle.Fill };
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 2000 };

    private string? _runId;
    private AnalysisReport? _report;
    private bool _loading;

    public ProgramMonitorPanel()
    {
        Dock = DockStyle.Fill;

        var warning = new Label
        {
            Dock = DockStyle.Top,
            Height = 40,
            Padding = new Padding(8, 4, 8, 4),
            BackColor = Theme.P.BannerWarning,
            ForeColor = Theme.P.BannerWarningText,
            Text = "Monitoring only, not a sandbox: the program runs for real on this PC. WinGaurdian records every file, registry, " +
                   "process and network action it takes, but does not block or undo them. Only run programs you would be willing to run " +
                   "anyway; analyse suspected malware in a virtual machine.",
        };

        var browse = new Button { Text = "Browse...", AutoSize = true };
        browse.Click += (_, _) => Browse();
        _run.Click += async (_, _) => await RunAsync();
        _stop.Click += async (_, _) => await StopAsync(terminate: false);
        _end.Click += async (_, _) => await StopAsync(terminate: true);
        _export.Click += (_, _) => Export();
        _askGemini.Click += (_, _) => AskGemini();
        _filter.TextChanged += (_, _) => Render();
        _showReads.CheckedChanged += async (_, _) => await RefreshAsync();

        var launchRow = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, Padding = new Padding(4, 4, 4, 0), WrapContents = false };
        launchRow.Controls.AddRange([_path, browse, _arguments, _run, _stop, _end]);
        var viewRow = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 34, Padding = new Padding(4, 2, 4, 0), WrapContents = false };
        viewRow.Controls.AddRange([_filter, _showReads, _export, _askGemini, _status]);

        _views.TabPages.Add(Page("Findings", _findings));
        _views.TabPages.Add(Page("Processes", _processes));
        _views.TabPages.Add(Page("Files", _files));
        _views.TabPages.Add(Page("Registry", _registry));
        _views.TabPages.Add(Page("Network", _network));
        _views.TabPages.Add(Page("DNS Lookups", _dns));
        _views.TabPages.Add(Page("Other Alerts", _alerts));

        foreach (var list in new[] { _findings, _processes, _files, _registry, _network, _dns, _alerts })
            list.ContextMenuStrip = BuildMenu(list);
        _alerts.DoubleClick += (_, _) =>
        {
            if (_alerts.SelectedItems.Count > 0 && _alerts.SelectedItems[0].Tag is GuardianEvent e)
                _ = EventDetailsForm.ShowAsync(FindForm()!, e.Id);
        };

        Controls.Add(_views);
        Controls.Add(viewRow);
        Controls.Add(launchRow);
        Controls.Add(warning);

        Theme.Primary(_run);
        _timer.Tick += async (_, _) => await RefreshAsync();
    }

    /// <summary>Pre-fills the program to run (used when the dashboard reopens elevated for a program that needs admin rights).</summary>
    public void Prefill(string path, string? arguments)
    {
        _path.Text = path;
        _arguments.Text = arguments ?? "";
        _status.Text = "Ready: click Run & Monitor to start the program.";
    }

    // ------------------------------------------------------------------ running

    private void Browse()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Choose a program to run and monitor",
            Filter = "Programs, scripts and installers|*.exe;*.com;*.scr;*.bat;*.cmd;*.ps1;*.vbs;*.vbe;*.js;*.jse;*.wsf;*.msi;*.hta|All files|*.*",
        };
        if (dialog.ShowDialog(FindForm()) == DialogResult.OK) _path.Text = dialog.FileName;
    }

    internal async Task RunAsync()
    {
        var path = _path.Text.Trim().Trim('"');
        if (path.Length == 0 || !File.Exists(path))
        {
            MessageBox.Show(FindForm(), "Choose a program file that exists.", "WinGaurdian - Program Monitor", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        if (_report?.State == AnalysisState.Running)
        {
            MessageBox.Show(FindForm(), "A program is still being monitored. Click Stop Monitoring or End Program first.",
                "WinGaurdian - Program Monitor", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        if (MessageBox.Show(FindForm(),
                $"Run this program now?\n\n{path}\n\n" +
                "It runs normally on this PC with your permissions. It is NOT isolated: anything it changes, installs or sends " +
                "really happens. WinGaurdian will record everything it does so you can review it.\n\n" +
                "Only continue if you would be willing to run this program anyway.",
                "WinGaurdian - Run & Monitor", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return;

        SuspendedLauncher launcher;
        try
        {
            launcher = SuspendedLauncher.Start(path, _arguments.Text, null);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == SuspendedLauncher.ErrorElevationRequired)
        {
            OfferElevation(path);
            return;
        }
        catch (Exception ex) when (ex is Win32Exception or NotSupportedException)
        {
            MessageBox.Show(FindForm(), "Could not start the program.\n\n" + ex.Message, "WinGaurdian - Program Monitor",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        using (launcher)
        {
            PipeResponse response;
            try
            {
                response = await PipeClient.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.AnalysisStart, Pid = launcher.ProcessId }, 5000);
            }
            catch (Exception ex)
            {
                response = PipeResponse.Fail("Could not reach the WinGaurdian service: " + ex.Message);
            }

            if (!response.Ok || response.Message is not { } id)
            {
                launcher.Terminate(); // never let it run unrecorded
                MessageBox.Show(FindForm(), "Monitoring could not start, so the program was not run.\n\n" + response.Error,
                    "WinGaurdian - Program Monitor", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            _runId = id;
            _report = null;
            ClearLists();
            launcher.Resume();
            _status.Text = $"Started {Path.GetFileName(path)} (PID {launcher.ProcessId}). Recording...";
        }
        SetRunning(true);
        _timer.Start();
        await RefreshAsync();
    }

    private void OfferElevation(string path)
    {
        if (ServiceCommands.IsElevated)
        {
            MessageBox.Show(FindForm(), "Windows refused to start the program (it requires elevation).", "WinGaurdian - Program Monitor",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (MessageBox.Show(FindForm(),
                "This program needs administrator rights.\n\nTo monitor it, it has to be started from a WinGaurdian window that is " +
                "running as administrator. Open one now? (Windows will ask for permission.)",
                "WinGaurdian - Program Monitor", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            ServiceCommands.RelaunchElevated("--analyze " + EncodeLaunch(path, _arguments.Text));
    }

    public static string EncodeLaunch(string path, string? arguments) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new[] { path, arguments ?? "" })));

    public static (string Path, string Arguments)? DecodeLaunch(string encoded)
    {
        try
        {
            return JsonSerializer.Deserialize<string[]>(Encoding.UTF8.GetString(Convert.FromBase64String(encoded))) is [var path, var args]
                ? (path, args)
                : null;
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return null;
        }
    }

    private async Task StopAsync(bool terminate)
    {
        if (_runId is null) return;
        if (terminate && MessageBox.Show(FindForm(), "End the program and every process it started?", "WinGaurdian - Program Monitor",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            return;
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.AnalysisStop, Id = _runId, Terminate = terminate });
            _status.Text = response.Ok ? response.Message ?? "" : response.Error ?? "Could not stop monitoring.";
        }
        catch (Exception ex)
        {
            _status.Text = "Could not reach the WinGaurdian service: " + ex.Message;
        }
        await RefreshAsync();
    }

    private void SetRunning(bool running)
    {
        _run.Enabled = !running;
        _stop.Enabled = _end.Enabled = running;
        _path.ReadOnly = _arguments.ReadOnly = running;
    }

    // ------------------------------------------------------------------ results

    private async Task RefreshAsync()
    {
        if (_runId is null || _loading) return;
        _loading = true;
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest
            {
                Command = PipeProtocol.Commands.AnalysisReport,
                Id = _runId,
                IncludeReads = _showReads.Checked,
            }, 5000);
            if (response.Analysis is not { } report)
            {
                _timer.Stop();
                SetRunning(false);
                _status.Text = response.Error ?? "No results.";
                return;
            }
            _report = report;
            if (report.State != AnalysisState.Running)
            {
                _timer.Stop();
                SetRunning(false);
            }
            Render();
        }
        catch (Exception ex)
        {
            _status.Text = "Could not reach the WinGaurdian service: " + ex.Message;
        }
        finally
        {
            _loading = false;
        }
    }

    private void Render()
    {
        if (_report is not { } r) return;
        _export.Enabled = _askGemini.Enabled = true;

        var elapsed = (r.EndedUtc ?? DateTime.UtcNow) - r.StartedUtc;
        var findings = AnalysisReportFormatter.Findings(r);
        var changes = r.Files.Count(f => f.Operation != FileOperation.Opened);
        _status.ForeColor = findings.Any(f => f.Severity == Severity.High) ? Theme.P.Danger : Theme.P.Text;
        _status.Text =
            $"{(r.State == AnalysisState.Running ? "Recording" : AnalysisReportFormatter.StateText(r.State))} - {elapsed:hh\\:mm\\:ss}  |  " +
            $"{r.Processes.Count} process(es), {changes} file change(s), {r.Registry.Count(x => x.Operation != RegistryOperation.KeyOpened)} registry change(s), " +
            $"{r.Network.Count} connection(s), {r.Dns.Count} lookup(s)  |  {findings.Count(f => f.Severity >= Severity.Medium)} finding(s)" +
            (r.Truncated ? "  |  some activity not kept (limit reached)" : "");

        _views.TabPages[0].Text = $"Findings ({findings.Count})";
        _views.TabPages[1].Text = $"Processes ({r.Processes.Count})";
        _views.TabPages[2].Text = $"Files ({r.Files.Count})";
        _views.TabPages[3].Text = $"Registry ({r.Registry.Count})";
        _views.TabPages[4].Text = $"Network ({r.Network.Count})";
        _views.TabPages[5].Text = $"DNS Lookups ({r.Dns.Count})";
        _views.TabPages[6].Text = $"Other Alerts ({r.RelatedEvents.Count})";

        var filter = _filter.Text.Trim();
        bool Match(params string?[] fields) => filter.Length == 0 || fields.Any(f => f?.Contains(filter, StringComparison.OrdinalIgnoreCase) == true);
        static string Time(DateTime? utc) => utc?.ToLocalTime().ToString("HH:mm:ss") ?? "";

        ListViews.Fill(_findings, findings.Where(f => Match(f.Area, f.Text, f.Reason)),
            f => Colored(new ListViewItem([f.Severity.ToString(), f.Area, f.Text, f.Reason]) { Tag = f }, f.Severity),
            f => f.Area + f.Text);

        ListViews.Fill(_processes, r.Processes.Where(p => Match(p.ImagePath, p.CommandLine, p.Pid.ToString(), p.Reason)),
            p => Colored(new ListViewItem(
            [
                p.Severity.ToString(), p.Pid.ToString(), p.ParentPid.ToString(), Path.GetFileName(p.ImagePath ?? "?"), p.CommandLine ?? "",
                Time(p.StartedUtc), Time(p.ExitedUtc), p.ExitCode?.ToString() ?? "", p.Elevated ? "Yes" : "", p.Signature ?? "(checking...)",
                p.Reason ?? "", p.ImagePath ?? "",
            ]) { Tag = p }, p.Severity), p => p.Pid + "|" + p.StartedUtc.Ticks);

        ListViews.Fill(_files, r.Files.Where(f => Match(f.Path, f.Operation.ToString(), f.ProcessName, f.Detail, f.Reason)),
            f => Colored(new ListViewItem(
            [
                f.Severity.ToString(), f.Operation.ToString(), f.Path, f.ProcessName, f.Bytes > 0 ? AnalysisReportFormatter.Bytes(f.Bytes) : "",
                f.Count.ToString(), Time(f.FirstUtc), f.Detail ?? "", f.Reason ?? "",
            ]) { Tag = f }, f.Severity), f => $"{f.Path}|{f.Operation}|{f.Pid}");

        ListViews.Fill(_registry, r.Registry.Where(a => Match(a.Key, a.ValueName, a.Data, a.Operation.ToString(), a.ProcessName, a.Reason)),
            a => Colored(new ListViewItem(
            [
                a.Severity.ToString(), a.Operation.ToString(), a.Key,
                a.ValueName is null ? "" : a.ValueName.Length == 0 ? "(Default)" : a.ValueName,
                a.Data ?? "", a.ValueType ?? "", a.ProcessName, a.Count.ToString(), a.Failure is null ? "OK" : "Failed: " + a.Failure, a.Reason ?? "",
            ]) { Tag = a }, a.Severity), a => $"{a.Key}|{a.ValueName}|{a.Operation}|{a.Pid}");

        ListViews.Fill(_network, r.Network.Where(n => Match(n.HostName, n.RemoteAddress, n.RemotePort.ToString(), n.Protocol, n.ProcessName, n.Reason)),
            n => Colored(new ListViewItem(
            [
                n.Severity.ToString(), n.Protocol, n.Inbound ? "Inbound" : "Outbound", n.HostName ?? "", n.RemoteAddress, n.RemotePort.ToString(),
                n.ProcessName, AnalysisReportFormatter.Bytes(n.BytesSent), AnalysisReportFormatter.Bytes(n.BytesReceived), n.Attempts.ToString(),
                Time(n.FirstUtc), n.Reason ?? "",
            ]) { Tag = n }, n.Severity), n => $"{n.Protocol}|{n.RemoteAddress}|{n.RemotePort}|{n.Pid}|{n.Inbound}");

        ListViews.Fill(_dns, r.Dns.Where(d => Match(d.Name, d.Results, d.ProcessName)),
            d => Colored(new ListViewItem(
            [
                d.Severity.ToString(), d.Name, d.QueryType, d.Results ?? "", d.ProcessName, d.Count.ToString(), d.Reason ?? "",
            ]) { Tag = d }, d.Severity), d => $"{d.Name}|{d.QueryType}|{d.Pid}");

        ListViews.Fill(_alerts, r.RelatedEvents.Where(e => Match(e.Subject, e.Details, e.FilePath)),
            e => Colored(new ListViewItem(
            [
                e.Id.ToString(), e.TimeUtc.ToLocalTime().ToString("g"), e.Severity.ToString(), e.Category.ToString(), e.Change.ToString(), e.Subject,
            ]) { Tag = e }, e.Severity), e => e.Id.ToString());
    }

    private static ListViewItem Colored(ListViewItem item, Severity severity)
    {
        item.BackColor = Theme.SeverityRow(severity);
        return item;
    }

    private void ClearLists()
    {
        foreach (var list in new[] { _findings, _processes, _files, _registry, _network, _dns, _alerts }) list.Items.Clear();
    }

    // ---------------------------------------------------------------- actions

    private ContextMenuStrip BuildMenu(ListView list)
    {
        var menu = new ContextMenuStrip();
        var copy = new ToolStripMenuItem("Copy");
        var openLocation = new ToolStripMenuItem("Open File Location");
        var lookup = new ToolStripMenuItem("Look Up File Hash Online");
        var block = new ToolStripMenuItem("Block Executable...");
        menu.Items.AddRange([copy, new ToolStripSeparator(), openLocation, lookup, block]);

        string? SelectedFile() => list.SelectedItems.Count == 0 ? null : list.SelectedItems[0].Tag switch
        {
            AnalysisProcess p => p.ImagePath,
            FileActivity f => f.Path,
            GuardianEvent e => e.FilePath,
            _ => null,
        };

        menu.Opening += (_, args) =>
        {
            if (list.SelectedItems.Count == 0) { args.Cancel = true; return; }
            var file = SelectedFile();
            var exists = file is not null && Path.IsPathRooted(file) && File.Exists(file);
            openLocation.Visible = lookup.Visible = block.Visible = file is not null;
            openLocation.Enabled = lookup.Enabled = exists;
            block.Enabled = exists && SeverityRules.IsExecutable(file!);
        };
        copy.Click += (_, _) => ListViews.CopySelected(list);
        openLocation.Click += (_, _) => { if (SelectedFile() is { } f) FirewallPanel.OpenLocation(f); };
        lookup.Click += async (_, _) =>
        {
            if (SelectedFile() is { } f)
                await ServiceCommands.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Lookup, Path = f }, FindForm());
        };
        block.Click += async (_, _) =>
        {
            if (SelectedFile() is { } f)
                await ServiceCommands.ConfirmAndBlockAsync(FindForm(), f, $"From the Program Monitor ({Path.GetFileName(_report?.ProgramPath ?? f)})");
        };
        return menu;
    }

    private void Export()
    {
        if (_report is not { } r) return;
        using var dialog = new SaveFileDialog
        {
            Title = "Export program monitor report",
            Filter = "Text report (*.txt)|*.txt|JSON data (*.json)|*.json",
            FileName = $"WinGaurdian-{Path.GetFileNameWithoutExtension(r.ProgramPath ?? "program")}-{r.StartedUtc.ToLocalTime():yyyyMMdd-HHmmss}",
        };
        if (dialog.ShowDialog(FindForm()) != DialogResult.OK) return;
        try
        {
            var json = dialog.FilterIndex == 2 || dialog.FileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase);
            File.WriteAllText(dialog.FileName, json
                ? JsonSerializer.Serialize(r, new JsonSerializerOptions(PipeProtocol.Json) { WriteIndented = true })
                : AnalysisReportFormatter.Build(r));
            _status.Text = "Report saved to " + dialog.FileName;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(FindForm(), "Could not save the report.\n\n" + ex.Message, "WinGaurdian", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void AskGemini()
    {
        if (_report is not { } r) return;
        AskGeminiForm.Show(FindForm(),
            $"what {Path.GetFileName(r.ProgramPath ?? "a program")} did",
            "what a program did when they ran it under WinGaurdian's Program Monitor (a behaviour report of the files, registry, " +
            "processes and network activity it caused; the program was not isolated), and whether it looks like malware, adware or a normal program",
            AnalysisReportFormatter.Build(r, GeminiAssistant.MaxDetailsChars - 200));
    }

    private static TabPage Page(string title, Control content)
    {
        var page = new TabPage(title);
        page.Controls.Add(content);
        return page;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _timer.Dispose();
        base.Dispose(disposing);
    }
}
