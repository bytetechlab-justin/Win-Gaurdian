using WinGuardian.Core;
using WinGuardian.Core.Ipc;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Tray;

/// <summary>Status summary plus tabs for events, quarantine and the trust list (built in code, no designer).</summary>
internal sealed class DashboardForm : Form
{
    private readonly Label _statusLabel;
    private readonly CheckBox _unackOnly;
    private readonly ListView _events;
    private readonly ListView _quarantine;
    private readonly ListView _trusted;
    private readonly TabControl _tabs;
    private readonly FirewallPanel _firewall = new();
    private readonly ProgramMonitorPanel _programMonitor = new();
    private readonly ListView _blocked;
    private readonly Button _powerButton;
    private bool? _protectionOff; // null until the service has answered
    private bool _refreshQueued;

    public const string ProgramMonitorTab = "Program Monitor";

    /// <param name="analyze">Program to pre-fill in the Program Monitor tab.</param>
    /// <param name="autoRun">Start running it straight away (after the usual confirmation), e.g. from Explorer's "Run Through WG".</param>
    public DashboardForm(string? initialTab = null, (string Path, string Arguments)? analyze = null, bool autoRun = false)
    {
        Text = "WinGaurdian";
        Width = 1200;
        Height = 700;
        StartPosition = FormStartPosition.CenterScreen;
        Icon = Branding.AppIcon;
        Font = new Font("Segoe UI", 9f);

        _statusLabel = new Label { Dock = DockStyle.Fill, Padding = new Padding(10), Text = "Connecting..." };

        var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, Padding = new Padding(6, 4, 6, 4) };
        toolbar.Controls.Add(MakeButton("Refresh", RefreshAllAsync));
        var scanButton = MakeButton("Run Full Scan", async () =>
        {
            await ServiceCommands.SendAsync(PipeProtocol.Commands.Scan, this);
            await RefreshAllAsync();
        });
        toolbar.Controls.Add(scanButton);
        toolbar.Controls.Add(MakeButton("Acknowledge All", async () =>
        {
            await ServiceCommands.SendAsync(PipeProtocol.Commands.Acknowledge, this);
            await RefreshAllAsync();
        }));
        toolbar.Controls.Add(MakeButton("Rebuild Baseline...", () => TrayApplicationContext.ConfirmRebuildAsync(this)));
        toolbar.Controls.Add(MakeButton("Settings...", () =>
        {
            ServiceCommands.OpenSettings();
            return RefreshAllAsync();
        }));
        _powerButton = MakeButton("Turn Off", async () =>
        {
            if (_protectionOff is not { } off) return;
            await ServiceCommands.SetProtectionAsync(turnOn: off, this);
            await RefreshAllAsync();
        });
        _powerButton.Enabled = false;
        toolbar.Controls.Add(_powerButton);
        _unackOnly = new CheckBox { Text = "Unacknowledged only", AutoSize = true, Margin = new Padding(16, 8, 0, 0) };
        _unackOnly.CheckedChanged += async (_, _) => await RefreshEventsAsync();
        toolbar.Controls.Add(_unackOnly);

        _events = MakeList(("ID", 55), ("Time", 130), ("Severity", 65), ("Category", 80), ("Change", 75), ("Subject", 420), ("Signature", 230), ("Details", 700));
        _events.DoubleClick += (_, _) => ShowSelectedDetails();
        _events.ContextMenuStrip = BuildEventMenu();

        _quarantine = MakeList(("Quarantined", 130), ("Original location", 450), ("Size", 90), ("Reason", 300), ("SHA256", 450));
        var quarantineButtons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 38, Padding = new Padding(4) };
        quarantineButtons.Controls.Add(MakeButton("Restore", () => QuarantineActionAsync(PipeProtocol.Commands.Restore,
            "Restore this file to its original location? Its path will be added to the trusted list.")));
        quarantineButtons.Controls.Add(MakeButton("Delete Permanently", () => QuarantineActionAsync(PipeProtocol.Commands.DeleteQuarantined,
            "Permanently delete this file? This cannot be undone.")));
        quarantineButtons.Controls.Add(MakeButton("Refresh", RefreshQuarantineAsync));

        _trusted = MakeList(("Kind", 90), ("Value", 650), ("Added", 130), ("Note", 300));
        _blocked = MakeList(("Program", 450), ("Protection", 230), ("Services disabled", 200), ("Blocked", 130), ("Reason", 300), ("SHA256", 450));
        var blockedButtons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 38, Padding = new Padding(4) };
        blockedButtons.Controls.Add(MakeButton("Unblock", UnblockSelectedAsync));
        blockedButtons.Controls.Add(MakeButton("Refresh", RefreshBlockedAsync));

        var trustedButtons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 38, Padding = new Padding(4) };
        trustedButtons.Controls.Add(MakeButton("Remove Trust", RemoveTrustAsync));
        trustedButtons.Controls.Add(MakeButton("Refresh", RefreshTrustedAsync));

        _tabs = new ThemedTabControl { Dock = DockStyle.Fill };
        _tabs.TabPages.Add(MakeTab("Events", _events));
        _tabs.TabPages.Add(MakeTab("Quarantine", _quarantine, quarantineButtons));
        _tabs.TabPages.Add(MakeTab("Blocked", _blocked, blockedButtons));
        _tabs.TabPages.Add(MakeTab("Trusted Items", _trusted, trustedButtons));
        _tabs.TabPages.Add(MakeTab("Firewall", _firewall));
        _tabs.TabPages.Add(MakeTab(ProgramMonitorTab, _programMonitor));
        if (analyze is { } launch) _programMonitor.Prefill(launch.Path, launch.Arguments);
        _tabs.SelectedIndexChanged += async (_, _) => await RefreshCurrentTabAsync();

        Controls.Add(_tabs);
        Controls.Add(toolbar);
        // Header: status on the left, logo in the top-right corner.
        var header = new Panel { Dock = DockStyle.Top, Height = 150 }; // room for the "turned off" line
        header.Controls.Add(_statusLabel);
        header.Controls.Add(new PictureBox
        {
            Image = Branding.Logo,
            SizeMode = PictureBoxSizeMode.Zoom,
            Dock = DockStyle.Right,
            Width = 132,
            Padding = new Padding(6),
        });
        if (Theme.IsDark)
        {
            // A raised status card with a thin blue accent along its bottom edge.
            header.BackColor = Theme.P.Raised;
            header.Controls.Add(new Panel { Dock = DockStyle.Bottom, Height = 2, BackColor = Theme.P.Accent });
            toolbar.Padding = new Padding(6, 8, 6, 4);
            toolbar.Height = 46;
        }
        Controls.Add(header);
        Theme.Primary(scanButton);
        Theme.Apply(this);

        Shown += async (_, _) =>
        {
            if (initialTab is not null) SelectTab(initialTab);
            await RefreshAllAsync();
            if (autoRun && analyze is not null) await _programMonitor.RunAsync();
        };
    }

    public void SelectTab(string title)
    {
        if (_tabs.TabPages.Cast<TabPage>().FirstOrDefault(p => p.Text.Equals(title, StringComparison.OrdinalIgnoreCase)) is { } page)
            _tabs.SelectedTab = page;
    }

    // ------------------------------------------------------------------ status

    public void ApplyStatus(GuardianStatus s)
    {
        string When(DateTime? utc) => utc?.ToLocalTime().ToString("g") ?? "never";
        string OnOff(bool on) => on ? "on" : "off";
        var progress = s.ScanInProgress ? $"  -  {s.ScanFilesProcessed:N0} files processed" : "";
        SetProtectionState(s.ProtectionOff);
        _statusLabel.ForeColor = s.ProtectionOff ? Theme.P.Danger : Theme.P.Text;
        _statusLabel.Text =
            (s.ProtectionOff
                ? $"TURNED OFF since {When(s.ProtectionOffSinceUtc)}: changes are still recorded, but nothing is scanned, looked up, " +
                  "quarantined or blocked automatically. Click Turn On to resume.\n"
                : "") +
            $"Service v{s.ServiceVersion}: {s.Phase}{progress}\n" +
            $"Baseline created: {When(s.BaselineCreatedUtc)}    Last full scan: {When(s.LastFullScanUtc)}\n" +
            $"Baseline: {s.BaselineFileCount:N0} files, {s.BaselineProcessCount:N0} executables, {s.BaselineServiceCount:N0} services/drivers, {s.BaselinePersistenceCount:N0} autostart entries\n" +
            $"Scheduled tasks analysed: {s.BaselineTaskCount:N0}    Task change attribution (auditing): {OnOff(s.TaskAuditingActive)}\n" +
            $"Real-time process tracing (ETW): {OnOff(s.EtwProcessTracing)}    MalwareBazaar: {OnOff(s.MalwareBazaarConfigured)}    VirusTotal: {OnOff(s.VirusTotalConfigured)}    Quarantined files: {s.QuarantineCount}    Blocked programs: {s.BlockedCount}\n" +
            $"Unacknowledged alerts: {s.UnacknowledgedCount:N0}" +
            (s.LastError is null ? "" : $"    Last error: {s.LastError}");
    }

    private void SetProtectionState(bool? off)
    {
        _protectionOff = off;
        _powerButton.Enabled = off is not null;
        _powerButton.Text = off == true ? "Turn On" : "Turn Off";
    }

    public void ApplyDisconnected(string? message = null)
    {
        SetProtectionState(null);
        _statusLabel.ForeColor = Theme.P.Danger;
        _statusLabel.Text = message ?? "The WinGaurdian service is not running or cannot be reached.";
    }

    /// <summary>Called by the tray when new events arrive; coalesced so bursts trigger one reload.</summary>
    public void RefreshEventsSoon()
    {
        if (_refreshQueued || IsDisposed) return;
        _refreshQueued = true;
        BeginInvoke(async () =>
        {
            _refreshQueued = false;
            await RefreshEventsAsync();
        });
    }

    private async Task RefreshAllAsync()
    {
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Status });
            if (response.Status is not null) ApplyStatus(response.Status);
        }
        catch (ServerVerificationException ex)
        {
            ApplyDisconnected(ex.Message);
            return;
        }
        catch
        {
            ApplyDisconnected();
            return;
        }
        await RefreshCurrentTabAsync();
    }

    private Task RefreshCurrentTabAsync() => _tabs.SelectedTab?.Text switch
    {
        "Quarantine" => RefreshQuarantineAsync(),
        "Blocked" => RefreshBlockedAsync(),
        "Trusted Items" => RefreshTrustedAsync(),
        "Firewall" => _firewall.RefreshAsync(),
        ProgramMonitorTab => Task.CompletedTask, // refreshes itself while a program is being monitored
        _ => RefreshEventsAsync(),
    };

    // ------------------------------------------------------------------ events

    private async Task RefreshEventsAsync()
    {
        var response = await TryQueryAsync(new PipeRequest
        {
            Command = PipeProtocol.Commands.Events,
            Limit = 1000,
            UnacknowledgedOnly = _unackOnly.Checked,
        });
        if (response is null) return;

        Fill(_events, response.Events ?? [], e => new ListViewItem(
        [
            e.Id.ToString(),
            e.TimeUtc.ToLocalTime().ToString("g"),
            e.Severity.ToString(),
            e.Category.ToString(),
            e.Change.ToString(),
            e.Subject,
            e.Signature ?? "",
            (e.Details ?? "").Replace('\n', ' '),
        ])
        {
            Tag = e,
            BackColor = e.Severity switch
            {
                Severity.High or Severity.Medium => Theme.SeverityRow(e.Severity),
                _ => Theme.P.Surface,
            },
            ForeColor = e.Acknowledged ? SystemColors.GrayText : SystemColors.WindowText,
        });
    }

    private List<GuardianEvent> SelectedEvents() =>
        _events.SelectedItems.Cast<ListViewItem>().Select(i => i.Tag).OfType<GuardianEvent>().ToList();

    private ContextMenuStrip BuildEventMenu()
    {
        var menu = new ContextMenuStrip();
        var acknowledge = new ToolStripMenuItem("Acknowledge Selected");
        var details = new ToolStripMenuItem("Show Details...");
        var trustFile = new ToolStripMenuItem("Trust This File");
        var trustFolder = new ToolStripMenuItem("Trust Everything in This Folder");
        var trustHash = new ToolStripMenuItem("Trust This File Content (Hash)");
        var trustItem = new ToolStripMenuItem("Trust This Item");
        var trustPublisher = new ToolStripMenuItem("Trust This Publisher");
        var quarantine = new ToolStripMenuItem("Quarantine File...");
        var block = new ToolStripMenuItem("Block Executable...");
        var askGemini = new ToolStripMenuItem("Ask Gemini...");
        var lookup = new ToolStripMenuItem("Look Up Hash Online");
        var openVt = new ToolStripMenuItem("Open in VirusTotal (browser)");
        var copy = new ToolStripMenuItem("Copy Details");

        menu.Items.AddRange([acknowledge, details, new ToolStripSeparator(), trustFile, trustFolder, trustHash, trustItem, trustPublisher,
            new ToolStripSeparator(), quarantine, block, lookup, openVt, new ToolStripSeparator(), askGemini, copy]);

        menu.Opening += (_, args) =>
        {
            var selected = SelectedEvents();
            if (selected.Count == 0) { args.Cancel = true; return; }
            var e = selected[0];
            var single = selected.Count == 1;
            var fileEvent = e.Category is EventCategory.File or EventCategory.Process && e.FilePath is not null;

            details.Enabled = single;
            trustHash.Visible = single && e.Sha256 is not null;
            var behavior = e.Category == EventCategory.Process && e.Change == ChangeKind.Detected;
            trustFile.Visible = trustFolder.Visible = single && fileEvent && !behavior;
            trustItem.Visible = single && e.TrustKey is not null &&
                                (behavior || e.Category is EventCategory.Service or EventCategory.Persistence or EventCategory.ScheduledTask or EventCategory.Network);
            trustItem.Text = behavior ? "Trust This Behavior From This Parent Program"
                : e.Category switch
                {
                    EventCategory.Service => "Trust This Service",
                    EventCategory.ScheduledTask => "Trust This Scheduled Task",
                    EventCategory.Network when e.TrustKey!.StartsWith("Listener|") => "Trust This Program Listening on This Port",
                    EventCategory.Network => "Trust This Firewall Rule",
                    _ => "Trust This Autostart Entry",
                };
            trustPublisher.Visible = single && e.Signer is not null && !behavior &&
                                     e.Category is EventCategory.File or EventCategory.Process or EventCategory.Service or EventCategory.Persistence
                                         or EventCategory.ScheduledTask or EventCategory.Network;
            trustPublisher.Text = $"Trust Everything Signed by \"{e.Signer}\"";
            quarantine.Visible = single && e.FilePath is not null && e.Category != EventCategory.Tamper && e.Change != ChangeKind.Removed;
            askGemini.Text = selected.Count == 1 ? "Ask Gemini..." : $"Ask Gemini About {Math.Min(selected.Count, MaxGeminiItems)} Events...";
            // Always listed so it's discoverable; greyed out (with the reason) when nothing selected can be blocked.
            var blockable = BlockableEvents(selected);
            var paths = blockable.Select(x => x.FilePath!).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            block.Enabled = paths > 0;
            block.Text = paths switch
            {
                0 => "Block Executable (no program file in this event)",
                1 => "Block Executable...",
                _ => $"Block {paths} Executables...",
            };
            lookup.Visible = single && (e.Sha256 is not null || e.FilePath is not null) && e.Category != EventCategory.Tamper;
            openVt.Visible = single && e.Sha256 is not null;
        };

        acknowledge.Click += async (_, _) =>
        {
            var ids = SelectedEvents().Select(e => e.Id).ToList();
            if (await ServiceCommands.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Acknowledge, Ids = ids }, this, showSuccess: false))
                await RefreshEventsAsync();
        };
        details.Click += (_, _) => ShowSelectedDetails();
        trustFile.Click += async (_, _) => await TrustAsync(TrustKind.Path, e => e.FilePath);
        trustFolder.Click += async (_, _) => await TrustAsync(TrustKind.Folder, e => Path.GetDirectoryName(e.FilePath));
        trustHash.Click += async (_, _) => await TrustAsync(TrustKind.Hash, e => e.Sha256);
        trustItem.Click += async (_, _) => await TrustAsync(SelectedEvents()[0] switch
        {
            { Category: EventCategory.Process } => TrustKind.Behavior,
            { Category: EventCategory.Service } => TrustKind.Service,
            _ => TrustKind.Persistence,
        }, e => e.TrustKey);
        trustPublisher.Click += async (_, _) => await TrustAsync(TrustKind.Publisher, e => e.Signer);
        quarantine.Click += async (_, _) => await QuarantineSelectedAsync();
        askGemini.Click += async (_, _) => await AskGeminiAsync();
        block.Click += async (_, _) =>
        {
            var events = BlockableEvents(SelectedEvents());
            if (events.Count == 0) return;
            var paths = events.Select(x => x.FilePath!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var note = events.Count == 1 ? $"From event #{events[0].Id}: {events[0].Subject}" : $"From events {string.Join(", ", events.Select(x => "#" + x.Id))}";
            if (await ServiceCommands.ConfirmAndBlockAsync(this, paths, note, events.Select(x => x.Id).ToList()))
                await RefreshAllAsync();
        };
        lookup.Click += async (_, _) =>
        {
            var e = SelectedEvents()[0];
            await ServiceCommands.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Lookup, Sha256 = e.Sha256, Path = e.FilePath }, this);
        };
        openVt.Click += (_, _) => SettingsForm.OpenUrl($"https://www.virustotal.com/gui/file/{SelectedEvents()[0].Sha256}");
        copy.Click += (_, _) => Clipboard.SetText(string.Join(Environment.NewLine + Environment.NewLine, SelectedEvents().Select(Describe)));
        return menu;
    }

    private const int MaxGeminiItems = 10;

    /// <summary>Sends the selected events (with their full analysis) to Gemini through the agy CLI.</summary>
    private async Task AskGeminiAsync()
    {
        var selected = SelectedEvents().Take(MaxGeminiItems).ToList();
        if (selected.Count == 0) return;
        var reports = new List<string>();
        foreach (var e in selected)
        {
            // The list omits the (large) analysis; fetch each event in full so Gemini sees everything.
            var full = await TryQueryAsync(new PipeRequest { Command = PipeProtocol.Commands.Event, Id = e.Id.ToString() });
            reports.Add(EventReport.Build(full?.Events is [var complete] ? complete : e));
        }
        AskGeminiForm.Show(this,
            selected.Count == 1 ? $"event #{selected[0].Id}" : $"{selected.Count} events",
            selected.Count == 1 ? "this WinGaurdian security event" : $"these {selected.Count} related WinGaurdian security events",
            string.Join("\n\n----------\n\n", reports));
    }

    /// <summary>Events that name a program file that still exists conceptually (not tamper notices or deleted files).</summary>
    private static List<GuardianEvent> BlockableEvents(IEnumerable<GuardianEvent> events) =>
        events.Where(e => e.FilePath is not null && e.Category != EventCategory.Tamper && e.Change != ChangeKind.Removed &&
                          Path.HasExtension(e.FilePath)).ToList();

    private async Task TrustAsync(TrustKind kind, Func<GuardianEvent, string?> valueOf)
    {
        var e = SelectedEvents().FirstOrDefault();
        if (e is null || valueOf(e) is not { } value) return;

        var explanation = kind switch
        {
            TrustKind.Folder => $"Stop alerting on changes to any file in:\n{value}\n\nOnly do this for folders that change legitimately.",
            TrustKind.Hash => $"Trust this exact file content wherever it appears:\nSHA256 {value}",
            TrustKind.Publisher => $"Stop alerting on files, programs, services and autostart entries with a valid signature from:\n{value}\n\n" +
                                   "Only do this for publishers you trust completely. Tampered or unsigned files are still reported.",
            _ => $"Stop alerting on:\n{value}",
        };
        if (MessageBox.Show(this, explanation, "WinGaurdian - Trust", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK)
            return;

        if (await ServiceCommands.SendAsync(new PipeRequest
            {
                Command = PipeProtocol.Commands.Trust,
                TrustKind = kind,
                Value = value,
                Note = $"From event #{e.Id}: {e.Category} {e.Change}",
                Ids = [e.Id],
            }, this))
            await RefreshEventsAsync();
    }

    private async Task QuarantineSelectedAsync()
    {
        var e = SelectedEvents().FirstOrDefault();
        if (e?.FilePath is null) return;

        var inWindows = e.FilePath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\", StringComparison.OrdinalIgnoreCase);
        var message = $"Quarantine this file?\n\n{e.FilePath}\n\nAny process running it will be terminated and the file moved to quarantine. You can restore it later.";
        if (inWindows)
            message += "\n\nWARNING: this file is inside the Windows folder. Removing a legitimate system file can break Windows. Only continue if you are sure it is malicious.";

        if (MessageBox.Show(this, message, "WinGaurdian - Quarantine", MessageBoxButtons.YesNo,
                inWindows ? MessageBoxIcon.Warning : MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return;

        if (await ServiceCommands.SendAsync(new PipeRequest
            {
                Command = PipeProtocol.Commands.Quarantine,
                Path = e.FilePath,
                Note = $"Manual, from event #{e.Id}: {e.Subject}",
                Ids = [e.Id],
            }, this))
            await RefreshAllAsync();
    }

    private void ShowSelectedDetails()
    {
        if (SelectedEvents().FirstOrDefault() is not { } e) return;
        _ = EventDetailsForm.ShowAsync(this, e.Id);
    }

    private static string Describe(GuardianEvent e) =>
        $"{e.TimeUtc.ToLocalTime():F}\nSeverity: {e.Severity}\n{e.Category} {e.Change}\n\n{e.Subject}\n\n{e.Details}" +
        (e.FilePath is null ? "" : $"\n\nFile: {e.FilePath}") +
        (e.Sha256 is null ? "" : $"\nSHA256: {e.Sha256}");

    // -------------------------------------------------------------- quarantine

    private async Task RefreshQuarantineAsync()
    {
        var response = await TryQueryAsync(new PipeRequest { Command = PipeProtocol.Commands.Quarantined });
        if (response is null) return;
        Fill(_quarantine, response.Quarantined ?? [], q => new ListViewItem(
        [
            q.QuarantinedUtc.ToLocalTime().ToString("g"),
            q.OriginalPath + (q.PendingReboot ? "  (original deleted at next reboot)" : ""),
            $"{q.Size:N0}",
            q.Reason ?? "",
            q.Sha256 ?? "",
        ]) { Tag = q });
    }

    private async Task QuarantineActionAsync(string command, string confirmation)
    {
        if (_quarantine.SelectedItems.Count == 0 || _quarantine.SelectedItems[0].Tag is not QuarantineItem item) return;
        if (MessageBox.Show(this, $"{confirmation}\n\n{item.OriginalPath}", "WinGaurdian - Quarantine",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return;
        if (await ServiceCommands.SendAsync(new PipeRequest { Command = command, Id = item.Id }, this))
            await RefreshQuarantineAsync();
    }

    // ----------------------------------------------------------------- trusted

    private async Task RefreshTrustedAsync()
    {
        var response = await TryQueryAsync(new PipeRequest { Command = PipeProtocol.Commands.Trusted });
        if (response is null) return;
        Fill(_trusted, response.Trusted ?? [], t => new ListViewItem(
            [t.Kind.ToString(), t.Value, t.AddedUtc.ToLocalTime().ToString("g"), t.Note ?? ""]) { Tag = t });
    }

    private async Task RefreshBlockedAsync()
    {
        var response = await TryQueryAsync(new PipeRequest { Command = PipeProtocol.Commands.Blocked });
        if (response is null) return;
        Fill(_blocked, response.Blocked ?? [], b => new ListViewItem(
        [
            b.Path,
            b.AclApplied ? "Windows refuses to run it" : "Terminated whenever it starts",
            string.Join(", ", b.Services.Select(s => s.Name)),
            b.AddedUtc.ToLocalTime().ToString("g"),
            b.Reason ?? "",
            b.Sha256 ?? "",
        ]) { Tag = b });
    }

    private async Task UnblockSelectedAsync()
    {
        if (_blocked.SelectedItems.Count == 0 || _blocked.SelectedItems[0].Tag is not BlockedItem b) return;
        if (MessageBox.Show(this, $"Allow this program to run again?\n\n{b.Path}", "WinGaurdian - Unblock",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return;
        if (await ServiceCommands.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Unblock, Id = b.Id }, this))
            await RefreshBlockedAsync();
    }

    private async Task RemoveTrustAsync()
    {
        if (_trusted.SelectedItems.Count == 0 || _trusted.SelectedItems[0].Tag is not TrustEntry t) return;
        if (await ServiceCommands.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Untrust, TrustKind = t.Kind, Value = t.Value }, this))
            await RefreshTrustedAsync();
    }

    // ----------------------------------------------------------------- helpers

    private async Task<PipeResponse?> TryQueryAsync(PipeRequest request)
    {
        try
        {
            return await PipeClient.SendAsync(request);
        }
        catch (ServerVerificationException ex)
        {
            ApplyDisconnected(ex.Message);
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static void Fill<T>(ListView list, IEnumerable<T> rows, Func<T, ListViewItem> toItem)
    {
        list.BeginUpdate();
        list.Items.Clear();
        foreach (var row in rows) list.Items.Add(toItem(row));
        list.EndUpdate();
    }

    private static ListView MakeList(params (string Title, int Width)[] columns)
    {
        var list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false };
        foreach (var (title, width) in columns) list.Columns.Add(title, width);
        return list;
    }

    private static TabPage MakeTab(string title, Control content, Control? bottom = null)
    {
        var page = new TabPage(title);
        page.Controls.Add(content);
        if (bottom is not null) page.Controls.Add(bottom);
        return page;
    }

    private static Button MakeButton(string text, Func<Task> onClick)
    {
        var button = new Button { Text = text, AutoSize = true };
        button.Click += async (_, _) => await onClick();
        return button;
    }
}
