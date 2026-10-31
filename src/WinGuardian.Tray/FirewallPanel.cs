using System.Diagnostics;
using WinGuardian.Core.Ipc;
using WinGuardian.Core.Network;

namespace WinGuardian.Tray;

/// <summary>
/// The dashboard's Firewall tab: live listening ports and connections with their programs and services,
/// a 24-hour connection history, and the Windows Firewall's state and rules. Data comes from the service
/// (which can see every process, including protected system ones).
/// </summary>
internal sealed class FirewallPanel : UserControl
{
    private static Color UnsignedColor => Theme.P.MediumRow;
    private static Color RiskyColor => Theme.P.HighRow;

    private readonly Label _status = new() { Dock = DockStyle.Fill, AutoEllipsis = true, Padding = new Padding(4, 6, 4, 0) };
    private readonly TextBox _filter = new() { Width = 260, PlaceholderText = "Filter (program, port, address, service...)" };
    private readonly CheckBox _autoRefresh = new() { Text = "Auto-refresh", Checked = true, AutoSize = true, Margin = new Padding(12, 6, 0, 0) };
    private readonly ListView _listeners;
    private readonly ListView _connections;
    private readonly ListView _history;
    private readonly ListView _rules;
    private readonly ThemedTabControl _views = new() { Dock = DockStyle.Fill };
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 5000 };
    private NetworkSnapshot? _snapshot;
    private bool _loading;

    public FirewallPanel()
    {
        Dock = DockStyle.Fill;

        _listeners = MakeList(("Protocol", 70), ("Local address", 130), ("Port", 60), ("Program", 160), ("PID", 60),
            ("Services", 260), ("Signature", 220), ("First seen", 120), ("Path", 380));
        _connections = MakeList(("Protocol", 70), ("Local", 170), ("Remote", 220), ("State", 90), ("Program", 160), ("PID", 60),
            ("Services", 220), ("Signature", 200), ("Path", 360));
        _history = MakeList(("Program", 160), ("Protocol", 70), ("Remote address", 200), ("Port", 60), ("First seen", 120),
            ("Last seen", 120), ("Times seen", 80), ("Services", 200), ("Path", 360));
        _rules = MakeList(("Name", 300), ("Direction", 70), ("Action", 60), ("Enabled", 65), ("Protocol", 70), ("Local ports", 100),
            ("Remote ports", 100), ("Program / service", 360), ("Profiles", 110), ("Source", 90));

        _views.TabPages.Add(Page("Listening Ports", _listeners));
        _views.TabPages.Add(Page("Active Connections", _connections));
        _views.TabPages.Add(Page("Connection History (24h)", _history));
        _views.TabPages.Add(Page("Firewall Rules", _rules));

        foreach (var list in new[] { _listeners, _connections, _history })
            list.ContextMenuStrip = BuildEndpointMenu(list);
        _rules.ContextMenuStrip = BuildRuleMenu();

        var refresh = new Button { Text = "Refresh", AutoSize = true };
        refresh.Click += async (_, _) => await RefreshAsync();
        _filter.TextChanged += (_, _) => Render();

        var toolbar = new FlowLayoutPanel { Dock = DockStyle.Right, AutoSize = true, WrapContents = false, Padding = new Padding(0, 4, 4, 0) };
        toolbar.Controls.AddRange([_filter, refresh, _autoRefresh]);
        var top = new Panel { Dock = DockStyle.Top, Height = 36 };
        top.Controls.Add(_status);
        top.Controls.Add(toolbar);

        Controls.Add(_views);
        Controls.Add(top);

        _timer.Tick += async (_, _) =>
        {
            if (_autoRefresh.Checked && Visible && !AnyMenuOpen()) await RefreshAsync();
        };
        VisibleChanged += (_, _) => _timer.Enabled = Visible;
    }

    public async Task RefreshAsync()
    {
        if (_loading) return;
        _loading = true;
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Network });
            if (response.Network is null)
            {
                _status.Text = response.Error ?? "No network data returned.";
                return;
            }
            _snapshot = response.Network;
            Render();
        }
        catch (Exception ex)
        {
            _status.ForeColor = Theme.P.Danger;
            _status.Text = "Could not reach the WinGaurdian service: " + ex.Message;
        }
        finally
        {
            _loading = false;
        }
    }

    private void Render()
    {
        if (_snapshot is not { } s) return;

        var fw = s.Firewall;
        var off = fw.Profiles.Where(p => !p.Enabled).Select(p => p.Name).ToList();
        _status.ForeColor = !fw.ServiceRunning || off.Count > 0 ? Theme.P.Danger : Theme.P.Text;
        _status.Text =
            (fw.ServiceRunning ? "Windows Firewall: " + string.Join("  ", fw.Profiles.Select(p => $"{p.Name} {(p.Enabled ? "ON" : "OFF")}"))
                               : "Windows Firewall service is NOT running") +
            $"   |   {s.Listeners.Count} listening, {s.Connections.Count} connections, {fw.RuleCount} rules ({fw.InboundAllowRuleCount} allow inbound)" +
            $"   |   updated {s.CapturedUtc.ToLocalTime():T}";

        var filter = _filter.Text.Trim();
        bool Match(params string?[] fields) =>
            filter.Length == 0 || fields.Any(f => f?.Contains(filter, StringComparison.OrdinalIgnoreCase) == true);

        Fill(_listeners, s.Listeners.Where(l => Match(l.Protocol, l.LocalAddress, l.LocalPort.ToString(), l.ProcessName, l.Pid.ToString(), l.Services, l.ProcessPath, l.Signature)),
            l => Colored(new ListViewItem(
            [
                l.Protocol, l.LocalAddress, l.LocalPort.ToString(), l.ProcessName, l.Pid.ToString(), l.Services ?? "", l.Signature ?? "",
                l.FirstSeenUtc?.ToLocalTime().ToString("g") ?? "baseline", l.ProcessPath ?? "",
            ]) { Tag = l }, l), l => $"{l.Protocol}|{l.LocalAddress}|{l.LocalPort}|{l.Pid}");

        Fill(_connections, s.Connections.Where(c => Match(c.Protocol, c.LocalAddress, c.RemoteAddress, c.RemotePort?.ToString(), c.LocalPort.ToString(), c.State, c.ProcessName, c.Pid.ToString(), c.Services, c.ProcessPath)),
            c => Colored(new ListViewItem(
            [
                c.Protocol, $"{c.LocalAddress}:{c.LocalPort}", $"{c.RemoteAddress}:{c.RemotePort}", c.State ?? "", c.ProcessName, c.Pid.ToString(),
                c.Services ?? "", c.Signature ?? "", c.ProcessPath ?? "",
            ]) { Tag = c }, c), c => $"{c.Protocol}|{c.LocalAddress}|{c.LocalPort}|{c.RemoteAddress}|{c.RemotePort}");

        Fill(_history, s.History.Where(h => Match(h.ProcessName, h.RemoteAddress, h.RemotePort.ToString(), h.Protocol, h.Services, h.ProcessPath)),
            h => new ListViewItem(
            [
                h.ProcessName, h.Protocol, h.RemoteAddress, h.RemotePort.ToString(), h.FirstSeenUtc.ToLocalTime().ToString("g"),
                h.LastSeenUtc.ToLocalTime().ToString("g"), h.TimesSeen.ToString(), h.Services ?? "", h.ProcessPath ?? "",
            ]) { Tag = h }, h => $"{h.ProcessPath ?? h.ProcessName}|{h.Protocol}|{h.RemoteAddress}|{h.RemotePort}");

        Fill(_rules, s.Rules.Where(r => Match(r.Name, r.Direction, r.Action, r.Protocol, r.LocalPorts, r.RemotePorts, r.Program, r.Service, r.Profiles, r.Source))
                .OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase),
            r => new ListViewItem(
            [
                r.Name, r.Direction, r.Action, r.Enabled ? "Yes" : "No", r.Protocol, r.LocalPorts ?? "Any", r.RemotePorts ?? "Any",
                r.Program ?? (r.Service is null ? (r.Package is null ? "Any program" : "App package") : $"Service: {r.Service}"),
                r.Profiles, r.Source,
            ])
            {
                Tag = r,
                ForeColor = r.Enabled ? SystemColors.WindowText : SystemColors.GrayText,
                BackColor = r.AllowsInbound && r.Program is not null && !r.Program.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase)
                    ? UnsignedColor : Theme.P.Surface,
            }, r => r.Key);
    }

    private static ListViewItem Colored(ListViewItem item, NetworkEndpoint e)
    {
        if (e.ProcessPath is not null && e.Signer is null)
            item.BackColor = e.InUserWritableLocation ? RiskyColor : UnsignedColor;
        return item;
    }

    private static void Fill<T>(ListView list, IEnumerable<T> rows, Func<T, ListViewItem> toItem, Func<T, string> keyOf) =>
        ListViews.Fill(list, rows, toItem, keyOf);

    // ------------------------------------------------------------------ menus

    private ContextMenuStrip BuildEndpointMenu(ListView list)
    {
        var menu = new ContextMenuStrip();
        var copy = new ToolStripMenuItem("Copy");
        var filterProcess = new ToolStripMenuItem("Show Only This Program");
        var openLocation = new ToolStripMenuItem("Open File Location");
        var lookup = new ToolStripMenuItem("Look Up Program Hash Online");
        var block = new ToolStripMenuItem("Block Executable...");
        var askGemini = new ToolStripMenuItem("Ask Gemini...");
        menu.Items.AddRange([copy, filterProcess, new ToolStripSeparator(), openLocation, lookup, new ToolStripSeparator(), block,
            new ToolStripSeparator(), askGemini]);
        askGemini.Click += (_, _) => AskGemini(list);

        (string? Path, string Name)? Selected() => list.SelectedItems.Count == 0 ? null : list.SelectedItems[0].Tag switch
        {
            NetworkEndpoint e => (e.ProcessPath, e.ProcessName),
            ConnectionHistoryEntry h => (h.ProcessPath, h.ProcessName),
            _ => null,
        };

        menu.Opening += (_, args) =>
        {
            var s = Selected();
            if (s is null) { args.Cancel = true; return; }
            openLocation.Enabled = lookup.Enabled = block.Enabled = s.Value.Path is not null;
        };
        copy.Click += (_, _) => CopySelected(list);
        filterProcess.Click += (_, _) => { if (Selected() is { } s) _filter.Text = s.Name; };
        openLocation.Click += (_, _) => { if (Selected()?.Path is { } p) OpenLocation(p); };
        lookup.Click += async (_, _) =>
        {
            if (Selected()?.Path is { } p)
                await ServiceCommands.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Lookup, Path = p }, FindForm());
        };
        block.Click += async (_, _) =>
        {
            if (Selected() is { Path: { } p } s)
                await ServiceCommands.ConfirmAndBlockAsync(FindForm(), p, $"From the Firewall tab ({s.Name})");
        };
        return menu;
    }

    private ContextMenuStrip BuildRuleMenu()
    {
        var menu = new ContextMenuStrip();
        var copy = new ToolStripMenuItem("Copy");
        var openLocation = new ToolStripMenuItem("Open Program Location");
        var raw = new ToolStripMenuItem("Show Rule Definition...");
        var askGemini = new ToolStripMenuItem("Ask Gemini...");
        menu.Items.AddRange([copy, openLocation, raw, new ToolStripSeparator(), askGemini]);
        askGemini.Click += (_, _) => AskGemini(_rules);
        FirewallRule? Selected() => _rules.SelectedItems.Count == 0 ? null : _rules.SelectedItems[0].Tag as FirewallRule;
        menu.Opening += (_, args) =>
        {
            if (Selected() is not { } r) { args.Cancel = true; return; }
            openLocation.Enabled = r.Program is not null && File.Exists(r.Program);
        };
        copy.Click += (_, _) => CopySelected(_rules);
        openLocation.Click += (_, _) => { if (Selected()?.Program is { } p) OpenLocation(p); };
        raw.Click += (_, _) =>
        {
            if (Selected() is { } r)
                MessageBox.Show(FindForm(), $"{r.Name}\n\n{r.Description}\n\n{r.Describe()}\n\nRegistry value: {r.Id} ({r.Source})\n\n{r.Raw}",
                    "Firewall rule", MessageBoxButtons.OK, MessageBoxIcon.Information);
        };
        return menu;
    }

    /// <summary>Sends the selected rows (up to 10) to Gemini through the agy CLI.</summary>
    private void AskGemini(ListView list)
    {
        var rows = list.SelectedItems.Cast<ListViewItem>().Take(10).Select(i => i.Tag).ToList();
        var reports = rows.Select(tag => tag switch
        {
            NetworkEndpoint e => EventReport.Build(e),
            ConnectionHistoryEntry h => EventReport.Build(h),
            FirewallRule r => EventReport.Build(r),
            _ => null,
        }).OfType<string>().ToList();
        if (reports.Count == 0) return;

        var kind = rows[0] switch
        {
            FirewallRule => "firewall rule",
            ConnectionHistoryEntry => "network connection",
            NetworkEndpoint { RemoteAddress: null } => "listening network port",
            _ => "network connection",
        };
        var context = _snapshot is { } s
            ? $"\n\n(Context: Windows Firewall is {(s.Firewall.ServiceRunning ? string.Join(", ", s.Firewall.Profiles.Select(p => $"{p.Name} {(p.Enabled ? "on" : "off")}")) : "not running")}.)"
            : "";
        AskGeminiForm.Show(FindForm(),
            reports.Count == 1 ? kind : $"{reports.Count} items",
            reports.Count == 1 ? $"this {kind} seen on their PC" : $"these {reports.Count} items from the Windows Firewall view",
            string.Join("\n\n----------\n\n", reports) + context);
    }

    private static void CopySelected(ListView list) => ListViews.CopySelected(list);

    internal static void OpenLocation(string path)
    {
        if (File.Exists(path))
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
    }

    private bool AnyMenuOpen() =>
        new[] { _listeners, _connections, _history, _rules }.Any(l => l.ContextMenuStrip?.Visible == true);

    // ---------------------------------------------------------------- helpers

    private static TabPage Page(string title, Control content)
    {
        var page = new TabPage(title);
        page.Controls.Add(content);
        return page;
    }

    private static ListView MakeList(params (string Title, int Width)[] columns) => ListViews.MakeSortable(columns);
}
