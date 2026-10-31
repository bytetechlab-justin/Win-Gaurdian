using System.Text.Json;
using WinGuardian.Core;
using WinGuardian.Core.Ipc;
using WinGuardian.Core.Tasks;

namespace WinGuardian.Tray;

/// <summary>
/// Full details of one event: a readable report on top and every recorded fact below in expandable sections,
/// with Copy and Export JSON.
/// </summary>
internal sealed class EventDetailsForm : Form
{
    private static readonly JsonSerializerOptions Indented = new(PipeProtocol.Json) { WriteIndented = true };

    private static readonly Dictionary<string, string> SectionTitles = new()
    {
        ["Configuration"] = "Task configuration",
        ["Actions"] = "Executable / COM handler details",
        ["Comparison"] = "Previous vs current configuration",
        ["ModifyingProcess"] = "Modifying process",
        ["Assessment"] = "Threat assessment",
        ["Target"] = "Digital signature and file",
        ["Com"] = "Registry registration",
    };

    private readonly string _report;
    private readonly string _json;
    private readonly GuardianEvent _event;

    public EventDetailsForm(GuardianEvent e)
    {
        _event = e;
        var analysis = TaskAnalysisFormatter.TryParse(e.Analysis);
        _report = EventReport.Build(e);
        _json = e.Analysis is not null ? Reindent(e.Analysis) : JsonSerializer.Serialize(e, Indented);

        Text = $"WinGaurdian - Event #{e.Id}";
        Width = 900;
        Height = 760;
        StartPosition = FormStartPosition.CenterParent;
        Font = new Font("Segoe UI", 9f);
        Icon = Branding.AppIcon;

        var report = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Font = new Font("Consolas", 9.5f),
            Text = _report.Replace("\n", Environment.NewLine),
            BackColor = Theme.P.Surface,
        };

        var tree = new TreeView { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 9f) };
        BuildTree(tree);

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 400 };
        split.Panel1.Controls.Add(report);
        split.Panel2.Controls.Add(tree);
        split.Panel2.Controls.Add(new Label { Text = "Recorded evidence (expand sections):", Dock = DockStyle.Top, Height = 20 });

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 40, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(6) };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var export = new Button { Text = "Export JSON...", AutoSize = true };
        var copy = new Button { Text = "Copy Details", AutoSize = true };
        close.Click += (_, _) => Close();
        copy.Click += (_, _) => Clipboard.SetText(_report.Replace("\n", Environment.NewLine));
        export.Click += (_, _) => ExportJson();
        buttons.Controls.AddRange([close, export, copy]);

        Controls.Add(split);
        Controls.Add(buttons);
        CancelButton = close;
        Theme.Apply(this);
        // A focused TextBox selects all its text by default; start with nothing selected, scrolled to the top.
        Shown += (_, _) => report.Select(0, 0);
    }

    public static async Task ShowAsync(IWin32Window owner, long id)
    {
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest { Command = PipeProtocol.Commands.Event, Id = id.ToString() });
            if (response.Events is not [var e])
            {
                MessageBox.Show(owner, response.Error ?? "Event not found.", "WinGaurdian", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            using var form = new EventDetailsForm(e);
            form.ShowDialog(owner);
        }
        catch (Exception ex)
        {
            MessageBox.Show(owner, "Could not load the event.\n\n" + ex.Message, "WinGaurdian", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void BuildTree(TreeView tree)
    {
        using var doc = JsonDocument.Parse(_json);
        tree.BeginUpdate();
        foreach (var property in doc.RootElement.EnumerateObject())
        {
            var node = MakeNode(property.Name, property.Value);
            tree.Nodes.Add(node);
            if (property.Name == "Assessment") node.ExpandAll();
        }
        tree.EndUpdate();
    }

    private static TreeNode MakeNode(string name, JsonElement value)
    {
        var title = SectionTitles.GetValueOrDefault(name, Humanize(name));
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
            {
                var node = new TreeNode(title);
                foreach (var p in value.EnumerateObject()) node.Nodes.Add(MakeNode(p.Name, p.Value));
                return node;
            }
            case JsonValueKind.Array:
            {
                var items = value.EnumerateArray().ToList();
                var node = new TreeNode($"{title} [{items.Count}]");
                for (var i = 0; i < items.Count; i++)
                {
                    var item = items[i];
                    node.Nodes.Add(item.ValueKind is JsonValueKind.Object or JsonValueKind.Array
                        ? MakeNode($"#{i + 1}", item)
                        : new TreeNode(item.ToString()));
                }
                return node;
            }
            case JsonValueKind.Null:
                return new TreeNode($"{title}: (none)");
            default:
                return new TreeNode($"{title}: {value}");
        }
    }

    private static string Humanize(string name) =>
        string.Concat(name.Select((ch, i) => i > 0 && char.IsUpper(ch) && !char.IsUpper(name[i - 1]) ? " " + ch : ch.ToString()));

    private void ExportJson()
    {
        using var dialog = new SaveFileDialog
        {
            FileName = $"winguardian-event-{_event.Id}.json",
            Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*",
        };
        if (dialog.ShowDialog(this) == DialogResult.OK)
            File.WriteAllText(dialog.FileName, _json);
    }

    private static string Reindent(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return JsonSerializer.Serialize(doc.RootElement, Indented);
    }

}
