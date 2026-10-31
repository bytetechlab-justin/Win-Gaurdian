using System.Diagnostics;

namespace WinGuardian.Tray;

/// <summary>Shows exactly what is sent to Gemini, streams the answer, and lets the user edit and ask again.</summary>
internal sealed class AskGeminiForm : Form
{
    private readonly string _cli;
    private readonly TextBox _prompt;
    private readonly TextBox _answer;
    private readonly Label _status = new() { AutoSize = true, Margin = new Padding(8, 9, 8, 0) };
    private readonly Button _ask = new() { Text = "Ask Again", AutoSize = true };
    private readonly Button _stop = new() { Text = "Stop", AutoSize = true, Enabled = false };
    private readonly System.Windows.Forms.Timer _clock = new() { Interval = 1000 };
    private CancellationTokenSource? _running;
    private Stopwatch? _elapsed;

    private AskGeminiForm(string cli, string title, string prompt)
    {
        _cli = cli;
        Text = $"WinGaurdian - Ask Gemini: {title}";
        Width = 1000;
        Height = 780;
        StartPosition = FormStartPosition.CenterParent;
        Font = new Font("Segoe UI", 9f);
        Icon = Branding.AppIcon;

        var note = new Label
        {
            Dock = DockStyle.Top,
            Height = 34,
            Padding = new Padding(8, 4, 8, 0),
            ForeColor = SystemColors.GrayText,
            Text = "This text is sent to Google Gemini through your Gemini CLI (agy), using your account. Gemini runs in plan mode: " +
                   "it can answer, but cannot change files or run commands. You can edit the question and ask again.",
        };
        _prompt = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            Font = new Font("Consolas", 9f),
            Text = prompt.Replace("\n", Environment.NewLine),
        };
        _answer = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            BackColor = SystemColors.Window,
            Font = new Font("Segoe UI", 10f),
        };

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 260 };
        split.Panel1.Controls.Add(_prompt);
        split.Panel1.Controls.Add(new Label { Text = "Question sent to Gemini:", Dock = DockStyle.Top, Height = 18 });
        split.Panel2.Controls.Add(_answer);
        split.Panel2.Controls.Add(new Label { Text = "Gemini's answer:", Dock = DockStyle.Top, Height = 18 });

        var copy = new Button { Text = "Copy Answer", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        copy.Click += (_, _) => { if (_answer.TextLength > 0) Clipboard.SetText(_answer.Text); };
        close.Click += (_, _) => Close();
        _ask.Click += async (_, _) => await AskAsync();
        _stop.Click += (_, _) => _running?.Cancel();

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 40, Padding = new Padding(6), FlowDirection = FlowDirection.LeftToRight };
        buttons.Controls.AddRange([_ask, _stop, copy, close, _status]);

        Controls.Add(split);
        Controls.Add(note);
        Controls.Add(buttons);
        CancelButton = close;

        _clock.Tick += (_, _) => { if (_elapsed is not null) _status.Text = $"Waiting for Gemini... {(int)_elapsed.Elapsed.TotalSeconds}s"; };
        Shown += async (_, _) => await AskAsync();
        FormClosing += (_, _) => _running?.Cancel();
    }

    /// <summary>Opens the window and asks immediately. <paramref name="what"/> describes the item, e.g. "this security event".</summary>
    public static void Show(IWin32Window? owner, string title, string what, string details)
    {
        var cli = GeminiAssistant.FindCli();
        if (cli is null)
        {
            MessageBox.Show(owner,
                "The Gemini CLI (agy.exe) was not found.\n\nWinGaurdian looks in %LOCALAPPDATA%\\agy\\bin and on your PATH. " +
                "If it is installed elsewhere, set the WINGUARDIAN_AGY_PATH environment variable to its full path.",
                "WinGaurdian - Ask Gemini", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        var form = new AskGeminiForm(cli, title, GeminiAssistant.BuildPrompt(what, details));
        form.FormClosed += (_, _) => form.Dispose();
        form.Show(owner); // not modal: several questions can be open while you keep using the dashboard
    }

    private async Task AskAsync()
    {
        if (_running is not null) return;
        _running = new CancellationTokenSource();
        _answer.Clear();
        _ask.Enabled = false;
        _stop.Enabled = true;
        _prompt.ReadOnly = true;
        _elapsed = Stopwatch.StartNew();
        _clock.Start();
        _status.Text = "Waiting for Gemini...";
        try
        {
            var result = await GeminiAssistant.AskAsync(_cli, _prompt.Text.Replace(Environment.NewLine, "\n"),
                chunk =>
                {
                    if (!IsDisposed && IsHandleCreated)
                        BeginInvoke(() => _answer.AppendText(chunk.Replace("**", "").Replace("\r\n", "\n").Replace("\n", Environment.NewLine))); // plain-text box: drop Markdown bold markers
                },
                _running.Token);
            if (IsDisposed) return; // closed while waiting

            _status.Text = result switch
            {
                { Cancelled: true } => "Stopped.",
                { TimedOut: true } => "Gemini did not answer in time.",
                { ExitCode: 0 } when _answer.TextLength > 0 => $"Answered in {(int)_elapsed.Elapsed.TotalSeconds}s.",
                _ => $"Gemini CLI exited with code {result.ExitCode}.",
            };
            if (result.ExitCode != 0 && result.Error.Length > 0 && !result.Cancelled)
                _answer.AppendText(Environment.NewLine + Environment.NewLine + "[Gemini CLI error] " + result.Error);
        }
        catch (Exception ex) when (!IsDisposed)
        {
            _status.Text = "Could not run the Gemini CLI.";
            _answer.Text = ex.Message;
        }
        finally
        {
            _clock.Stop();
            _running.Dispose();
            _running = null;
            if (!IsDisposed)
            {
                _ask.Enabled = true;
                _stop.Enabled = false;
                _prompt.ReadOnly = false;
            }
        }
    }
}
