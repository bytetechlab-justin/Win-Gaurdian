using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using WinGuardian.Core;

namespace WinGuardian.Tray;

/// <summary>Every colour the UI uses, so the light and dark themes stay consistent.</summary>
internal sealed record Palette(
    bool IsDark,
    Color Window,        // form background
    Color Surface,       // lists, text areas
    Color Raised,        // toolbars, headers, tab strip, buttons
    Color Hover,
    Color Border,
    Color Input,
    Color Text,
    Color MutedText,
    Color Accent,        // blue highlights: selected tab, primary buttons, links, focus
    Color AccentHover,
    Color AccentText,
    Color Selection,     // selected list rows
    Color Danger,        // error/alert text
    Color HighRow,
    Color MediumRow,
    Color LowRow,
    Color BannerWarning, Color BannerWarningText,
    Color BannerDanger, Color BannerSuspicious, Color BannerSuccess, Color BannerInfo, Color BannerNeutral);

/// <summary>
/// WinGaurdian's look. Dark (default): near-black blue-grey surfaces with blue accents, dark title bars,
/// scrollbars and menus. Light: the classic Windows look. Chosen from the tray menu; stored per user.
/// </summary>
internal static class Theme
{
    public static readonly Palette Dark = new(
        IsDark: true,
        Window: Hex(0x15171C), Surface: Hex(0x1B1E25), Raised: Hex(0x232733), Hover: Hex(0x2D3341), Border: Hex(0x333A48),
        Input: Hex(0x11131A), Text: Hex(0xE6E9EF), MutedText: Hex(0x98A2B3),
        Accent: Hex(0x3B82F6), AccentHover: Hex(0x2563EB), AccentText: Color.White, Selection: Hex(0x1E3A66),
        Danger: Hex(0xF87171),
        HighRow: Hex(0x46202A), MediumRow: Hex(0x41361A), LowRow: Hex(0x1A2A42),
        BannerWarning: Hex(0x3A2F12), BannerWarningText: Hex(0xFCD675),
        BannerDanger: Hex(0x5A1E26), BannerSuspicious: Hex(0x553417), BannerSuccess: Hex(0x163A26), BannerInfo: Hex(0x1C2C47),
        BannerNeutral: Hex(0x232733));

    public static readonly Palette Light = new(
        IsDark: false,
        Window: SystemColors.Control, Surface: SystemColors.Window, Raised: SystemColors.Control, Hover: SystemColors.ControlLight,
        Border: SystemColors.ControlDark, Input: SystemColors.Window, Text: SystemColors.ControlText, MutedText: SystemColors.GrayText,
        Accent: Hex(0x0B63CE), AccentHover: Hex(0x0A58B8), AccentText: Color.White, Selection: SystemColors.Highlight,
        Danger: Color.Firebrick,
        HighRow: Color.FromArgb(255, 220, 220), MediumRow: Color.FromArgb(255, 243, 205), LowRow: Color.FromArgb(240, 246, 255),
        BannerWarning: Color.FromArgb(255, 243, 205), BannerWarningText: SystemColors.ControlText,
        BannerDanger: Color.FromArgb(255, 205, 205), BannerSuspicious: Color.FromArgb(255, 225, 190), BannerSuccess: Color.FromArgb(214, 240, 214),
        BannerInfo: Color.FromArgb(225, 230, 240), BannerNeutral: SystemColors.ControlLight);

    private const string SettingsKey = @"Software\WinGuardian\Tray";
    private const string DarkValue = "DarkTheme";

    /// <summary>Read once per process: the theme can only change when the tray restarts.</summary>
    public static bool IsDark { get; } = ReadDarkSetting();

    public static Palette P => IsDark ? Dark : Light;

    private static bool ReadDarkSetting()
    {
        using var key = Registry.CurrentUser.OpenSubKey(SettingsKey);
        return key?.GetValue(DarkValue) is not int value || value != 0; // dark unless turned off
    }

    public static void SaveDarkSetting(bool dark)
    {
        using var key = Registry.CurrentUser.CreateSubKey(SettingsKey);
        key.SetValue(DarkValue, dark ? 1 : 0, RegistryValueKind.DWord);
    }

    /// <summary>Call once at start-up, before any window exists.</summary>
    public static void Initialize()
    {
#pragma warning disable WFO5001 // dark mode for the common controls (title bars, scrollbars, system colours) is marked experimental
        Application.SetColorMode(IsDark ? SystemColorMode.Dark : SystemColorMode.Classic);
#pragma warning restore WFO5001
    }

    public static Color SeverityRow(Severity severity) => severity switch
    {
        Severity.High => P.HighRow,
        Severity.Medium => P.MediumRow,
        Severity.Low => P.LowRow,
        _ => P.Surface,
    };

    // ------------------------------------------------------------------ applying

    /// <summary>Styles a form and everything on it (call at the end of its constructor).</summary>
    public static void Apply(Form form)
    {
        if (!IsDark) return;
        form.BackColor = P.Window;
        form.ForeColor = P.Text;
        form.HandleCreated += (_, _) => DarkTitleBar(form.Handle);
        if (form.IsHandleCreated) DarkTitleBar(form.Handle);
        Style(form);
    }

    /// <summary>Marks a button as the main action (filled blue).</summary>
    public static void Primary(Button button)
    {
        button.Tag = PrimaryTag;
        if (IsDark) StyleButton(button);
    }

    private static readonly object PrimaryTag = new();

    private static void Style(Control control)
    {
        foreach (Control child in control.Controls) StyleOne(child);
        control.ControlAdded += (_, e) => { if (e.Control is not null) StyleOne(e.Control); };
        if (control.ContextMenuStrip is { } menu) StyleMenu(menu);
    }

    private static void StyleOne(Control c)
    {
        switch (c)
        {
            case Button b:
                StyleButton(b);
                break;
            case CheckBox box:
                box.FlatStyle = FlatStyle.Flat;
                box.FlatAppearance.BorderColor = P.Border;
                box.FlatAppearance.CheckedBackColor = P.Accent;
                box.FlatAppearance.MouseOverBackColor = P.Hover;
                box.ForeColor = P.Text;
                break;
            case LinkLabel link:
                link.LinkColor = link.ActiveLinkColor = Hex(0x60A5FA);
                link.VisitedLinkColor = Hex(0x93C5FD);
                break;
            case TextBox text:
                text.BackColor = text.ReadOnly ? P.Surface : P.Input;
                text.ForeColor = P.Text;
                text.BorderStyle = BorderStyle.FixedSingle;
                break;
            case NumericUpDown number:
                number.BackColor = P.Input;
                number.ForeColor = P.Text;
                number.BorderStyle = BorderStyle.FixedSingle;
                break;
            case ListView list:
                StyleList(list);
                break;
            case TreeView tree:
                tree.BackColor = P.Surface;
                tree.ForeColor = P.Text;
                tree.LineColor = P.Border;
                tree.BorderStyle = BorderStyle.None;
                tree.HandleCreated += (_, _) => SetWindowTheme(tree.Handle, "DarkMode_Explorer", null);
                break;
            case TabPage page:
                page.UseVisualStyleBackColor = false;
                page.BackColor = P.Window;
                page.ForeColor = P.Text;
                break;
            case SplitContainer split:
                split.BackColor = P.Border; // the splitter bar
                split.Panel1.BackColor = split.Panel2.BackColor = P.Window;
                break;
        }
        if (c.ContextMenuStrip is { } menu) StyleMenu(menu);
        if (c is not ListView and not TreeView) Style(c);
    }

    private static void StyleButton(Button b)
    {
        if (!IsDark) return;
        var primary = ReferenceEquals(b.Tag, PrimaryTag);
        b.FlatStyle = FlatStyle.Flat;
        b.UseVisualStyleBackColor = false;
        b.BackColor = primary ? P.Accent : P.Raised;
        b.ForeColor = primary ? P.AccentText : P.Text;
        b.FlatAppearance.BorderColor = primary ? P.Accent : P.Border;
        b.FlatAppearance.MouseOverBackColor = primary ? P.AccentHover : P.Hover;
        b.FlatAppearance.MouseDownBackColor = primary ? P.AccentHover : P.Border;
        b.Padding = new Padding(8, 2, 8, 2);
        b.Cursor = Cursors.Hand;
    }

    // ---------------------------------------------------------------- lists

    private static void StyleList(ListView list)
    {
        list.BackColor = P.Surface;
        list.ForeColor = P.Text;
        list.BorderStyle = BorderStyle.None;
        list.GridLines = false; // light grid lines look harsh on dark; rows are separated by colour instead
        list.OwnerDraw = true;
        list.DrawColumnHeader += (_, e) =>
        {
            using var back = new SolidBrush(P.Raised);
            e.Graphics.FillRectangle(back, e.Bounds);
            using var line = new Pen(P.Border);
            e.Graphics.DrawLine(line, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
            e.Graphics.DrawLine(line, e.Bounds.Right - 1, e.Bounds.Top + 4, e.Bounds.Right - 1, e.Bounds.Bottom - 5);
            var text = e.Bounds with { X = e.Bounds.X + 6, Width = e.Bounds.Width - 10 };
            TextRenderer.DrawText(e.Graphics, e.Header?.Text, Bold(list.Font), text, P.MutedText,
                TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        };
        list.DrawItem += (_, e) => e.DrawDefault = false;
        list.DrawSubItem += (_, e) =>
        {
            if (e.Item is null || e.SubItem is null) return;
            var selected = e.Item.Selected;
            var back = selected ? P.Selection
                : e.Item.BackColor == SystemColors.Window || e.Item.BackColor == list.BackColor ? P.Surface
                : e.Item.BackColor;
            using (var brush = new SolidBrush(back)) e.Graphics.FillRectangle(brush, e.Bounds);
            if (selected && e.ColumnIndex == 0)
            {
                using var bar = new SolidBrush(P.Accent);
                e.Graphics.FillRectangle(bar, e.Bounds.X, e.Bounds.Y, 3, e.Bounds.Height);
            }
            using (var line = new Pen(Color.FromArgb(40, P.Border)))
                e.Graphics.DrawLine(line, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
            var fore = e.Item.ForeColor == SystemColors.GrayText ? P.MutedText : P.Text;
            var text = e.Bounds with { X = e.Bounds.X + 6, Width = e.Bounds.Width - 10 };
            TextRenderer.DrawText(e.Graphics, e.SubItem.Text, list.Font, text, fore,
                TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
        };
        // Owner-drawn rows don't repaint on selection changes by themselves when focus moves.
        list.SelectedIndexChanged += (_, _) => list.Invalidate();
        list.HandleCreated += (_, _) => DarkList(list);
        if (list.IsHandleCreated) DarkList(list);
    }

    private static void DarkList(ListView list)
    {
        SetWindowTheme(list.Handle, "DarkMode_ItemsView", null); // dark scrollbars, no column lines in empty space
        var header = SendMessage(list.Handle, 0x101F /* LVM_GETHEADER */, IntPtr.Zero, IntPtr.Zero);
        if (header != IntPtr.Zero) SetWindowTheme(header, "DarkMode_ItemsView", null); // dark area right of the last column
    }

    private static readonly Dictionary<Font, Font> BoldFonts = [];

    private static Font Bold(Font font)
    {
        if (!BoldFonts.TryGetValue(font, out var bold)) BoldFonts[font] = bold = new Font(font, FontStyle.Bold);
        return bold;
    }

    // ---------------------------------------------------------------- menus

    public static void StyleMenu(ToolStrip menu)
    {
        if (!IsDark) return;
        menu.Renderer = MenuRenderer.Instance;
        menu.BackColor = P.Raised;
        menu.ForeColor = P.Text;
    }

    private sealed class MenuRenderer() : ToolStripProfessionalRenderer(new MenuColors())
    {
        public static readonly MenuRenderer Instance = new();

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = e.Item.Enabled ? P.Text : P.MutedText;
            base.OnRenderItemText(e);
        }

        protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
        {
            e.ArrowColor = P.MutedText;
            base.OnRenderArrow(e);
        }

        protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e)
        {
            var box = new Rectangle(e.ImageRectangle.X - 2, e.ImageRectangle.Y - 2, e.ImageRectangle.Width + 4, e.ImageRectangle.Height + 4);
            using var back = new SolidBrush(P.Accent);
            e.Graphics.FillRectangle(back, box);
            using var tick = new Pen(Color.White, 2f);
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            e.Graphics.DrawLines(tick, [new(box.X + 4, box.Y + box.Height / 2), new(box.X + box.Width / 2 - 1, box.Bottom - 5), new(box.Right - 4, box.Y + 4)]);
        }
    }

    private sealed class MenuColors : ProfessionalColorTable
    {
        public override Color ToolStripDropDownBackground => P.Raised;
        public override Color ImageMarginGradientBegin => P.Raised;
        public override Color ImageMarginGradientMiddle => P.Raised;
        public override Color ImageMarginGradientEnd => P.Raised;
        public override Color MenuBorder => P.Border;
        public override Color MenuItemBorder => P.Accent;
        public override Color MenuItemSelected => P.Selection;
        public override Color MenuItemSelectedGradientBegin => P.Selection;
        public override Color MenuItemSelectedGradientEnd => P.Selection;
        public override Color MenuItemPressedGradientBegin => P.Selection;
        public override Color MenuItemPressedGradientEnd => P.Selection;
        public override Color SeparatorDark => P.Border;
        public override Color SeparatorLight => P.Border;
        public override Color CheckBackground => P.Accent;
        public override Color CheckSelectedBackground => P.AccentHover;
    }

    // ---------------------------------------------------------------- native

    private static void DarkTitleBar(IntPtr hwnd)
    {
        var on = 1;
        DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, ref on, sizeof(int));
        var caption = ToColorRef(P.Window);
        DwmSetWindowAttribute(hwnd, 35 /* DWMWA_CAPTION_COLOR (Windows 11) */, ref caption, sizeof(int));
        var border = ToColorRef(P.Border);
        DwmSetWindowAttribute(hwnd, 34 /* DWMWA_BORDER_COLOR */, ref border, sizeof(int));
    }

    private static int ToColorRef(Color c) => c.R | (c.G << 8) | (c.B << 16);

    private static Color Hex(int rgb) => Color.FromArgb((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF);

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    private static extern int SetWindowTheme(IntPtr hwnd, string? subAppName, string? subIdList);

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam);
}

/// <summary>
/// A TabControl that draws itself in the theme (the standard one always paints a light tab strip and border).
/// Selected tab: raised with a blue underline. Light theme: the normal Windows look.
/// </summary>
internal sealed class ThemedTabControl : TabControl
{
    public ThemedTabControl()
    {
        if (!Theme.IsDark) return;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        SizeMode = TabSizeMode.Normal;
        Padding = new Point(14, 6);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var p = Theme.P;
        var g = e.Graphics;
        g.Clear(p.Window);
        if (TabCount == 0) return;

        var strip = GetTabRect(0);
        using (var line = new Pen(p.Border))
            g.DrawLine(line, 0, strip.Bottom, Width, strip.Bottom);

        for (var i = 0; i < TabCount; i++)
        {
            var rect = GetTabRect(i);
            var selected = i == SelectedIndex;
            var hot = rect.Contains(PointToClient(MousePosition));
            if (selected || hot)
            {
                using var back = new SolidBrush(selected ? p.Raised : p.Hover);
                g.FillRectangle(back, rect.X, rect.Y, rect.Width, rect.Height + 1);
            }
            if (selected)
            {
                using var accent = new SolidBrush(p.Accent);
                g.FillRectangle(accent, rect.X, rect.Bottom - 2, rect.Width, 3);
            }
            TextRenderer.DrawText(g, TabPages[i].Text, Font, rect, selected ? p.Text : p.MutedText,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
        }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (Theme.IsDark) Invalidate(new Rectangle(0, 0, Width, DisplayRectangle.Top));
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        if (Theme.IsDark) Invalidate();
    }

    protected override void OnSelectedIndexChanged(EventArgs e)
    {
        base.OnSelectedIndexChanged(e);
        if (Theme.IsDark) Invalidate();
    }
}
