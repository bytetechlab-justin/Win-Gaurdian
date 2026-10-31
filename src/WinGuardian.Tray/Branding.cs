namespace WinGuardian.Tray;

/// <summary>Product name, logo and icons (embedded from Assets\; regenerate with scripts\build-icons.ps1).</summary>
internal static class Branding
{
    public const string Name = "WinGaurdian";

    private static readonly Lazy<Icon> AppIconLazy = new(() => new Icon(Resource("app.ico")));
    private static readonly Lazy<Image> LogoLazy = new(() => Image.FromStream(Resource("logo.png")));
    private static readonly Lazy<Bitmap> ShieldLazy = new(() => new Bitmap(Resource("shield.png")));

    /// <summary>Multi-size program icon, shared by every window.</summary>
    public static Icon AppIcon => AppIconLazy.Value;

    /// <summary>Full logo for the dashboard.</summary>
    public static Image Logo => LogoLazy.Value;

    /// <summary>High-resolution shield used to draw the tray icons.</summary>
    public static Bitmap Shield => ShieldLazy.Value;

    private static Stream Resource(string name) =>
        typeof(Branding).Assembly.GetManifestResourceStream(name)
        ?? throw new InvalidOperationException($"Embedded resource '{name}' is missing.");
}
