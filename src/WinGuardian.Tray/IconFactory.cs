using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;

namespace WinGuardian.Tray;

/// <summary>Tray icons: the WinGaurdian shield, with a small coloured status badge in the corner.</summary>
internal static class IconFactory
{
    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr handle);

    /// <param name="badge">Badge colour, or null for the plain shield.</param>
    /// <param name="glyph">Character drawn in the badge.</param>
    /// <param name="grayscale">Draw the shield without colour (service not running).</param>
    public static Icon CreateTrayIcon(Color? badge = null, string? glyph = null, bool grayscale = false)
    {
        // Twice the small-icon size keeps the shield crisp on high-DPI displays (Windows scales it down).
        var size = Math.Max(32, SystemInformation.SmallIconSize.Width * 2);
        using var bitmap = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.Clear(Color.Transparent);

            using var attributes = new ImageAttributes();
            if (grayscale)
            {
                attributes.SetColorMatrix(new ColorMatrix(
                [
                    [0.30f, 0.30f, 0.30f, 0, 0],
                    [0.59f, 0.59f, 0.59f, 0, 0],
                    [0.11f, 0.11f, 0.11f, 0, 0],
                    [0, 0, 0, 0.75f, 0],
                    [0, 0, 0, 0, 1],
                ]));
            }
            var shield = Branding.Shield;
            g.DrawImage(shield, new Rectangle(0, 0, size, size), 0, 0, shield.Width, shield.Height, GraphicsUnit.Pixel, attributes);

            if (badge is { } color)
            {
                var d = size * 0.55f;
                var rect = new RectangleF(size - d, size - d, d - 1, d - 1);
                using var fill = new SolidBrush(color);
                using var outline = new Pen(Color.White, Math.Max(1.5f, size / 24f));
                g.FillEllipse(fill, rect);
                g.DrawEllipse(outline, rect);
                if (glyph is not null)
                {
                    using var font = new Font("Segoe UI", d * 0.62f, FontStyle.Bold, GraphicsUnit.Pixel);
                    using var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                    g.DrawString(glyph, font, Brushes.White, rect, format);
                }
            }
        }

        // Icon.FromHandle does not own the handle; clone into a managed icon and free the original.
        var handle = bitmap.GetHicon();
        try
        {
            using var temp = Icon.FromHandle(handle);
            return (Icon)temp.Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }
}
