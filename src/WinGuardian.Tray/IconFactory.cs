using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace WinGuardian.Tray;

/// <summary>Draws the shield icons at runtime so no .ico assets are needed yet.</summary>
internal static class IconFactory
{
    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr handle);

    public static Icon CreateShield(Color fill, string? glyph = null)
    {
        using var bitmap = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);

            using var path = new GraphicsPath();
            path.AddLines(new PointF[]
            {
                new(16, 1), new(29, 6), new(28, 17), new(16, 31), new(4, 17), new(3, 6),
            });
            path.CloseFigure();
            using var brush = new SolidBrush(fill);
            using var outline = new Pen(Color.FromArgb(40, 40, 40), 1.5f);
            g.FillPath(brush, path);
            g.DrawPath(outline, path);

            if (glyph is not null)
            {
                using var font = new Font("Segoe UI", 14, FontStyle.Bold, GraphicsUnit.Pixel);
                using var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                g.DrawString(glyph, font, Brushes.White, new RectangleF(0, 1, 32, 28), format);
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
