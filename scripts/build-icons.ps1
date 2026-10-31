<#
.SYNOPSIS
    Regenerates the app's logo/icon assets from the master logo PNG.
    - Assets\logo.png    the logo, 512 px, shown in the dashboard's top-right corner
    - Assets\shield.png  the shield (cropped to its visible area, without any wordmark), 256 px, for the tray icon
    - Assets\WinGaurdian.ico  multi-size program icon (16-256 px) from the shield
.EXAMPLE
    .\scripts\build-icons.ps1 -Source C:\path\WinGaurdian.png
#>
param(
    [Parameter(Mandatory)] [string]$Source
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$assets = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\WinGuardian.Tray\Assets'
New-Item -ItemType Directory -Force $assets | Out-Null

function Resize([System.Drawing.Image]$image, [System.Drawing.Rectangle]$from, [int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)
    $g.DrawImage($image, (New-Object System.Drawing.Rectangle 0, 0, $size, $size), $from, [System.Drawing.GraphicsUnit]::Pixel)
    $g.Dispose()
    return $bmp
}

$master = [System.Drawing.Bitmap]::FromFile((Resolve-Path $Source))
try {
    # Full logo.
    $full = New-Object System.Drawing.Rectangle 0, 0, $master.Width, $master.Height
    $logo = Resize $master $full 512
    $logo.Save((Join-Path $assets 'logo.png'), [System.Drawing.Imaging.ImageFormat]::Png)
    $logo.Dispose()

    # Shield: bounding box of clearly visible pixels above the wordmark (top ~74% of the image), made square.
    $limitY = [int]($master.Height * 0.74)
    $minX = $master.Width; $minY = $master.Height; $maxX = 0; $maxY = 0
    for ($y = 0; $y -lt $limitY; $y += 2) {
        for ($x = 0; $x -lt $master.Width; $x += 2) {
            if ($master.GetPixel($x, $y).A -gt 160) {
                if ($x -lt $minX) { $minX = $x }; if ($x -gt $maxX) { $maxX = $x }
                if ($y -lt $minY) { $minY = $y }; if ($y -gt $maxY) { $maxY = $y }
            }
        }
    }
    $side = [Math]::Max($maxX - $minX, $maxY - $minY) + 8
    $cx = [int](($minX + $maxX) / 2); $cy = [int](($minY + $maxY) / 2)
    $crop = New-Object System.Drawing.Rectangle ([Math]::Max(0, $cx - [int]($side / 2))), ([Math]::Max(0, $cy - [int]($side / 2))), $side, $side
    Write-Host "Shield crop: $crop"

    $shield = Resize $master $crop 256
    $shield.Save((Join-Path $assets 'shield.png'), [System.Drawing.Imaging.ImageFormat]::Png)
    $shield.Dispose()

    # Multi-size .ico with PNG-compressed entries (supported since Windows Vista).
    $sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
    $images = foreach ($s in $sizes) {
        $bmp = Resize $master $crop $s
        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
        , $ms.ToArray()
    }
    $out = New-Object System.IO.MemoryStream
    $w = New-Object System.IO.BinaryWriter $out
    $w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $dim = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
        $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
        $w.Write([UInt16]1); $w.Write([UInt16]32)
        $w.Write([UInt32]$images[$i].Length); $w.Write([UInt32]$offset)
        $offset += $images[$i].Length
    }
    foreach ($img in $images) { $w.Write($img) }
    $w.Flush()
    [System.IO.File]::WriteAllBytes((Join-Path $assets 'WinGaurdian.ico'), $out.ToArray())
    Write-Host "Assets written to $assets"
}
finally {
    $master.Dispose()
}
