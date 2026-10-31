using System.Text.RegularExpressions;
using WinGuardian.Core;
using WinGuardian.Core.Analysis;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Tests;

public class FileInspectorTests : IDisposable
{
    private readonly string _work = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "wg-tests", Guid.NewGuid().ToString("N"))).FullName;

    public void Dispose()
    {
        try { Directory.Delete(_work, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string Write(string name, byte[] content)
    {
        var path = Path.Combine(_work, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    private static readonly byte[] FakeProgram = [(byte)'M', (byte)'Z', 0x90, 0, 3, 0, 0, 0, 4, 0];

    [Fact]
    public void ProgramDisguisedAsDocument_IsHigh()
    {
        var inspection = FileInspector.Inspect(Write("invoice.pdf", FakeProgram));
        Assert.True(inspection.IsProgram);
        Assert.Equal(Severity.High, inspection.Severity);
        Assert.Contains(inspection.Notes, n => n.Text.Contains("disguised"));
    }

    [Fact]
    public void DoubleExtension_IsHigh()
    {
        var inspection = FileInspector.Inspect(Write("photo.jpg.exe", FakeProgram));
        Assert.Contains(inspection.Notes, n => n.Severity == Severity.High && n.Text.Contains("Double extension"));
    }

    [Fact]
    public void RightToLeftOverrideInName_IsHigh()
    {
        var inspection = FileInspector.Inspect(Write("report\u202Efdp.exe", FakeProgram));
        Assert.Contains(inspection.Notes, n => n.Severity == Severity.High && n.Text.Contains("right-to-left"));
    }

    [Fact]
    public void PlainDocument_HasNoFindingsAndCorrectHash()
    {
        var content = "%PDF-1.7 hello"u8.ToArray();
        var inspection = FileInspector.Inspect(Write("letter.pdf", content));
        Assert.Equal(Severity.Info, inspection.Severity);
        Assert.Equal("PDF document", inspection.ContentType);
        Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content)), inspection.Sha256, ignoreCase: true);
        Assert.Null(inspection.Signature);
    }

    [Fact]
    public void UnsignedProgram_IsNoted()
    {
        var inspection = FileInspector.Inspect(Write("tool.exe", FakeProgram));
        Assert.Equal(SignatureStatus.Unsigned, inspection.Signature?.Status);
        Assert.Contains(inspection.Notes, n => n.Text.Contains("not digitally signed"));
    }

    [Fact]
    public void MarkOfTheWeb_IsReadFromTheZoneIdentifierStream()
    {
        var path = Write("setup.exe", FakeProgram);
        File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/\r\nHostUrl=https://example.com/setup.exe\r\n");
        var inspection = FileInspector.Inspect(path);
        Assert.Equal(3, inspection.Zone);
        Assert.Equal("https://example.com/setup.exe", inspection.DownloadedFrom);
        Assert.Contains(inspection.Notes, n => n.Text.Contains("Downloaded from the internet: https://example.com/setup.exe"));
    }

    [Fact]
    public void MissingFile_Throws() =>
        Assert.Throws<FileNotFoundException>(() => FileInspector.Inspect(Path.Combine(_work, "nope.exe")));

    [Fact]
    public void InstallScript_RegistersRunThroughWgForEverySupportedType()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "WinGuardian.slnx"))) root = Path.GetDirectoryName(root)!;
        foreach (var script in new[] { "install.ps1", "uninstall.ps1" })
        {
            var text = File.ReadAllText(Path.Combine(root, "scripts", script));
            var listed = Regex.Matches(text, @"'(\.[a-z0-9]+)'").Select(m => m.Groups[1].Value).ToHashSet();
            Assert.Equal(SuspendedLauncher.SupportedExtensions.ToHashSet(), listed);
        }
        foreach (var ext in SuspendedLauncher.SupportedExtensions)
            SuspendedLauncher.BuildCommand(@"C:\x\file" + ext, ""); // throws if a listed type can't actually be started
    }
}
