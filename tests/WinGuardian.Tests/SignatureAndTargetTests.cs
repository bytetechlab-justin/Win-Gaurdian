using WinGuardian.Core.Monitoring;
using WinGuardian.Core.Tasks;

namespace WinGuardian.Tests;

public class SignatureAndTargetTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "wg-tests", Guid.NewGuid().ToString("N"));

    public SignatureAndTargetTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }

    [Fact]
    public void Catalog_signed_windows_binary_is_valid_microsoft()
    {
        var t = TargetInspector.Inspect(TestEnv.System32("notepad.exe"));
        Assert.True(t.File.Exists);
        Assert.Equal(nameof(SignatureStatus.Valid), t.SignatureStatus);
        Assert.True(t.SignedByMicrosoft);
        Assert.NotNull(t.File.Sha256);
        Assert.Empty(t.WritableBy); // ordinary users cannot modify System32 binaries
    }

    [Fact]
    public void Embedded_signature_is_valid()
    {
        var r = SignatureVerifier.Verify(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"));
        Assert.Equal(SignatureStatus.Valid, r.Status);
        Assert.True(r.IsMicrosoft);
    }

    [Fact]
    public void Unsigned_file_is_reported_unsigned()
    {
        var path = Path.Combine(_dir, "unsigned.exe");
        File.WriteAllBytes(path, [0x4D, 0x5A, 1, 2, 3]);
        var t = TargetInspector.Inspect(path);
        Assert.Equal(nameof(SignatureStatus.Unsigned), t.SignatureStatus);
        Assert.False(t.SignedByMicrosoft);
        Assert.True(t.InUserWritableLocation);
    }

    [Fact]
    public void Modified_signed_file_is_reported_tampered()
    {
        var original = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        var bytes = File.ReadAllBytes(original);
        bytes[bytes.Length / 3] ^= 0xFF;
        var path = Path.Combine(_dir, "tampered.exe");
        File.WriteAllBytes(path, bytes);
        Assert.Equal(nameof(SignatureStatus.Tampered), TargetInspector.Inspect(path).SignatureStatus);
    }

    [Fact]
    public void Missing_file_reports_who_could_plant_it()
    {
        var t = TargetInspector.Inspect(Path.Combine(_dir, "not-there.exe"));
        Assert.False(t.File.Exists);
        Assert.Null(t.SignatureStatus); // never claim a signature result for a file that is not there
        Assert.NotEmpty(t.DirectoryWritableBy); // the test user owns its temp folder
    }

    [Fact]
    public void File_changing_during_read_is_detected_by_timestamp()
    {
        var path = Path.Combine(_dir, "a.bin");
        File.WriteAllText(path, "one");
        var state = TargetInspector.ReadFileState(path);
        Assert.False(TargetInspector.LooksChanged(state));
        File.WriteAllText(path, "two two");
        Assert.True(TargetInspector.LooksChanged(state));
    }
}
