using Microsoft.Win32;
using WinGuardian.Core.Tasks;

namespace WinGuardian.Tests;

public class ComResolverTests
{
    private static readonly string Shell32 = TestEnv.System32("shell32.dll");

    [Fact]
    public void Resolves_real_RefreshCache_class_to_wosc_dll()
    {
        var r = ComResolver.Resolve("{E07647F7-AED2-48D9-9720-939BC24A8A3C}");
        if (!r.Resolved) Assert.Skip("Class not registered on this machine.");
        Assert.Equal("InprocServer32", r.Server!.RegistrationType);
        Assert.Equal("64-bit", r.RegistryView);
        Assert.Equal(TestEnv.System32("wosc.dll"), r.Server.ServerPath, ignoreCase: true);
        Assert.Equal("Both", r.Server.ThreadingModel);
    }

    [Fact]
    public void Missing_registration_is_unresolved_not_an_error()
    {
        var r = ComResolver.Resolve(TestEnv.NewClsid());
        Assert.False(r.Resolved);
        Assert.Equal("class is not registered", r.Error);
    }

    [Fact]
    public void Invalid_class_id_is_reported()
    {
        Assert.Equal("not a valid class ID", ComResolver.Resolve("not-a-guid").Error);
    }

    [Fact]
    public void Resolves_64_bit_inproc_registration_with_environment_variables()
    {
        TestEnv.RequireElevation();
        using var com = new TestComClass().MachineInproc(@"%SystemRoot%\System32\shell32.dll");
        var r = ComResolver.Resolve(com.Clsid);
        Assert.True(r.Resolved);
        Assert.Equal("64-bit", r.RegistryView);
        Assert.Equal(Shell32, r.Server!.ServerPath, ignoreCase: true);
        Assert.Equal(@"%SystemRoot%\System32\shell32.dll", r.Server.RawValue);
    }

    [Fact]
    public void Falls_back_to_32_bit_registration()
    {
        TestEnv.RequireElevation();
        using var com = new TestComClass().MachineInproc(@"C:\Windows\SysWOW64\shell32.dll", RegistryView.Registry32);
        var r = ComResolver.Resolve(com.Clsid);
        Assert.True(r.Resolved);
        Assert.Equal("32-bit", r.RegistryView);
        Assert.Contains("WOW6432Node", r.RegistryLocation);
    }

    [Fact]
    public void Resolves_local_server_executable()
    {
        TestEnv.RequireElevation();
        using var com = new TestComClass().MachineLocalServer($"\"{TestEnv.System32("notepad.exe")}\" /embedding");
        var r = ComResolver.Resolve(com.Clsid);
        Assert.Equal("LocalServer32", r.Server!.RegistrationType);
        Assert.Equal(TestEnv.System32("notepad.exe"), r.Server.ServerPath, ignoreCase: true);
    }

    [Fact]
    public void Follows_TreatAs_redirection()
    {
        TestEnv.RequireElevation();
        using var target = new TestComClass().MachineInproc(Shell32);
        using var source = new TestComClass().MachineInproc("", treatAs: target.Clsid);
        var r = ComResolver.Resolve(source.Clsid);
        Assert.True(r.Resolved);
        Assert.Equal([source.Clsid, target.Clsid], r.TreatAsChain);
        Assert.Equal(Shell32, r.Server!.ServerPath, ignoreCase: true);
    }

    [Fact]
    public void Detects_TreatAs_cycles()
    {
        TestEnv.RequireElevation();
        var a = TestEnv.NewClsid();
        var b = TestEnv.NewClsid();
        using var ca = new TestComClass().MachineInproc("", clsid: a, treatAs: b);
        using var cb = new TestComClass().MachineInproc("", clsid: b, treatAs: a);
        var r = ComResolver.Resolve(a);
        Assert.False(r.Resolved);
        Assert.Contains("cycle", r.Error);
    }

    [Fact]
    public void Reports_per_user_override_without_machine_registration()
    {
        using var com = new TestComClass().UserInproc(@"C:\Users\Public\evil.dll");
        var r = ComResolver.Resolve(com.Clsid, [TestEnv.CurrentUserSid]);
        Assert.False(r.Resolved); // nothing machine-wide...
        var o = Assert.Single(r.UserOverrides); // ...but the user's registration supplies the class
        Assert.Equal(@"C:\Users\Public\evil.dll", o.Server!.ServerPath);
        Assert.Equal(TestEnv.CurrentUserSid, o.Sid);
    }

    [Fact]
    public void Per_user_override_shadows_machine_registration()
    {
        TestEnv.RequireElevation();
        using var com = new TestComClass().MachineInproc(Shell32).UserInproc(@"C:\Users\Public\evil.dll");
        var r = ComResolver.Resolve(com.Clsid, [TestEnv.CurrentUserSid]);
        Assert.True(r.Resolved);
        Assert.Equal(Shell32, r.Server!.ServerPath, ignoreCase: true);
        Assert.Single(r.UserOverrides);
        // Without the user's SID in scope, the override is not considered.
        Assert.Empty(ComResolver.Resolve(com.Clsid).UserOverrides);
    }

    [Fact]
    public void Redirection_to_another_dll_is_a_change()
    {
        TestEnv.RequireElevation();
        using var com = new TestComClass().MachineInproc(Shell32);
        var loaded = new HashSet<string> { "S-1-5-18" };
        var before = ComResolver.Resolve(com.Clsid);
        Assert.False(TaskComparer.ComChanged(before, ComResolver.Resolve(com.Clsid), loaded)); // stable when nothing changed

        com.SetMachineServer(@"C:\Users\Public\malicious.dll");
        Assert.True(TaskComparer.ComChanged(before, ComResolver.Resolve(com.Clsid), loaded));
    }
}
