using System.Security.Principal;
using Microsoft.Win32;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Core.Tasks;

/// <summary>
/// Resolves a COM class ID to the code Windows would load, reading the registry directly (never
/// instantiating the class). Checks the 64-bit and 32-bit (WOW6432Node) machine registrations, follows
/// TreatAs redirections with cycle detection, reads AppID settings (LocalService, DllSurrogate, RunAs),
/// and reports per-user registrations that shadow the machine-wide one (a common hijacking technique).
/// </summary>
public static class ComResolver
{
    private const int MaxTreatAsDepth = 8;
    private static readonly string System32 = Path.Combine(GuardianPaths.Normalize("%WINDIR%"), "System32");

    public static ComResolution Resolve(string classId, IEnumerable<string>? userSids = null)
    {
        var clsid = TaskDefinitionParser.NormalizeClsid(classId) ?? classId;
        var result = new ComResolution { ClassId = clsid };

        if (!Guid.TryParse(clsid, out _))
        {
            result.Error = "not a valid class ID";
            return result;
        }

        try
        {
            ResolveChain(result, clsid, OpenMachineClass);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            result.Error = $"registry not readable: {ex.Message}";
        }

        foreach (var sid in userSids ?? [])
        {
            try
            {
                var shadow = new ComResolution { ClassId = clsid };
                if (!ResolveChain(shadow, clsid, c => OpenUserClass(sid, c), userScope: true) && shadow.RegistryLocation is null)
                    continue; // no per-user registration for this class
                result.UserOverrides.Add(new UserComOverride
                {
                    Sid = sid,
                    Account = AccountName(sid),
                    RegistryLocation = shadow.RegistryLocation ?? "",
                    Server = shadow.Server,
                });
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                // A hive we cannot read is treated as having no override.
            }
        }
        return result;
    }

    private delegate (RegistryKey? Key, string Location, string View) ClassOpener(string clsid);

    /// <returns>True if a server registration was found.</returns>
    private static bool ResolveChain(ComResolution result, string clsid, ClassOpener open, bool userScope = false)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var current = clsid;

        for (var depth = 0; depth < MaxTreatAsDepth; depth++)
        {
            if (!visited.Add(current))
            {
                result.Error = $"TreatAs cycle at {current}";
                return false;
            }
            result.TreatAsChain.Add(current);

            var (key, location, view) = open(current);
            if (key is null)
            {
                result.Error = depth == 0 ? "class is not registered" : $"TreatAs target {current} is not registered";
                return false;
            }

            using (key)
            {
                result.RegistryLocation = location;
                result.RegistryView = view;

                using (var treatAs = key.OpenSubKey("TreatAs"))
                {
                    if (treatAs?.GetValue("") is string target && TaskDefinitionParser.NormalizeClsid(target) is { } next &&
                        Guid.TryParse(next, out _) && !next.Equals(current, StringComparison.OrdinalIgnoreCase))
                    {
                        current = next;
                        continue;
                    }
                }

                result.ClassName = key.GetValue("") as string;
                result.AppId = TaskDefinitionParser.NormalizeClsid(key.GetValue("AppID") as string);
                result.Server = ReadServer(key, "InprocServer32") ?? ReadServer(key, "LocalServer32");

                if (result.AppId is not null && !userScope)
                    ReadAppId(result, view);

                if (result.Server is null && result.AppIdLocalService is not null)
                {
                    result.Server = new ComServer
                    {
                        RegistrationType = "LocalService",
                        RawValue = result.AppIdLocalService,
                        ServerPath = ServiceBinary(result.AppIdLocalService),
                    };
                }

                result.Resolved = result.Server is not null;
                if (!result.Resolved) result.Error = "no InprocServer32, LocalServer32 or LocalService registration";
                return result.Resolved;
            }
        }

        result.Error = "TreatAs chain too long";
        return false;
    }

    private static (RegistryKey?, string, string) OpenMachineClass(string clsid)
    {
        using (var hklm64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        {
            var key = hklm64.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}");
            if (key is not null) return (key, $@"HKLM\SOFTWARE\Classes\CLSID\{clsid}", "64-bit");
        }
        using (var hklm32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
        {
            var key = hklm32.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}");
            if (key is not null) return (key, $@"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{clsid}", "32-bit");
        }
        return (null, "", "");
    }

    /// <summary>A user's classes live in HKU\{sid}_Classes (= HKCU\Software\Classes for that user).</summary>
    private static (RegistryKey?, string, string) OpenUserClass(string sid, string clsid)
    {
        foreach (var path in new[] { $@"{sid}_Classes\CLSID\{clsid}", $@"{sid}\Software\Classes\CLSID\{clsid}" })
        {
            var key = Registry.Users.OpenSubKey(path);
            if (key is not null) return (key, $@"HKU\{path}", "per-user");
        }
        return (null, "", "");
    }

    private static ComServer? ReadServer(RegistryKey classKey, string subKey)
    {
        using var key = classKey.OpenSubKey(subKey);
        if (key?.GetValue("", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string raw || raw.Trim().Length == 0)
            return null;

        var server = new ComServer
        {
            RegistrationType = subKey,
            RawValue = raw,
            ThreadingModel = key.GetValue("ThreadingModel") as string,
        };

        var expanded = Environment.ExpandEnvironmentVariables(raw.Trim());
        server.ServerPath = subKey == "InprocServer32"
            ? ResolveDll(expanded)
            : PathResolver.ExtractExecutablePath(expanded) ?? PathResolver.FirstTokenPath(expanded);

        // .NET classes are hosted by mscoree.dll; the assembly named by CodeBase/Assembly is what runs.
        if (Path.GetFileName(server.ServerPath ?? "").Equals("mscoree.dll", StringComparison.OrdinalIgnoreCase))
        {
            if (key.GetValue("CodeBase") is string codeBase && Uri.TryCreate(codeBase, UriKind.Absolute, out var uri) && uri.IsFile)
                server.ManagedAssembly = uri.LocalPath;
            else
                server.ManagedAssembly = key.GetValue("Assembly") as string;
        }
        return server;
    }

    private static string ResolveDll(string value)
    {
        var path = value.Trim().Trim('"');
        if (Path.IsPathRooted(path)) return path;
        // Bare DLL names are found through the normal search order; System32 is where Windows' own live.
        var inSystem32 = Path.Combine(System32, path);
        return File.Exists(inSystem32) ? inSystem32 : path;
    }

    private static void ReadAppId(ComResolution result, string view)
    {
        var registryView = view == "32-bit" ? RegistryView.Registry32 : RegistryView.Registry64;
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, registryView);
        using var appId = hklm.OpenSubKey($@"SOFTWARE\Classes\AppID\{result.AppId}");
        if (appId is null) return;
        result.AppIdLocalService = appId.GetValue("LocalService") as string;
        result.AppIdDllSurrogate = appId.GetValue("DllSurrogate") as string;
        result.AppIdRunAs = appId.GetValue("RunAs") as string;
    }

    private static string? ServiceBinary(string serviceName)
    {
        using var svc = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
        if (svc is null) return null;
        using var parameters = svc.OpenSubKey("Parameters");
        var dll = parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        var image = svc.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        return PathResolver.ExtractExecutablePath(dll) ?? PathResolver.ExtractExecutablePath(image);
    }

    private static string AccountName(string sid)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        }
        catch
        {
            return sid;
        }
    }
}
