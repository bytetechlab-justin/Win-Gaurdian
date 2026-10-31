using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using WinGuardian.Core.Ipc;

namespace WinGuardian.Core.Network;

/// <summary>
/// Reads Windows Defender Firewall state straight from its registry store: per-profile on/off and default
/// actions (local settings, overridden by Group Policy when present), and every firewall rule (local and
/// Group Policy). Rule strings look like "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|App=...|".
/// </summary>
public static class FirewallConfig
{
    private const string PolicyKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    private const string GroupPolicyKey = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";

    private static readonly (string Name, string LocalKey, string PolicyKey)[] ProfileKeys =
    [
        ("Domain", "DomainProfile", "DomainProfile"),
        ("Private", "StandardProfile", "PrivateProfile"),
        ("Public", "PublicProfile", "PublicProfile"),
    ];

    private static readonly ConcurrentDictionary<string, string> IndirectStrings = new();

    public static FirewallStatus ReadStatus(IReadOnlyCollection<FirewallRule> rules)
    {
        var status = new FirewallStatus
        {
            ServiceRunning = ServiceInfo.GetState("mpssvc") == ServiceInfo.State.Running,
            RuleCount = rules.Count,
            InboundAllowRuleCount = rules.Count(r => r.AllowsInbound),
        };
        foreach (var (name, local, policy) in ProfileKeys)
        {
            using var localKey = Registry.LocalMachine.OpenSubKey($@"{PolicyKey}\{local}");
            using var gpKey = Registry.LocalMachine.OpenSubKey($@"{GroupPolicyKey}\{policy}");
            int? Read(string value) => gpKey?.GetValue(value) as int? ?? localKey?.GetValue(value) as int?;

            status.Profiles.Add(new FirewallProfileState
            {
                Name = name,
                Enabled = (Read("EnableFirewall") ?? 1) != 0,
                SetByGroupPolicy = gpKey?.GetValue("EnableFirewall") is not null,
                DefaultInbound = (Read("DefaultInboundAction") ?? 1) == 0 ? "Allow" : "Block",
                DefaultOutbound = (Read("DefaultOutboundAction") ?? 0) == 1 ? "Block" : "Allow",
            });
        }
        return status;
    }

    public static List<FirewallRule> ReadRules()
    {
        var rules = new List<FirewallRule>();
        ReadRules(Registry.LocalMachine, $@"{PolicyKey}\FirewallRules", "Local", rules);
        ReadRules(Registry.LocalMachine, $@"{GroupPolicyKey}\FirewallRules", "Group Policy", rules);
        return rules;
    }

    private static void ReadRules(RegistryKey hive, string path, string source, List<FirewallRule> rules)
    {
        using var key = hive.OpenSubKey(path);
        if (key is null) return;
        foreach (var id in key.GetValueNames())
        {
            if (key.GetValue(id) is string raw)
                rules.Add(Parse(id, source, raw));
        }
    }

    /// <summary>Parses one rule string. Unknown fields are kept in <see cref="FirewallRule.Raw"/>.</summary>
    public static FirewallRule Parse(string id, string source, string raw)
    {
        var fields = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in raw.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var name = part[..eq];
            if (!fields.TryGetValue(name, out var list)) fields[name] = list = [];
            list.Add(part[(eq + 1)..]);
        }
        string? One(string name) => fields.TryGetValue(name, out var v) ? v[0] : null;
        string? All(string name) => fields.TryGetValue(name, out var v) ? string.Join(",", v) : null;
        string? AllOf(params string[] names)
        {
            var values = names.Where(fields.ContainsKey).SelectMany(n => fields[n]).ToList();
            return values.Count == 0 ? null : string.Join(",", values);
        }

        return new FirewallRule
        {
            Id = id,
            Source = source,
            Raw = raw,
            Name = Resolve(One("Name")) ?? id,
            Description = Resolve(One("Desc")),
            Direction = One("Dir") ?? "",
            Action = One("Action") ?? "",
            Enabled = string.Equals(One("Active"), "TRUE", StringComparison.OrdinalIgnoreCase),
            Protocol = ProtocolName(One("Protocol")),
            LocalPorts = All("LPort") ?? All("LPort2_10"),
            RemotePorts = All("RPort") ?? All("RPort2_10"),
            RemoteAddresses = AllOf("RA4", "RA6", "RA42", "RA62"),
            Program = One("App") is { } app ? Environment.ExpandEnvironmentVariables(app) : null,
            Service = One("Svc"),
            Package = One("PCross") ?? One("AppPkgId"),
            Profiles = All("Profile") ?? "All",
        };
    }

    public static string ProtocolName(string? number) => number switch
    {
        null => "Any",
        "6" => "TCP",
        "17" => "UDP",
        "1" => "ICMPv4",
        "58" => "ICMPv6",
        "2" => "IGMP",
        "47" => "GRE",
        _ => number,
    };

    /// <summary>Turns "@FirewallAPI.dll,-28502" / "@{Package?ms-resource://...}" into readable text.</summary>
    private static string? Resolve(string? value)
    {
        if (value is null || !value.StartsWith('@')) return value;
        return IndirectStrings.GetOrAdd(value, v =>
        {
            var buffer = new StringBuilder(1024);
            if (SHLoadIndirectString(v, buffer, buffer.Capacity, IntPtr.Zero) == 0 && buffer.Length > 0) return buffer.ToString();

            // Store-app resources only resolve for users who have the app installed (not SYSTEM):
            // "@{Microsoft.BingWeather_4.54..._x64__8wekyb3d8bbwe?ms-resource://...}" -> "Microsoft.BingWeather (Store app)".
            if (v.StartsWith("@{", StringComparison.Ordinal))
            {
                var package = v[2..].Split('?', '}')[0];
                var name = package.Split('_')[0];
                if (name.Length > 0) return $"{name} (Store app)";
            }
            return v;
        });
    }

    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
    private static extern int SHLoadIndirectString(string source, StringBuilder output, int outputSize, IntPtr reserved);
}
