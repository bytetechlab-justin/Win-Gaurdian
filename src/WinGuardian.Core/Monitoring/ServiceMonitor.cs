using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WinGuardian.Core.Data;

namespace WinGuardian.Core.Monitoring;

/// <summary>
/// Snapshots every service and driver registered under HKLM\SYSTEM\CurrentControlSet\Services and
/// reports additions, removals, and changes to how they launch (image path, ServiceDll, start type, account).
/// </summary>
public sealed class ServiceMonitor(GuardianDatabase db, EventRecorder events, ILogger<ServiceMonitor> logger)
{
    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";
    private const int UserServiceInstance = 0x80;

    public List<ServiceRecord> Capture()
    {
        var result = new List<ServiceRecord>();
        using var root = Registry.LocalMachine.OpenSubKey(ServicesKey);
        if (root is null) return result;

        foreach (var name in root.GetSubKeyNames())
        {
            try
            {
                using var key = root.OpenSubKey(name);
                // Keys without a Type value are parameter containers, not services.
                if (key?.GetValue("Type") is not int type) continue;
                // Per-user instances (e.g. CDPUserSvc_1a2b3c) are created at every logon; their template is tracked instead.
                if ((type & UserServiceInstance) != 0) continue;

                string? serviceDll;
                using (var parameters = key.OpenSubKey("Parameters"))
                    serviceDll = parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;

                result.Add(new ServiceRecord(
                    name,
                    key.GetValue("DisplayName") as string,
                    key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string,
                    serviceDll,
                    type,
                    key.GetValue("Start") as int? ?? -1,
                    key.GetValue("ObjectName") as string));
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                logger.LogDebug("Cannot read service key {Name}: {Message}", name, ex.Message);
            }
        }
        return result;
    }

    public int CaptureBaseline()
    {
        var current = Capture();
        using var c = db.Open();
        using var tx = c.BeginTransaction();
        db.ReplaceServices(c, tx, current);
        tx.Commit();
        logger.LogInformation("Service baseline captured: {Count} services/drivers", current.Count);
        return current.Count;
    }

    public void Poll()
    {
        var current = Capture();
        var stored = db.GetServices();
        var changes = new List<GuardianEvent>();

        foreach (var svc in current)
        {
            if (!stored.Remove(svc.Name, out var old))
            {
                changes.Add(ServiceEvent(svc, ChangeKind.Added, Severity.High, Describe(svc)));
                continue;
            }

            var diffs = Diff(old, svc);
            if (diffs.Count > 0)
            {
                var launchChanged = old.ImagePath != svc.ImagePath || old.ServiceDll != svc.ServiceDll || old.ObjectName != svc.ObjectName;
                changes.Add(ServiceEvent(svc, ChangeKind.Modified, launchChanged ? Severity.High : Severity.Medium,
                    string.Join("; ", diffs)));
            }
        }

        // Whatever is left in "stored" no longer exists.
        foreach (var gone in stored.Values)
            changes.Add(ServiceEvent(gone, ChangeKind.Removed, Severity.Medium, Describe(gone)));

        if (changes.Count == 0) return;

        using var c = db.Open();
        using var tx = c.BeginTransaction();
        foreach (var e in changes) events.Record(c, tx, e);
        db.ReplaceServices(c, tx, current);
        tx.Commit();
    }

    private static List<string> Diff(ServiceRecord a, ServiceRecord b)
    {
        var diffs = new List<string>();
        if (a.ImagePath != b.ImagePath) diffs.Add($"ImagePath '{a.ImagePath}' -> '{b.ImagePath}'");
        if (a.ServiceDll != b.ServiceDll) diffs.Add($"ServiceDll '{a.ServiceDll}' -> '{b.ServiceDll}'");
        if (a.ObjectName != b.ObjectName) diffs.Add($"Account '{a.ObjectName}' -> '{b.ObjectName}'");
        if (a.Start != b.Start) diffs.Add($"Start {ServiceRecord.StartName(a.Start)} -> {ServiceRecord.StartName(b.Start)}");
        if (a.Type != b.Type) diffs.Add($"Type 0x{a.Type:X} -> 0x{b.Type:X}");
        return diffs;
    }

    private static string Describe(ServiceRecord s) =>
        $"{(s.IsDriver ? "Driver" : "Service")} '{s.DisplayName ?? s.Name}'; Start {ServiceRecord.StartName(s.Start)}; " +
        $"ImagePath '{s.ImagePath}'" + (s.ServiceDll is null ? "" : $"; ServiceDll '{s.ServiceDll}'") +
        (s.ObjectName is null ? "" : $"; Account '{s.ObjectName}'");

    private static GuardianEvent ServiceEvent(ServiceRecord s, ChangeKind change, Severity severity, string details)
    {
        // For svchost-hosted services the DLL is what actually runs.
        var target = PathResolver.ExtractExecutablePath(s.ServiceDll) ?? PathResolver.ExtractExecutablePath(s.ImagePath);
        var isSelf = string.Equals(s.Name, GuardianPaths.ServiceName, StringComparison.OrdinalIgnoreCase);
        var e = new GuardianEvent
        {
            Category = isSelf ? EventCategory.Tamper : EventCategory.Service,
            Change = change,
            Subject = isSelf ? "WinGaurdian's own service configuration changed" : s.Name,
            Details = details,
            FilePath = target,
            Sha256 = change != ChangeKind.Removed && target is not null ? FileHasher.TryHash(target, 256L * 1024 * 1024) : null,
            TrustKey = s.Name,
        };
        var signature = change == ChangeKind.Removed ? null : SeverityRules.Sign(e);
        e.Severity = isSelf ? Severity.High : SeverityRules.ForLaunchTarget(severity, change, target, signature);
        if (signature is not null) e.Details += $"; target {e.Signature}";
        return e;
    }
}
