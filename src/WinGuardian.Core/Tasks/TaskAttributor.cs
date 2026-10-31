using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Core.Tasks;

public interface ITaskAttributor
{
    ProcessAttribution Attribute(string taskPath, string change, DateTime changeUtc);
}

/// <summary>Used when attribution is not wanted (e.g. tests).</summary>
public sealed class NullTaskAttributor : ITaskAttributor
{
    public ProcessAttribution Attribute(string taskPath, string change, DateTime changeUtc) =>
        new() { Note = "Attribution not available." };
}

/// <summary>
/// Finds out who changed a task. The task file is always written by the Task Scheduler service itself, so
/// the file change cannot reveal the requester. Windows records the requester in Security events 4698-4702
/// (when "Other Object Access" auditing is on, including the client process ID); without auditing, the
/// Task Scheduler operational log may still name the user. Nothing is guessed: if neither source has a
/// matching record, the result is "Unknown".
/// </summary>
public sealed class TaskAttributor(ProcessHistory history, ILogger<TaskAttributor> logger) : ITaskAttributor
{
    private static readonly TimeSpan Before = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan After = TimeSpan.FromMinutes(1);

    public ProcessAttribution Attribute(string taskPath, string change, DateTime changeUtc)
    {
        // The audit record can land a moment after the file change.
        for (var attempt = 0; attempt < 2; attempt++)
        {
            if (FromSecurityLog(taskPath, changeUtc) is { } fromSecurity) return fromSecurity;
            if (attempt == 0) Thread.Sleep(2000);
        }
        if (FromOperationalLog(taskPath, changeUtc) is { } fromOperational) return fromOperational;

        return new ProcessAttribution
        {
            Available = false,
            Note = TaskAuditing.IsEnabled() == true
                ? "Unknown: no matching audit record was found."
                : "Unknown: turn on \"Record which process changes scheduled tasks\" in Settings to capture this.",
        };
    }

    private ProcessAttribution? FromSecurityLog(string taskPath, DateTime changeUtc)
    {
        var match = Query("Security", "EventID=4698 or EventID=4699 or EventID=4700 or EventID=4701 or EventID=4702", taskPath, changeUtc);
        if (match is null) return null;
        var record = match.Value; var data = record.Data;

        var result = new ProcessAttribution
        {
            Available = true,
            Source = $"Security event {record.Id}",
            User = Join(data.GetValueOrDefault("SubjectDomainName"), data.GetValueOrDefault("SubjectUserName")),
        };

        if (int.TryParse(data.GetValueOrDefault("ClientProcessId"), out var pid) && pid > 0)
        {
            result.ProcessId = pid;
            if (int.TryParse(data.GetValueOrDefault("ParentProcessId"), out var ppid) && ppid > 0) result.ParentProcessId = ppid;
            DescribeProcess(result, pid, record.TimeUtc);
        }
        else
        {
            result.Note = "This Windows version does not record the client process in the audit event.";
        }
        return result;
    }

    private ProcessAttribution? FromOperationalLog(string taskPath, DateTime changeUtc)
    {
        var match = Query("Microsoft-Windows-TaskScheduler/Operational", "EventID=106 or EventID=140 or EventID=141", taskPath, changeUtc);
        if (match is null) return null;
        var record = match.Value; var data = record.Data;
        return new ProcessAttribution
        {
            Available = true,
            Source = $"Task Scheduler event {record.Id}",
            User = data.GetValueOrDefault("UserContext") ?? data.GetValueOrDefault("UserName"),
            Note = "The Task Scheduler log names the user but not the process.",
        };
    }

    private (int Id, DateTime TimeUtc, Dictionary<string, string> Data)? Query(string log, string ids, string taskPath, DateTime changeUtc)
    {
        try
        {
            var query = new EventLogQuery(log, PathType.LogName,
                $"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {(long)(DateTime.UtcNow - changeUtc + Before).TotalMilliseconds}]]]")
            {
                ReverseDirection = true,
            };
            using var reader = new EventLogReader(query);
            for (var i = 0; i < 500 && reader.ReadEvent() is { } record; i++)
            {
                using (record)
                {
                    var time = record.TimeCreated?.ToUniversalTime();
                    if (time is null || time < changeUtc - Before || time > changeUtc + After) continue;
                    var data = EventData(record);
                    if (string.Equals(data.GetValueOrDefault("TaskName"), taskPath, StringComparison.OrdinalIgnoreCase))
                        return (record.Id, time.Value, data); // copied out: the record is disposed on return
                }
            }
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException)
        {
            logger.LogDebug("Cannot read {Log}: {Message}", log, ex.Message);
        }
        return null;
    }

    private void DescribeProcess(ProcessAttribution result, int pid, DateTime atUtc)
    {
        if (history.Find(pid, atUtc) is { } started)
        {
            result.ProcessPath = started.ImagePath;
            result.CommandLine = started.CommandLine;
            result.ParentProcessId ??= started.ParentPid;
            result.ProcessStartUtc = started.StartUtc;
        }
        else
        {
            // Still running and started before the change (so the PID was not reused)?
            try
            {
                using var p = Process.GetProcessById(pid);
                var start = p.StartTime.ToUniversalTime();
                if (start <= atUtc)
                {
                    result.ProcessPath = NativeMethods.TryGetProcessImagePath(pid);
                    result.ProcessStartUtc = start;
                }
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
            }
            if (result.ProcessPath is null)
                result.Note = "The process has exited and was not seen starting, so its path is unknown.";
        }

        if (result.ProcessPath is not null && File.Exists(result.ProcessPath))
            result.ProcessSigner = SignatureVerifier.Verify(result.ProcessPath).Describe();
    }

    private static Dictionary<string, string> EventData(EventRecord record)
    {
        var xml = XDocument.Parse(record.ToXml());
        return xml.Descendants()
            .Where(e => e.Name.LocalName == "Data" && e.Attribute("Name") is not null)
            .GroupBy(e => e.Attribute("Name")!.Value)
            .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
    }

    private static string? Join(string? domain, string? user) =>
        user is null ? null : string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
}
