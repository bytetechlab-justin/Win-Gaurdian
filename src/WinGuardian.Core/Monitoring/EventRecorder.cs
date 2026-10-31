using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using WinGuardian.Core.Data;

namespace WinGuardian.Core.Monitoring;

/// <summary>
/// Persists events and mirrors them to the log (Windows Event Log when running as a service).
/// Events for trusted items are dropped here, in one place, so every monitor honours the trust list.
/// </summary>
public sealed class EventRecorder(GuardianDatabase db, TrustStore trust, ILogger<EventRecorder> logger)
{
    /// <summary>Raised after an event is stored (e.g. to queue a reputation lookup). Handlers must not block.</summary>
    public event Action<GuardianEvent>? Recorded;

    public bool Record(GuardianEvent e)
    {
        using var c = db.Open();
        return Record(c, null, e);
    }

    /// <summary>Records inside an existing connection/transaction (required while a scan holds the write lock).</summary>
    /// <returns>False if the event was suppressed by the trust list.</returns>
    public bool Record(SqliteConnection c, SqliteTransaction? tx, GuardianEvent e)
    {
        if (trust.Suppresses(e)) return false;

        db.InsertEvent(c, tx, e);
        var level = e.Severity >= Severity.Medium ? LogLevel.Warning : LogLevel.Information;
        logger.Log(level, "[{Severity}] {Category} {Change}: {Subject} {Details}",
            e.Severity, e.Category, e.Change, e.Subject, e.Details);

        try
        {
            Recorded?.Invoke(e);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Event subscriber failed");
        }
        return true;
    }

    public void Info(string subject, string? details = null) => Record(new GuardianEvent
    {
        Severity = Severity.Info,
        Category = EventCategory.System,
        Change = ChangeKind.Info,
        Subject = subject,
        Details = details,
    });
}
