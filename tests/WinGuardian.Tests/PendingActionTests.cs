using Microsoft.Extensions.Logging.Abstractions;
using WinGuardian.Core;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Tests;

/// <summary>The "ask before acting on a file" recommendation must survive storage, since the tray reads it back from the database.</summary>
public class PendingActionTests : IDisposable
{
    private readonly string _work = Path.Combine(Path.GetTempPath(), "wg-tests", Guid.NewGuid().ToString("N"));
    private readonly GuardianDatabase _db;
    private readonly EventRecorder _events;

    public PendingActionTests()
    {
        Directory.CreateDirectory(_work);
        _db = new GuardianDatabase(Path.Combine(_work, "pending.db"));
        _db.Initialize();
        _events = new EventRecorder(_db, new TrustStore(_db), NullLogger<EventRecorder>.Instance);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_work, true); } catch (IOException) { }
    }

    [Fact]
    public void Pending_action_round_trips_through_the_database()
    {
        _events.Record(new GuardianEvent
        {
            Severity = Severity.High, Category = EventCategory.Malware, Change = ChangeKind.Detected,
            Subject = "Known malware: C:\\x\\evil.exe", FilePath = @"C:\x\evil.exe", PendingAction = PendingActions.Quarantine,
        });
        _events.Info("Nothing to decide");

        var events = _db.GetEvents(null, 10, unacknowledgedOnly: true);
        Assert.Equal(PendingActions.Quarantine, Assert.Single(events, e => e.Category == EventCategory.Malware).PendingAction);
        Assert.Null(Assert.Single(events, e => e.Category == EventCategory.System).PendingAction);
    }

    [Fact]
    public void Older_databases_gain_the_pending_action_column()
    {
        // Initialize twice: the second run must find the column already there and not fail.
        _db.Initialize();
        _events.Info("still works");
        Assert.Single(_db.GetEvents(null, 10, false));
    }
}
