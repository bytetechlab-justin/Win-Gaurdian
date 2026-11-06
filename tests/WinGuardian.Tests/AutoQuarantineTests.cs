using Microsoft.Extensions.Logging.Abstractions;
using WinGuardian.Core;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;
using WinGuardian.Core.Reputation;

namespace WinGuardian.Tests;

/// <summary>
/// What happens to a detected file: quarantined automatically (at or above the threat level chosen in Settings),
/// or left alone with a pop-up requested. Verdicts come from the reputation cache, so no network is used.
/// </summary>
public class AutoQuarantineTests : IDisposable
{
    private readonly string _work = Path.Combine(Path.GetTempPath(), "wg-tests", Guid.NewGuid().ToString("N"));
    private readonly GuardianDatabase _db;
    private readonly GuardianState _state = new();
    private readonly QuarantineManager _quarantine;
    private readonly ReputationService _reputation;

    public AutoQuarantineTests()
    {
        Directory.CreateDirectory(_work);
        _db = new GuardianDatabase(Path.Combine(_work, "auto.db"));
        _db.Initialize();
        var trust = new TrustStore(_db);
        var events = new EventRecorder(_db, trust, NullLogger<EventRecorder>.Instance);
        _quarantine = new QuarantineManager(_db, trust, events, NullLogger<QuarantineManager>.Instance);
        _reputation = new ReputationService(_db, events, trust, _quarantine, _state, NullLogger<ReputationService>.Instance);
    }

    public void Dispose()
    {
        foreach (var item in _db.GetQuarantine()) _quarantine.Delete(item.Id);
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_work, true); } catch (IOException) { }
    }

    [Fact]
    public async Task Known_malware_is_left_alone_and_the_user_is_asked_when_auto_quarantine_is_off()
    {
        var (path, e) = await DetectAsync(ReputationVerdict.Malicious, threshold: null);

        Assert.True(File.Exists(path));
        Assert.Equal(PendingActions.Quarantine, e.PendingAction);
        Assert.Empty(_db.GetQuarantine());
    }

    [Fact]
    public async Task Suspicious_file_below_the_threshold_is_neither_quarantined_nor_prompted()
    {
        var (path, e) = await DetectAsync(ReputationVerdict.Suspicious, threshold: Severity.High);

        Assert.True(File.Exists(path));
        Assert.Null(e.PendingAction);
        Assert.Empty(_db.GetQuarantine());
    }

    [Fact]
    public async Task Nothing_is_quarantined_while_turned_off()
    {
        _state.SetProtectionOff(DateTime.UtcNow);
        _db.SetRuntimeSettings(new RuntimeSettings { MalwareBazaarApiKey = "test", AutoQuarantineMinSeverity = Severity.Medium });
        var path = NewFile();
        var sha = FileHasher.TryHash(path, long.MaxValue)!;
        _db.CacheReputation(sha, new ReputationResult("MalwareBazaar", ReputationVerdict.Malicious, "TestMalware", "test", null));

        // Turned off: background lookups are skipped entirely, so the file is untouched.
        Assert.True(_reputation.Enqueue(new ReputationRequest(sha, path, UseVirusTotal: false, Manual: false)));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try { await _reputation.RunAsync(cts.Token); } catch (OperationCanceledException) { }

        Assert.True(File.Exists(path));
        Assert.Empty(_db.GetQuarantine());
    }

    [Theory]
    [InlineData(ReputationVerdict.Malicious, Severity.High)]
    [InlineData(ReputationVerdict.Suspicious, Severity.Medium)]
    public async Task File_at_or_above_the_threshold_is_quarantined_without_asking(ReputationVerdict verdict, Severity threshold)
    {
        TestEnv.RequireElevation(); // the quarantine folder is under ProgramData, writable by administrators only

        var (path, e) = await DetectAsync(verdict, threshold);

        Assert.False(File.Exists(path));
        Assert.Null(e.PendingAction);
        Assert.Contains("Automatically quarantined", e.Details);
        Assert.Single(_db.GetQuarantine(), q => string.Equals(q.OriginalPath, path, StringComparison.OrdinalIgnoreCase));
    }

    private string NewFile()
    {
        var path = Path.Combine(_work, $"sample-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, Guid.NewGuid().ToByteArray());
        return path;
    }

    private async Task<(string Path, GuardianEvent Event)> DetectAsync(ReputationVerdict verdict, Severity? threshold)
    {
        _db.SetRuntimeSettings(new RuntimeSettings { MalwareBazaarApiKey = "test", AutoQuarantineMinSeverity = threshold });
        var path = NewFile();
        var sha = FileHasher.TryHash(path, long.MaxValue)!;
        _db.CacheReputation(sha, new ReputationResult("MalwareBazaar", verdict, "TestMalware", "test", null));

        Assert.True(_reputation.Enqueue(new ReputationRequest(sha, path, UseVirusTotal: false, Manual: false)));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var run = _reputation.RunAsync(cts.Token);
        GuardianEvent? e = null;
        while (e is null && !cts.IsCancellationRequested)
        {
            e = _db.GetEvents(null, 10, false).FirstOrDefault(x => x.Category == EventCategory.Malware);
            if (e is null) await Task.Delay(50, TestContext.Current.CancellationToken);
        }
        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
        return (path, Assert.IsType<GuardianEvent>(e));
    }
}
