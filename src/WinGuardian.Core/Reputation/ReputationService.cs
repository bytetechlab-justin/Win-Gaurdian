using System.Globalization;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;

namespace WinGuardian.Core.Reputation;

public sealed record ReputationRequest(string Sha256, string? FilePath, bool UseVirusTotal, bool Manual);

/// <summary>
/// Looks up the hashes of new/changed executables against MalwareBazaar and VirusTotal and raises a
/// Malware event on a hit. Lookups are queued, cached, rate-limited, and VirusTotal usage is capped
/// per day (free tier: 500/day), so bulk file changes such as Windows Update only go to MalwareBazaar.
/// </summary>
public sealed class ReputationService
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromDays(7);
    private static readonly TimeSpan NotFoundTtl = TimeSpan.FromDays(1);
    private const string MetaVirusTotalQuota = "virustotal_quota";
    private const int MaliciousEngineThreshold = 3;

    private static readonly HttpClient Http = CreateHttpClient();

    private readonly GuardianDatabase _db;
    private readonly EventRecorder _events;
    private readonly TrustStore _trust;
    private readonly QuarantineManager _quarantine;
    private readonly ILogger<ReputationService> _logger;
    private readonly Channel<ReputationRequest> _queue = Channel.CreateBounded<ReputationRequest>(
        new BoundedChannelOptions(5000) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true });
    private readonly HashSet<string> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _lastRequest = [];
    private readonly Dictionary<string, DateTime> _lastProviderError = [];

    public ReputationService(GuardianDatabase db, EventRecorder events, TrustStore trust, QuarantineManager quarantine,
        ILogger<ReputationService> logger)
    {
        _db = db;
        _events = events;
        _trust = trust;
        _quarantine = quarantine;
        _logger = logger;
        _events.Recorded += OnEventRecorded;
    }

    public bool Enqueue(ReputationRequest request)
    {
        lock (_pending)
        {
            if (!request.Manual && !_pending.Add(request.Sha256)) return false;
        }
        return _queue.Writer.TryWrite(request);
    }

    /// <summary>Decides which recorded events deserve a lookup.</summary>
    private void OnEventRecorded(GuardianEvent e)
    {
        if (e.Sha256 is null || e.Change is not (ChangeKind.Added or ChangeKind.Modified)) return;
        switch (e.Category)
        {
            case EventCategory.File when e.FilePath is not null && SeverityRules.IsExecutable(e.FilePath):
                Enqueue(new ReputationRequest(e.Sha256, e.FilePath, UseVirusTotal: false, Manual: false));
                break;
            case EventCategory.Process or EventCategory.Service or EventCategory.Persistence or EventCategory.ScheduledTask or EventCategory.Network:
                Enqueue(new ReputationRequest(e.Sha256, e.FilePath, UseVirusTotal: true, Manual: false));
                break;
        }
    }

    public async Task RunAsync(CancellationToken ct)
    {
        await foreach (var request in _queue.Reader.ReadAllAsync(ct))
        {
            try
            {
                await ProcessAsync(request, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Reputation lookup failed for {Hash}", request.Sha256);
                if (request.Manual)
                    _events.Info("Hash lookup failed", $"{request.Sha256}: {ex.Message}");
            }
            finally
            {
                lock (_pending) _pending.Remove(request.Sha256);
            }
        }
    }

    /// <summary>
    /// On-demand check of one file ("Scan with WG"): asks every configured provider now (using the cache and
    /// rate limits) and returns the answers. Detections are also recorded as events, like any other lookup.
    /// </summary>
    public async Task<FileScanResult> ScanAsync(string sha256, string? path, CancellationToken ct)
    {
        var settings = _db.GetRuntimeSettings();
        var result = new FileScanResult
        {
            Sha256 = sha256,
            ReputationConfigured = !string.IsNullOrWhiteSpace(settings.MalwareBazaarApiKey) || !string.IsNullOrWhiteSpace(settings.VirusTotalApiKey),
            Trusted = _trust.IsTrustedFile(path, sha256),
            PreviouslyQuarantined = _db.GetQuarantine().Any(q => string.Equals(q.Sha256, sha256, StringComparison.OrdinalIgnoreCase)),
        };

        if (!string.IsNullOrWhiteSpace(settings.MalwareBazaarApiKey))
            result.Reputation.Add(await LookupAsync(new MalwareBazaarProvider(Http, settings.MalwareBazaarApiKey.Trim()), sha256, ct));
        if (!string.IsNullOrWhiteSpace(settings.VirusTotalApiKey))
        {
            var provider = new VirusTotalProvider(Http, settings.VirusTotalApiKey.Trim(), MaliciousEngineThreshold);
            var cached = _db.GetCachedReputation(sha256, provider.Name, CacheTtl);
            if (cached is not null || TryConsumeVirusTotalQuota(settings.VirusTotalDailyLimit))
                result.Reputation.Add(cached ?? await LookupAsync(provider, sha256, ct));
            else
                result.VirusTotalQuotaReached = true;
        }

        // Detections become events (and are auto-quarantined if enabled); clean results need no event.
        if (result.Reputation.Any(r => r.Verdict is ReputationVerdict.Malicious or ReputationVerdict.Suspicious))
            lock (_reportLock) Report(new ReputationRequest(sha256, path, UseVirusTotal: true, Manual: false), result.Reputation, settings);
        return result;
    }

    private async Task ProcessAsync(ReputationRequest request, CancellationToken ct)
    {
        if (!request.Manual && _trust.IsTrustedFile(request.FilePath, request.Sha256)) return;

        var settings = _db.GetRuntimeSettings();
        var results = new List<ReputationResult>();

        if (!string.IsNullOrWhiteSpace(settings.MalwareBazaarApiKey))
            results.Add(await LookupAsync(new MalwareBazaarProvider(Http, settings.MalwareBazaarApiKey.Trim()), request.Sha256, ct));

        var alreadyMalicious = results.Any(r => r.Verdict == ReputationVerdict.Malicious);
        // Don't spend the VirusTotal daily quota on files Microsoft itself signed (unless asked to).
        var microsoftSigned = !request.Manual && request.FilePath is not null && File.Exists(request.FilePath) &&
                              SignatureVerifier.Verify(request.FilePath).IsMicrosoft;
        if (!string.IsNullOrWhiteSpace(settings.VirusTotalApiKey) && (request.UseVirusTotal || request.Manual) &&
            !alreadyMalicious && !microsoftSigned)
        {
            var provider = new VirusTotalProvider(Http, settings.VirusTotalApiKey.Trim(), MaliciousEngineThreshold);
            var cached = _db.GetCachedReputation(request.Sha256, provider.Name, CacheTtl);
            if (cached is not null || TryConsumeVirusTotalQuota(settings.VirusTotalDailyLimit))
                results.Add(cached ?? await LookupAsync(provider, request.Sha256, ct));
            else
                _logger.LogInformation("VirusTotal daily limit reached; skipping {Hash}", request.Sha256);
        }

        lock (_reportLock) Report(request, results, settings);
    }

    /// <summary>One lookup at a time: on-demand scans (pipe threads) and the background queue share the rate limits.</summary>
    private readonly SemaphoreSlim _lookupGate = new(1, 1);
    private readonly Lock _quotaLock = new();
    private readonly Lock _reportLock = new();

    private async Task<ReputationResult> LookupAsync(IReputationProvider provider, string sha256, CancellationToken ct)
    {
        await _lookupGate.WaitAsync(ct);
        try
        {
            return await LookupCoreAsync(provider, sha256, ct);
        }
        finally
        {
            _lookupGate.Release();
        }
    }

    private async Task<ReputationResult> LookupCoreAsync(IReputationProvider provider, string sha256, CancellationToken ct)
    {
        if (_db.GetCachedReputation(sha256, provider.Name, CacheTtl) is { } cached &&
            (cached.Verdict != ReputationVerdict.NotFound || _db.GetCachedReputation(sha256, provider.Name, NotFoundTtl) is not null))
            return cached;

        for (var attempt = 0; ; attempt++)
        {
            if (_lastRequest.TryGetValue(provider.Name, out var last) && DateTime.UtcNow - last < provider.MinInterval)
                await Task.Delay(provider.MinInterval - (DateTime.UtcNow - last), ct);
            _lastRequest[provider.Name] = DateTime.UtcNow;

            try
            {
                var result = await provider.LookupAsync(sha256, ct);
                if (result.Verdict != ReputationVerdict.Error) _db.CacheReputation(sha256, result);
                return result;
            }
            catch (RateLimitedException) when (attempt < 3)
            {
                _logger.LogInformation("{Provider} rate limited; waiting a minute", provider.Name);
                await Task.Delay(TimeSpan.FromMinutes(1), ct);
            }
            catch (HttpRequestException ex)
            {
                return new ReputationResult(provider.Name, ReputationVerdict.Error, null, ex.Message, null);
            }
        }
    }

    private void Report(ReputationRequest request, List<ReputationResult> results, RuntimeSettings settings)
    {
        var worst = results.Count == 0 ? (ReputationVerdict?)null : results.Max(r => r.Verdict == ReputationVerdict.Error ? ReputationVerdict.NotFound : r.Verdict);
        var summary = results.Count == 0
            ? "No reputation provider is configured (add an API key in Settings)."
            : string.Join("\n", results.Select(r =>
                $"{r.Provider}: {r.Verdict}{(r.Label is null ? "" : $" - {r.Label}")}. {r.Detail}{(r.Link is null ? "" : $" {r.Link}")}"));

        if (worst is ReputationVerdict.Malicious or ReputationVerdict.Suspicious)
        {
            var malicious = worst == ReputationVerdict.Malicious;
            var label = results.FirstOrDefault(r => r.Verdict == worst)?.Label;

            // The path can come from an unprivileged caller (manual lookups and scans send a hash and a path), so
            // only quarantine a file whose current content really is the malware: never "this hash, that file".
            if (malicious && settings.AutoQuarantineMalicious && request.FilePath is not null && File.Exists(request.FilePath) &&
                string.Equals(FileHasher.TryHash(request.FilePath, long.MaxValue), request.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var item = _quarantine.Quarantine(request.FilePath, $"Automatic: known malware ({label})");
                    summary += $"\nAutomatically quarantined (id {item.Id}){(item.PendingReboot ? "; the original will be deleted at the next reboot" : "")}.";
                }
                catch (Exception ex)
                {
                    summary += $"\nAutomatic quarantine failed: {ex.Message}";
                }
            }

            _events.Record(new GuardianEvent
            {
                Severity = malicious ? Severity.High : Severity.Medium,
                Category = EventCategory.Malware,
                Change = ChangeKind.Detected,
                Subject = $"{(malicious ? "Known malware" : "Suspicious file")}{(label is null ? "" : $" ({label})")}: {request.FilePath ?? request.Sha256}",
                Details = $"SHA256 {request.Sha256}\n{summary}",
                FilePath = request.FilePath,
                Sha256 = request.Sha256,
            });
        }
        else if (request.Manual)
        {
            var allFailed = results.Count > 0 && results.All(r => r.Verdict == ReputationVerdict.Error);
            _events.Info($"Hash lookup {(allFailed ? "failed" : "found no detections")} for {request.FilePath ?? request.Sha256}",
                $"SHA256 {request.Sha256}\n{summary}");
        }

        // Surface configuration problems (e.g. a mistyped API key) instead of failing silently forever.
        foreach (var failure in results.Where(r => r.Verdict == ReputationVerdict.Error))
        {
            if (_lastProviderError.TryGetValue(failure.Provider, out var last) && DateTime.UtcNow - last < TimeSpan.FromHours(6)) continue;
            _lastProviderError[failure.Provider] = DateTime.UtcNow;
            _events.Record(new GuardianEvent
            {
                Severity = Severity.Low,
                Category = EventCategory.System,
                Change = ChangeKind.Info,
                Subject = $"{failure.Provider} lookups are failing",
                Details = $"{failure.Detail}. Check the API key in Settings.",
            });
        }
    }

    /// <summary>Counts VirusTotal requests per UTC day in the meta table.</summary>
    private bool TryConsumeVirusTotalQuota(int dailyLimit)
    {
        lock (_quotaLock) return TryConsumeVirusTotalQuotaLocked(dailyLimit);
    }

    private bool TryConsumeVirusTotalQuotaLocked(int dailyLimit)
    {
        var today = DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var parts = (_db.GetMeta(MetaVirusTotalQuota) ?? "").Split('|');
        var used = parts.Length == 2 && parts[0] == today && int.TryParse(parts[1], out var n) ? n : 0;
        if (used >= dailyLimit) return false;
        _db.SetMeta(MetaVirusTotalQuota, $"{today}|{used + 1}");
        return true;
    }

    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("WinGuardian/0.2");
        return client;
    }
}
