using System.Net;
using System.Text.Json;

namespace WinGuardian.Core.Reputation;

public interface IReputationProvider
{
    string Name { get; }

    /// <summary>Minimum delay between requests (free-tier rate limits).</summary>
    TimeSpan MinInterval { get; }

    Task<ReputationResult> LookupAsync(string sha256, CancellationToken ct);
}

/// <summary>Thrown when a provider reports it is rate-limited; the request should be retried later.</summary>
public sealed class RateLimitedException(string provider) : Exception($"{provider} rate limit reached");

/// <summary>abuse.ch MalwareBazaar: a database of confirmed malware samples. Free API key required.</summary>
public sealed class MalwareBazaarProvider(HttpClient http, string apiKey) : IReputationProvider
{
    public string Name => "MalwareBazaar";
    public TimeSpan MinInterval => TimeSpan.FromSeconds(1);

    public async Task<ReputationResult> LookupAsync(string sha256, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["query"] = "get_info", ["hash"] = sha256 }),
        };
        request.Headers.Add("Auth-Key", apiKey);

        using var response = await http.SendAsync(request, ct);
        if (response.StatusCode == HttpStatusCode.TooManyRequests) throw new RateLimitedException(Name);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            return new ReputationResult(Name, ReputationVerdict.Error, null, "API key rejected", null);
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var status = doc.RootElement.TryGetProperty("query_status", out var s) ? s.GetString() : null;
        if (status is "hash_not_found" or "no_results")
            return new ReputationResult(Name, ReputationVerdict.NotFound, null, "Not in MalwareBazaar", null);
        if (status != "ok")
            return new ReputationResult(Name, ReputationVerdict.Error, null, $"query_status: {status}", null);

        var sample = doc.RootElement.GetProperty("data")[0];
        var signature = sample.TryGetProperty("signature", out var sig) && sig.ValueKind == JsonValueKind.String ? sig.GetString() : null;
        var tags = sample.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array
            ? string.Join(", ", t.EnumerateArray().Select(x => x.GetString()))
            : null;
        var firstSeen = sample.TryGetProperty("first_seen", out var fs) ? fs.GetString() : null;

        // Everything in MalwareBazaar is a submitted malware sample.
        return new ReputationResult(Name, ReputationVerdict.Malicious, signature ?? tags ?? "malware sample",
            $"Known malware sample (first seen {firstSeen}); tags: {tags}",
            $"https://bazaar.abuse.ch/sample/{sha256}/");
    }
}

/// <summary>VirusTotal: scan results from ~70 antivirus engines. Free API key: 4 requests/minute, 500/day.</summary>
public sealed class VirusTotalProvider(HttpClient http, string apiKey, int maliciousThreshold) : IReputationProvider
{
    public string Name => "VirusTotal";
    public TimeSpan MinInterval => TimeSpan.FromSeconds(16);

    public async Task<ReputationResult> LookupAsync(string sha256, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
        request.Headers.Add("x-apikey", apiKey);

        using var response = await http.SendAsync(request, ct);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return new ReputationResult(Name, ReputationVerdict.NotFound, null, "Never submitted to VirusTotal", null);
        if (response.StatusCode == HttpStatusCode.TooManyRequests) throw new RateLimitedException(Name);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            return new ReputationResult(Name, ReputationVerdict.Error, null, "API key rejected", null);
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var attributes = doc.RootElement.GetProperty("data").GetProperty("attributes");
        var stats = attributes.GetProperty("last_analysis_stats");
        int Stat(string name) => stats.TryGetProperty(name, out var v) ? v.GetInt32() : 0;
        var malicious = Stat("malicious");
        var suspicious = Stat("suspicious");
        var total = malicious + suspicious + Stat("undetected") + Stat("harmless");

        string? label = null;
        if (attributes.TryGetProperty("popular_threat_classification", out var ptc) &&
            ptc.TryGetProperty("suggested_threat_label", out var stl))
            label = stl.GetString();

        var verdict = malicious >= maliciousThreshold ? ReputationVerdict.Malicious
            : malicious > 0 || suspicious > 0 ? ReputationVerdict.Suspicious
            : ReputationVerdict.Clean;

        return new ReputationResult(Name, verdict, label,
            $"{malicious}/{total} engines flag it as malicious, {suspicious} as suspicious",
            $"https://www.virustotal.com/gui/file/{sha256}");
    }
}
