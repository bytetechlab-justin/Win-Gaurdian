namespace WinGuardian.Core.Reputation;

/// <summary>The service's half of "Scan with WG": online reputation and what WinGaurdian already knows about the file.</summary>
public sealed class FileScanResult
{
    public string Sha256 { get; set; } = "";
    public List<ReputationResult> Reputation { get; set; } = [];

    /// <summary>At least one online service (MalwareBazaar / VirusTotal) has an API key.</summary>
    public bool ReputationConfigured { get; set; }
    public bool VirusTotalQuotaReached { get; set; }

    public bool Trusted { get; set; }
    public bool Blocked { get; set; }
    public bool PreviouslyQuarantined { get; set; }
}
