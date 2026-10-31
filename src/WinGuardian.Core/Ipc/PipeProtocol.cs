using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinGuardian.Core.Ipc;

/// <summary>
/// One JSON request line, one JSON response line, then the connection closes.
/// Read-only commands are open to any signed-in user; commands that change state require
/// the caller to be an elevated administrator (checked by impersonating the pipe client).
/// </summary>
public static class PipeProtocol
{
    public const string PipeName = "WinGuardian.Control";

    public static class Commands
    {
        public const string Status = "status";
        public const string Events = "events";
        public const string Scan = "scan";
        public const string Lookup = "lookup";
        public const string Trusted = "trusted";
        public const string Quarantined = "quarantined";
        public const string Event = "event";
        public const string Network = "network";
        public const string Blocked = "blocked";
        public const string Block = "block";
        public const string Unblock = "unblock";

        // Program analysis. Not admin-only: any user may monitor programs they start themselves (checked by the service).
        public const string AnalysisStart = "analysisStart";
        public const string AnalysisReport = "analysisReport";
        public const string AnalysisStop = "analysisStop";

        // "Scan with WG": the tray hashes the file (as the user) and asks for its online reputation. Not admin-only.
        public const string ScanFile = "scanFile";

        public const string Acknowledge = "acknowledge";
        public const string Rebuild = "rebuild";
        public const string Trust = "trust";
        public const string Untrust = "untrust";
        public const string Quarantine = "quarantine";
        public const string Restore = "restore";
        public const string DeleteQuarantined = "deleteQuarantined";
        public const string GetSettings = "getSettings";
        public const string SetSettings = "setSettings";

        public static bool RequiresAdmin(string command) => command is
            Acknowledge or Rebuild or Trust or Untrust or Quarantine or Restore or DeleteQuarantined or GetSettings or SetSettings or Block or Unblock;
    }

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    public static readonly Encoding Utf8 = new UTF8Encoding(false);
}

public sealed class PipeRequest
{
    public string Command { get; set; } = "";
    public long? SinceId { get; set; }
    public int Limit { get; set; } = 200;
    public bool UnacknowledgedOnly { get; set; }
    public List<long>? Ids { get; set; }
    public string? Id { get; set; }
    public string? Path { get; set; }

    /// <summary>Several files for one request (e.g. blocking multiple selected events at once).</summary>
    public List<string>? Paths { get; set; }
    public string? Sha256 { get; set; }
    public string? Note { get; set; }
    public TrustKind? TrustKind { get; set; }
    public string? Value { get; set; }
    public RuntimeSettings? Settings { get; set; }

    /// <summary>Program analysis: the process to start monitoring.</summary>
    public int? Pid { get; set; }

    /// <summary>Program analysis: also return files and registry keys the program only read.</summary>
    public bool IncludeReads { get; set; }

    /// <summary>Program analysis: end the monitored processes when stopping.</summary>
    public bool Terminate { get; set; }
}

public sealed class PipeResponse
{
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public bool AccessDenied { get; set; }
    public string? Message { get; set; }
    public GuardianStatus? Status { get; set; }
    public List<GuardianEvent>? Events { get; set; }
    public List<TrustEntry>? Trusted { get; set; }
    public List<QuarantineItem>? Quarantined { get; set; }
    public RuntimeSettings? Settings { get; set; }
    public Network.NetworkSnapshot? Network { get; set; }
    public List<Monitoring.BlockedItem>? Blocked { get; set; }
    public Analysis.AnalysisReport? Analysis { get; set; }
    public Reputation.FileScanResult? FileScan { get; set; }

    public static PipeResponse Success(string? message = null) => new() { Ok = true, Message = message };
    public static PipeResponse Fail(string error) => new() { Ok = false, Error = error };
}

/// <summary>The process serving the pipe is not the installed WinGuardian service.</summary>
public sealed class ServerVerificationException(string message) : Exception(message);

public static class PipeClient
{
    /// <summary>Set to 1 to talk to a service started from a console during development (no installed service).</summary>
    public const string AllowUnverifiedVariable = "WINGUARDIAN_ALLOW_UNVERIFIED_SERVER";

    public static async Task<PipeResponse> SendAsync(PipeRequest request, int timeoutMs = 3000, CancellationToken ct = default)
    {
        await using var pipe = new NamedPipeClientStream(".", PipeProtocol.PipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(timeoutMs, ct);
        VerifyServer(pipe);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));

        await using var writer = new StreamWriter(pipe, PipeProtocol.Utf8, leaveOpen: true) { AutoFlush = true };
        using var reader = new StreamReader(pipe, PipeProtocol.Utf8, leaveOpen: true);
        await writer.WriteLineAsync(JsonSerializer.Serialize(request, PipeProtocol.Json).AsMemory(), timeout.Token);
        var line = await reader.ReadLineAsync(timeout.Token)
                   ?? throw new IOException("The WinGaurdian service closed the connection without replying.");
        return JsonSerializer.Deserialize<PipeResponse>(line, PipeProtocol.Json)
               ?? throw new IOException("Empty response from the WinGaurdian service.");
    }

    /// <summary>
    /// Guards against a malicious process creating the pipe first and feeding the tray fake "all clear"
    /// status: the process at the other end must be the one the Service Control Manager started.
    /// </summary>
    private static void VerifyServer(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var serverPid))
            throw new ServerVerificationException("Could not identify the process serving the WinGaurdian pipe.");

        var servicePid = ServiceInfo.GetProcessId(GuardianPaths.ServiceName);
        if (servicePid is not null && servicePid == serverPid) return;

        if (servicePid is null && Environment.GetEnvironmentVariable(AllowUnverifiedVariable) == "1") return;

        throw new ServerVerificationException(
            $"The process answering on the WinGaurdian pipe (PID {serverPid}) is not the WinGaurdian service " +
            $"({(servicePid is null ? "service not running" : $"service PID {servicePid}")}). It may be an impersonation attempt.");
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);
}
