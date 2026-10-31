using System.IO.Pipes;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using WinGuardian.Core;
using WinGuardian.Core.Data;
using WinGuardian.Core.Ipc;
using WinGuardian.Core.Monitoring;
using WinGuardian.Core.Network;
using WinGuardian.Core.Reputation;
using WinGuardian.Core.Tasks;

namespace WinGuardian.Service;

/// <summary>Named-pipe endpoint the tray app uses to read status/events and send commands.</summary>
public sealed class PipeServer(
    GuardianDatabase db,
    GuardianState state,
    EventRecorder events,
    TrustStore trust,
    QuarantineManager quarantine,
    ReputationService reputation,
    NetworkMonitor network,
    ExecutionBlocker blocker,
    ILogger<PipeServer> logger) : BackgroundService
{
    private static readonly string Version =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var security = CreatePipeSecurity();
        var first = true;
        var squatReported = false;

        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                // On the first instance, insist that nobody else already owns the pipe name.
                var pipeOptions = PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None);
                try
                {
                    server = NamedPipeServerStreamAcl.Create(PipeProtocol.PipeName, PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte,
                        pipeOptions, 0, 0, security);
                }
                catch (Exception ex) when (first && ex is IOException or UnauthorizedAccessException)
                {
                    if (!squatReported)
                    {
                        squatReported = true;
                        events.Record(new GuardianEvent
                        {
                            Severity = Severity.High,
                            Category = EventCategory.Tamper,
                            Change = ChangeKind.Detected,
                            Subject = "Another process has taken over WinGaurdian's control pipe",
                            Details = $"\\\\.\\pipe\\{PipeProtocol.PipeName} already existed when the service started " +
                                      "(pipe squatting). The tray app will refuse to trust it. Error: " + ex.Message,
                        });
                    }
                    await Task.Delay(TimeSpan.FromSeconds(10), ct);
                    continue;
                }
                first = false;

                await server.WaitForConnectionAsync(ct);
                _ = HandleClientAsync(server, ct); // the next listener is created immediately
                server = null;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Pipe server error");
                await Task.Delay(1000, ct);
            }
            finally
            {
                server?.Dispose();
            }
        }
    }

    /// <summary>
    /// SYSTEM and Administrators get full control; signed-in users may connect (read/write data) but
    /// may not create their own instances of the pipe, which prevents a user process impersonating the service
    /// while it is running.
    /// </summary>
    private static PipeSecurity CreatePipeSecurity()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return security;
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using (pipe)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(60));

                using var reader = new StreamReader(pipe, PipeProtocol.Utf8, leaveOpen: true);
                await using var writer = new StreamWriter(pipe, PipeProtocol.Utf8, leaveOpen: true) { AutoFlush = true };

                var line = await reader.ReadLineAsync(timeout.Token);
                if (line is null) return;

                PipeResponse response;
                try
                {
                    var request = JsonSerializer.Deserialize<PipeRequest>(line, PipeProtocol.Json)
                                  ?? throw new JsonException("empty request");
                    response = PipeProtocol.Commands.RequiresAdmin(request.Command) && !IsElevatedAdmin(pipe)
                        ? new PipeResponse { AccessDenied = true, Error = "This action requires administrator rights." }
                        : await Task.Run(() => Dispatch(request), timeout.Token);
                }
                catch (JsonException ex)
                {
                    response = PipeResponse.Fail("Malformed request: " + ex.Message);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogWarning(ex, "Pipe request failed");
                    response = PipeResponse.Fail(ex.Message);
                }

                await writer.WriteLineAsync(JsonSerializer.Serialize(response, PipeProtocol.Json).AsMemory(), timeout.Token);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException)
            {
                // Client disconnected or timed out.
            }
        }
    }

    /// <summary>
    /// Impersonates the client to inspect its token. A non-elevated admin under UAC has the
    /// Administrators group disabled, so this is only true for elevated callers (or SYSTEM).
    /// </summary>
    private static bool IsElevatedAdmin(NamedPipeServerStream pipe)
    {
        var result = false;
        try
        {
            pipe.RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
                result = identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            });
        }
        catch
        {
            result = false;
        }
        return result;
    }

    private PipeResponse Dispatch(PipeRequest request)
    {
        switch (request.Command)
        {
            case PipeProtocol.Commands.Status:
                return new PipeResponse { Ok = true, Status = BuildStatus() };

            case PipeProtocol.Commands.Blocked:
                return new PipeResponse { Ok = true, Blocked = blocker.List() };

            case PipeProtocol.Commands.Block:
            {
                var paths = (request.Paths ?? (request.Path is null ? [] : [request.Path]))
                    .Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (paths.Count == 0) return PipeResponse.Fail("No file path given.");

                var lines = new List<string>();
                var blocked = 0;
                foreach (var path in paths)
                {
                    try
                    {
                        var item = blocker.Block(path, request.Note ?? "Blocked by an administrator");
                        blocked++;
                        lines.Add($"Blocked {Path.GetFileName(path)}: " +
                                  (item.AclApplied ? "Windows will refuse to run it." : "system-owned file, so it will be terminated whenever it starts.") +
                                  (item.Services.Count > 0 ? $" Stopped and disabled service(s): {string.Join(", ", item.Services.Select(s => s.Name))}." : ""));
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or FileNotFoundException or IOException or UnauthorizedAccessException)
                    {
                        lines.Add($"Not blocked {Path.GetFileName(path)}: {ex.Message}");
                    }
                }
                if (blocked > 0 && request.Ids is { Count: > 0 }) db.Acknowledge(request.Ids);
                var summary = string.Join("\n", lines);
                return blocked > 0 ? PipeResponse.Success(summary) : PipeResponse.Fail(summary);
            }

            case PipeProtocol.Commands.Unblock:
            {
                if (request.Id is null) return PipeResponse.Fail("No blocked item id given.");
                var item = blocker.Unblock(request.Id);
                return PipeResponse.Success("Unblocked." + (item.Services.Count > 0
                    ? $"\n\nThe start type of {string.Join(", ", item.Services.Select(s => s.Name))} was restored; start the service manually or restart Windows if needed."
                    : ""));
            }

            case PipeProtocol.Commands.Network:
                return new PipeResponse { Ok = true, Network = network.GetSnapshot() };

            case PipeProtocol.Commands.Event:
            {
                if (!long.TryParse(request.Id, out var id)) return PipeResponse.Fail("No event id given.");
                return db.GetEvent(id) is { } e ? new PipeResponse { Ok = true, Events = [e] } : PipeResponse.Fail("No such event.");
            }

            case PipeProtocol.Commands.Events:
                return new PipeResponse
                {
                    Ok = true,
                    Events = db.GetEvents(request.SinceId, Math.Clamp(request.Limit, 1, 5000), request.UnacknowledgedOnly),
                };

            case PipeProtocol.Commands.Scan:
                if (state.ScanInProgress) return PipeResponse.Success("A scan is already running.");
                state.Commands.Writer.TryWrite(GuardianCommand.FullScan);
                return PipeResponse.Success("Full scan started.");

            case PipeProtocol.Commands.Acknowledge:
                return PipeResponse.Success($"{db.Acknowledge(request.Ids):N0} alert(s) acknowledged.");

            case PipeProtocol.Commands.Rebuild:
                if (state.ScanInProgress) return PipeResponse.Fail("A scan is running; try again when it finishes.");
                state.Commands.Writer.TryWrite(GuardianCommand.RebuildBaseline);
                return PipeResponse.Success("Baseline rebuild started.");

            case PipeProtocol.Commands.Lookup:
                return Lookup(request);

            case PipeProtocol.Commands.Trusted:
                return new PipeResponse { Ok = true, Trusted = db.GetTrusted() };

            case PipeProtocol.Commands.Trust:
            {
                if (request.TrustKind is not { } kind || string.IsNullOrWhiteSpace(request.Value))
                    return PipeResponse.Fail("Trust needs a kind and a value.");
                db.AddTrusted(kind, request.Value.Trim(), request.Note);
                trust.Invalidate();
                if (request.Ids is { Count: > 0 }) db.Acknowledge(request.Ids);
                events.Info($"Trusted {kind}: {request.Value}", request.Note);
                return PipeResponse.Success($"Trusted {kind.ToString().ToLowerInvariant()}: {request.Value}");
            }

            case PipeProtocol.Commands.Untrust:
            {
                if (request.TrustKind is not { } kind || request.Value is null) return PipeResponse.Fail("Untrust needs a kind and a value.");
                var removed = db.RemoveTrusted(kind, request.Value);
                trust.Invalidate();
                if (removed) events.Info($"Removed trust for {kind}: {request.Value}");
                return removed ? PipeResponse.Success("Removed from the trusted list.") : PipeResponse.Fail("Not in the trusted list.");
            }

            case PipeProtocol.Commands.Quarantined:
                return new PipeResponse { Ok = true, Quarantined = db.GetQuarantine() };

            case PipeProtocol.Commands.Quarantine:
            {
                if (string.IsNullOrWhiteSpace(request.Path)) return PipeResponse.Fail("No file path given.");
                var item = quarantine.Quarantine(request.Path, request.Note ?? "Quarantined by an administrator");
                if (request.Ids is { Count: > 0 }) db.Acknowledge(request.Ids);
                return PipeResponse.Success(item.PendingReboot
                    ? "The file is in use; a copy was quarantined and the original will be deleted at the next reboot."
                    : "File quarantined.");
            }

            case PipeProtocol.Commands.Restore:
                if (request.Id is null) return PipeResponse.Fail("No quarantine id given.");
                quarantine.Restore(request.Id);
                return PipeResponse.Success("File restored and its path added to the trusted list.");

            case PipeProtocol.Commands.DeleteQuarantined:
                if (request.Id is null) return PipeResponse.Fail("No quarantine id given.");
                quarantine.Delete(request.Id);
                return PipeResponse.Success("Quarantined file permanently deleted.");

            case PipeProtocol.Commands.GetSettings:
            {
                var current = db.GetRuntimeSettings();
                current.TaskAuditingEnabled = TaskAuditing.IsEnabled() == true; // report the real policy state
                return new PipeResponse { Ok = true, Settings = current };
            }

            case PipeProtocol.Commands.SetSettings:
            {
                if (request.Settings is not { } s) return PipeResponse.Fail("No settings given.");
                s.EventRetentionDays = Math.Clamp(s.EventRetentionDays, 1, 3650);
                s.VirusTotalDailyLimit = Math.Clamp(s.VirusTotalDailyLimit, 0, 1_000_000);
                s.MalwareBazaarApiKey = string.IsNullOrWhiteSpace(s.MalwareBazaarApiKey) ? null : s.MalwareBazaarApiKey.Trim();
                s.VirusTotalApiKey = string.IsNullOrWhiteSpace(s.VirusTotalApiKey) ? null : s.VirusTotalApiKey.Trim();
                var auditingNote = "";
                if (s.TaskAuditingEnabled != (TaskAuditing.IsEnabled() == true))
                {
                    if (!TaskAuditing.SetEnabled(s.TaskAuditingEnabled))
                        return PipeResponse.Fail("Could not change the Windows audit policy (it may be controlled by Group Policy).");
                    auditingNote = s.TaskAuditingEnabled
                        ? " Scheduled-task auditing turned on (Windows 'Other Object Access Events')."
                        : " Scheduled-task auditing turned off.";
                }
                db.SetRuntimeSettings(s);
                events.Info("Settings changed",
                    $"MalwareBazaar {(s.MalwareBazaarApiKey is null ? "off" : "on")}, VirusTotal {(s.VirusTotalApiKey is null ? "off" : "on")}, " +
                    $"auto-quarantine {(s.AutoQuarantineMalicious ? "on" : "off")}, event retention {s.EventRetentionDays} days." + auditingNote);
                return PipeResponse.Success("Settings saved.");
            }

            default:
                return PipeResponse.Fail($"Unknown command '{request.Command}'.");
        }
    }

    private PipeResponse Lookup(PipeRequest request)
    {
        var sha256 = request.Sha256;
        if (sha256 is null && request.Path is not null)
        {
            if (!File.Exists(request.Path)) return PipeResponse.Fail("The file no longer exists and no hash was given.");
            sha256 = FileHasher.TryHash(request.Path, long.MaxValue);
        }
        if (sha256 is null || sha256.Length != 64 || !sha256.All(Uri.IsHexDigit))
            return PipeResponse.Fail("A valid SHA-256 hash is required.");

        var settings = db.GetRuntimeSettings();
        if (settings.MalwareBazaarApiKey is null && settings.VirusTotalApiKey is null)
            return PipeResponse.Fail("No reputation service is configured. Add a MalwareBazaar or VirusTotal API key in Settings.");

        reputation.Enqueue(new ReputationRequest(sha256.ToUpperInvariant(), request.Path, UseVirusTotal: true, Manual: true));
        return PipeResponse.Success("Lookup queued. The result will appear in the event list shortly.");
    }

    private GuardianStatus BuildStatus()
    {
        var (files, processes, services, persistence) = db.GetBaselineCounts();
        var (unacked, highest, latestId) = db.GetEventSummary();
        var settings = db.GetRuntimeSettings();
        return new GuardianStatus
        {
            ServiceVersion = Version,
            Phase = state.Phase,
            StartedUtc = state.StartedUtc,
            BaselineCreatedUtc = db.GetMetaDate(GuardianDatabase.MetaBaselineCreated),
            LastFullScanUtc = db.GetMetaDate(GuardianDatabase.MetaLastFullScan),
            ScanInProgress = state.ScanInProgress,
            ScanFilesProcessed = state.ScanFilesProcessed,
            BaselineFileCount = files,
            BaselineProcessCount = processes,
            BaselineServiceCount = services,
            BaselinePersistenceCount = persistence,
            UnacknowledgedCount = unacked,
            HighestUnacknowledgedSeverity = highest,
            LatestEventId = latestId,
            LastError = state.LastError,
            EtwProcessTracing = state.EtwProcessTracing,
            MalwareBazaarConfigured = settings.MalwareBazaarApiKey is not null,
            VirusTotalConfigured = settings.VirusTotalApiKey is not null,
            QuarantineCount = db.GetQuarantine().Count,
            BaselineTaskCount = db.CountTaskStates(),
            TaskAuditingActive = TaskAuditing.IsEnabled() == true,
            BlockedCount = db.GetBlocked().Count,
        };
    }
}
