using WinGuardian.Core;
using WinGuardian.Core.Configuration;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;
using WinGuardian.Core.Network;
using WinGuardian.Core.Tasks;

namespace WinGuardian.Service;

/// <summary>
/// The service's main loop. On first launch it captures the baseline (processes, services, persistence
/// entries, then a full file scan in the background). After that it runs ETW process tracing, polls
/// processes/services/persistence, keeps the real-time file watcher running, schedules full file scans,
/// prunes old events, maintains the self-protection heartbeat, and executes commands from the tray.
/// </summary>
public sealed class MonitorWorker(
    GuardianDatabase db,
    GuardianOptions options,
    GuardianState state,
    EventRecorder events,
    FileMonitor fileMonitor,
    ProcessMonitor processMonitor,
    ServiceMonitor serviceMonitor,
    PersistenceMonitor persistenceMonitor,
    ScheduledTaskMonitor taskMonitor,
    NetworkMonitor networkMonitor,
    ProcessStartWatcher processStartWatcher,
    SelfProtection selfProtection,
    FileWatcherService watcher,
    IHostApplicationLifetime lifetime,
    ILogger<MonitorWorker> logger) : BackgroundService
{
    private Task? _scanTask;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try
        {
            await Task.Run(db.Initialize, ct);
            await Task.Run(selfProtection.CheckStartup, ct);

            if (db.GetMetaDate(GuardianDatabase.MetaBaselineCreated) is null)
                StartBaseline(ct);
            else
            {
                if (db.GetMeta(GuardianDatabase.MetaPersistenceBaseline) is null)
                {
                    // Upgrade from a version without persistence monitoring.
                    var count = persistenceMonitor.CaptureBaseline();
                    events.Info("Persistence baseline captured", $"{count} autostart entries recorded.");
                }
                if (!taskMonitor.HasBaseline)
                {
                    // Upgrade from a version without scheduled-task analysis.
                    var tasks = await Task.Run(taskMonitor.CaptureBaseline, ct);
                    events.Info("Scheduled task baseline captured", $"{tasks} tasks recorded with their actions, COM handlers and signatures.");
                }
                if (!networkMonitor.HasBaseline)
                {
                    var listeners = await Task.Run(networkMonitor.CaptureBaseline, ct);
                    events.Info("Network baseline captured", $"{listeners} listening ports and the current firewall rules recorded.");
                }
                taskMonitor.Start();
                watcher.Start();
                state.Phase = "Monitoring";
                logger.LogInformation("Baseline found; monitoring started");
            }
            state.EtwProcessTracing = processStartWatcher.Start();

            var nextProcessPoll = DateTime.UtcNow;
            var nextServicePoll = DateTime.UtcNow;
            var nextPersistencePoll = DateTime.UtcNow;
            var nextNetworkPoll = DateTime.UtcNow;
            var nextHeartbeat = DateTime.UtcNow;
            var nextPrune = DateTime.UtcNow;
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));

            while (await timer.WaitForNextTickAsync(ct))
            {
                while (state.Commands.Reader.TryRead(out var command))
                    HandleCommand(command, ct);

                var now = DateTime.UtcNow;
                if (now >= nextProcessPoll)
                {
                    RunSafely("process poll", processMonitor.Poll);
                    nextProcessPoll = now.AddSeconds(options.ProcessPollSeconds);
                }
                if (now >= nextServicePoll)
                {
                    RunSafely("service poll", serviceMonitor.Poll);
                    nextServicePoll = now.AddSeconds(options.ServicePollSeconds);
                }
                if (now >= nextPersistencePoll)
                {
                    RunSafely("persistence poll", persistenceMonitor.Poll);
                    RunSafely("scheduled task check", taskMonitor.Poll);
                    nextPersistencePoll = now.AddSeconds(options.PersistencePollSeconds);
                }
                if (now >= nextNetworkPoll && networkMonitor.HasBaseline)
                {
                    RunSafely("network poll", networkMonitor.Poll);
                    nextNetworkPoll = now.AddSeconds(options.NetworkPollSeconds);
                }
                if (now >= nextHeartbeat)
                {
                    RunSafely("heartbeat", selfProtection.Heartbeat);
                    nextHeartbeat = now.AddSeconds(15);
                }
                if (now >= nextPrune)
                {
                    RunSafely("event cleanup", PruneEvents);
                    nextPrune = now.AddHours(1);
                }
                if (!IsScanRunning && IsFullScanDue(now))
                    StartScan(isBaseline: false, ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal stop (Service Control Manager or system shutdown).
            RunSafely("clean stop marker", selfProtection.RecordCleanStop);
        }
        catch (Exception ex)
        {
            // Exit non-zero so the Service Control Manager's recovery options restart us.
            logger.LogCritical(ex, "WinGuardian monitor failed");
            Environment.ExitCode = 1;
            lifetime.StopApplication();
        }
        finally
        {
            watcher.Stop();
            taskMonitor.Stop();
            processStartWatcher.Dispose();
        }
    }

    private bool IsScanRunning => _scanTask is { IsCompleted: false };

    private bool IsFullScanDue(DateTime now)
    {
        if (db.GetMetaDate(GuardianDatabase.MetaBaselineCreated) is null) return false;
        var last = db.GetMetaDate(GuardianDatabase.MetaLastFullScan);
        return last is null || now - last.Value >= TimeSpan.FromHours(options.FullScanIntervalHours);
    }

    private void HandleCommand(GuardianCommand command, CancellationToken ct)
    {
        switch (command)
        {
            case GuardianCommand.FullScan when IsScanRunning:
                logger.LogInformation("Full scan requested but a scan is already running");
                break;
            case GuardianCommand.FullScan:
                StartScan(isBaseline: false, ct);
                break;
            case GuardianCommand.RebuildBaseline when IsScanRunning:
                events.Info("Baseline rebuild skipped", "A file scan was in progress; try again when it finishes.");
                break;
            case GuardianCommand.RebuildBaseline:
                watcher.Stop();
                taskMonitor.Stop();
                db.ClearBaseline();
                processMonitor.Reset();
                events.Info("Baseline rebuild started", "Requested by an administrator.");
                StartBaseline(ct);
                break;
        }
    }

    private void StartBaseline(CancellationToken ct)
    {
        state.Phase = "Building baseline";
        var processes = processMonitor.CaptureBaseline();
        var services = serviceMonitor.CaptureBaseline();
        var persistence = persistenceMonitor.CaptureBaseline();
        var tasks = taskMonitor.CaptureBaseline();
        networkMonitor.CaptureBaseline();
        taskMonitor.Start();
        events.Info("Process, service, persistence and scheduled task baseline captured",
            $"{processes} executables running, {services} services/drivers registered, {persistence} autostart entries, {tasks} scheduled tasks.");
        StartScan(isBaseline: true, ct);
    }

    private void StartScan(bool isBaseline, CancellationToken ct)
    {
        state.ScanInProgress = true;
        if (!isBaseline) state.Phase = "Scanning";

        _scanTask = Task.Run(() =>
        {
            // Keep the machine responsive: the baseline scan reads every file under C:\Windows.
            Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
            try
            {
                var started = DateTime.UtcNow;
                var changes = fileMonitor.RunFullScan(isBaseline, ct);
                var elapsed = DateTime.UtcNow - started;

                if (isBaseline)
                {
                    db.SetMetaDate(GuardianDatabase.MetaBaselineCreated, DateTime.UtcNow);
                    events.Info("File baseline created",
                        $"{state.ScanFilesProcessed:N0} files recorded in {elapsed:hh\\:mm\\:ss}.");
                    watcher.Start();
                }
                else
                {
                    events.Info("Full file scan completed",
                        $"{state.ScanFilesProcessed:N0} files checked in {elapsed:hh\\:mm\\:ss}; {changes:N0} change(s) found.");
                }
                state.LastError = null;
            }
            catch (OperationCanceledException)
            {
                logger.LogInformation("File scan cancelled");
            }
            catch (Exception ex)
            {
                state.LastError = ex.Message;
                logger.LogError(ex, "File scan failed");
            }
            finally
            {
                state.ScanInProgress = false;
                state.Phase = db.GetMetaDate(GuardianDatabase.MetaBaselineCreated) is null ? "Baseline incomplete" : "Monitoring";
            }
        }, CancellationToken.None);
    }

    private void PruneEvents()
    {
        var retention = Math.Max(1, db.GetRuntimeSettings().EventRetentionDays);
        var removed = db.PruneEvents(retention, hardLimitDays: Math.Max(retention, 365));
        if (removed > 0) logger.LogInformation("Pruned {Count} old events", removed);
    }

    private void RunSafely(string name, Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            state.LastError = $"{name}: {ex.Message}";
            logger.LogWarning(ex, "{Name} failed", name);
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        if (_scanTask is not null)
            await Task.WhenAny(_scanTask, Task.Delay(TimeSpan.FromSeconds(10), cancellationToken));
    }
}
