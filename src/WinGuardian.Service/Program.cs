using Microsoft.Extensions.Logging.Configuration;
using Microsoft.Extensions.Logging.EventLog;
using Microsoft.Extensions.Options;
using WinGuardian.Core;
using WinGuardian.Core.Configuration;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;
using WinGuardian.Core.Reputation;
using WinGuardian.Core.Network;
using WinGuardian.Core.Tasks;
using WinGuardian.Service;

// Pin the content root to the exe folder so appsettings.json is found both as a service and from a console.
var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});

builder.Services.AddWindowsService(o => o.ServiceName = GuardianPaths.ServiceName);
LoggerProviderOptions.RegisterProviderOptions<EventLogSettings, EventLogLoggerProvider>(builder.Services);

builder.Services.Configure<GuardianOptions>(builder.Configuration.GetSection("Guardian"));
builder.Services.PostConfigure<GuardianOptions>(o => o.ApplyDefaults());
builder.Services.AddSingleton(sp => sp.GetRequiredService<IOptions<GuardianOptions>>().Value);

builder.Services.AddSingleton(_ =>
{
    DataDirectorySecurity.EnsureLockedDown(GuardianPaths.DataDirectory);
    var db = new GuardianDatabase(GuardianPaths.DatabasePath);
    db.Initialize(); // before any hosted service (including the pipe server) touches it
    return db;
});
builder.Services.AddSingleton(sp =>
{
    // "Turned off" survives restarts until an administrator turns WinGaurdian back on.
    var state = new GuardianState();
    state.SetProtectionOff(sp.GetRequiredService<GuardianDatabase>().GetMetaDate(GuardianDatabase.MetaProtectionOff));
    return state;
});
builder.Services.AddSingleton<PathFilter>();
builder.Services.AddSingleton<TrustStore>();
builder.Services.AddSingleton<EventRecorder>();
builder.Services.AddSingleton<QuarantineManager>();
builder.Services.AddSingleton<ExecutionBlocker>();
builder.Services.AddSingleton<ReputationService>();
builder.Services.AddSingleton<FileMonitor>();
builder.Services.AddSingleton<ProcessMonitor>();
builder.Services.AddSingleton<ProcessStartWatcher>();
builder.Services.AddSingleton<ServiceMonitor>();
builder.Services.AddSingleton<PersistenceMonitor>();
builder.Services.AddSingleton<SelfProtection>();
builder.Services.AddSingleton<ProcessHistory>();
builder.Services.AddSingleton<ITaskAttributor, TaskAttributor>();
builder.Services.AddSingleton<ScheduledTaskMonitor>();
builder.Services.AddSingleton<NetworkMonitor>();
builder.Services.AddSingleton<WinGuardian.Core.Analysis.ProgramAnalyzer>();
builder.Services.AddSingleton<FileWatcherService>();

builder.Services.AddHostedService<MonitorWorker>();
builder.Services.AddHostedService<ReputationWorker>();
builder.Services.AddHostedService<PipeServer>();

builder.Build().Run();
