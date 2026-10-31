using WinGuardian.Core.Reputation;

namespace WinGuardian.Service;

/// <summary>Hosts the reputation lookup queue.</summary>
public sealed class ReputationWorker(ReputationService reputation) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try
        {
            await reputation.RunAsync(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }
}
