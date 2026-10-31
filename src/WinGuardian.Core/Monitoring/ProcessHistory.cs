namespace WinGuardian.Core.Monitoring;

public sealed record ProcessStartRecord(int Pid, int ParentPid, string? ImagePath, string? CommandLine, DateTime StartUtc);

/// <summary>
/// Recent process starts seen by ETW, so later evidence that only carries a PID (e.g. a Security event
/// log entry) can be tied to the right program even if it has already exited or its PID was reused.
/// </summary>
public sealed class ProcessHistory
{
    private const int Capacity = 20_000;
    private readonly LinkedList<ProcessStartRecord> _records = new();
    private readonly Lock _gate = new();

    public void Add(ProcessStartRecord record)
    {
        lock (_gate)
        {
            _records.AddLast(record);
            if (_records.Count > Capacity) _records.RemoveFirst();
        }
    }

    /// <summary>The most recent start of <paramref name="pid"/> at or before <paramref name="atUtc"/>.</summary>
    public ProcessStartRecord? Find(int pid, DateTime atUtc)
    {
        lock (_gate)
        {
            for (var node = _records.Last; node is not null; node = node.Previous)
            {
                if (node.Value.Pid == pid && node.Value.StartUtc <= atUtc.AddSeconds(1)) return node.Value;
            }
        }
        return null;
    }
}
