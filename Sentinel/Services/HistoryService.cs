using System.Text.Json;
using Sentinel.Models;

namespace Sentinel.Services;

public sealed class HistoryService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly object _gate = new();
    private List<ScanSession> _sessions = new();
    private int _limit = 200;

    public IReadOnlyList<ScanSession> Sessions
    {
        get { lock (_gate) return _sessions.ToList(); }
    }

    public void Load(int limit)
    {
        lock (_gate)
        {
            _limit = Math.Max(10, limit);
            try
            {
                if (File.Exists(AppPaths.HistoryFile))
                {
                    _sessions = JsonSerializer.Deserialize<List<ScanSession>>(File.ReadAllText(AppPaths.HistoryFile), JsonOptions) ?? new List<ScanSession>();
                }
                else
                {
                    _sessions = new List<ScanSession>();
                }
            }
            catch
            {
                _sessions = new List<ScanSession>();
            }
            _sessions.Sort((a, b) => b.StartedAtUtc.CompareTo(a.StartedAtUtc));
            TrimLocked();
        }
    }

    public void Add(ScanSession session)
    {
        lock (_gate)
        {
            _sessions.Insert(0, session);
            TrimLocked();
            SaveLocked();
        }
    }

    public void Delete(string sessionId)
    {
        lock (_gate)
        {
            _sessions.RemoveAll(s => s.Id == sessionId);
            SaveLocked();
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _sessions.Clear();
            SaveLocked();
        }
    }

    private void TrimLocked()
    {
        if (_sessions.Count > _limit) _sessions.RemoveRange(_limit, _sessions.Count - _limit);
    }

    private void SaveLocked()
    {
        try
        {
            AppPaths.EnsureDirectories();
            string tmp = AppPaths.HistoryFile + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_sessions, JsonOptions));
            File.Move(tmp, AppPaths.HistoryFile, overwrite: true);
        }
        catch
        {
            // History persistence must never break a scan.
        }
    }
}
