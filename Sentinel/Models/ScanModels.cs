using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Sentinel.Models;

public enum ScanItemKind
{
    Detection,
    Clean,
    Warning
}

public sealed class ScanResultItem : INotifyPropertyChanged
{
    private string _status = "";
    private bool _quarantined;

    public string Status
    {
        get => _status;
        set { _status = value; Raise(); }
    }

    public ScanItemKind Kind { get; set; }
    public string Threat { get; set; } = "";
    public string Path { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string Sha256Short => Sha256.Length > 16 ? Sha256[..12] + "…" : Sha256;
    public bool IsDetection => Kind == ScanItemKind.Detection;

    public bool Quarantined
    {
        get => _quarantined;
        set { _quarantined = value; Raise(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Raise([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class ScanProgressInfo
{
    public long FilesScanned { get; init; }
    public long TotalFiles { get; init; }
    public bool TotalKnown { get; init; }
    public string CurrentFile { get; init; } = "";
    public double ElapsedSeconds { get; init; }

    /// <summary>Approximate files scanned per second since the scan started.</summary>
    public double ScanSpeed { get; init; }
}

public sealed class ScanOutcome
{
    public List<ScanResultItem> Detections { get; } = new();
    public List<string> Warnings { get; } = new();
    public long ScannedFileCount { get; set; }
    public int ExitCode { get; set; }
    public bool Cancelled { get; set; }
    public string? FatalError { get; set; }
    public TimeSpan Duration { get; set; }
    public string StdErrExcerpt { get; set; } = "";
}

public sealed class ScanSession
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTime StartedAtUtc { get; set; }
    public DateTime FinishedAtUtc { get; set; }
    public string Target { get; set; } = "";
    public string EngineVersion { get; set; } = "";
    public long ScannedFileCount { get; set; }
    public int DetectionCount { get; set; }
    public int WarningCount { get; set; }
    public string Outcome { get; set; } = "";
    public List<ScanResultItem> Detections { get; set; } = new();
    public List<string> Warnings { get; set; } = new();

    public string StartedLocal => StartedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    public string DetectionSummary => DetectionCount == 0 ? "Clean" : $"{DetectionCount} detection(s)";

    /// <summary>Short, consistent label for the outcome - the same wording everywhere.</summary>
    public string OutcomeLabel => Outcome switch
    {
        "Detections found" => $"{DetectionCount} detection(s)",
        "Clean" => "Clean",
        "Cancelled" => "Cancelled",
        "Error" => "Error",
        _ => string.IsNullOrWhiteSpace(Outcome) ? "Unknown" : Outcome
    };
}
