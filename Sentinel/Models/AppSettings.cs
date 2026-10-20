namespace Sentinel.Models;

public sealed class AppSettings
{
    public string EnginePath { get; set; } = "";
    public string DatabaseDirectory { get; set; } = "";
    public string FreshClamPath { get; set; } = "";
    public string LastScanTarget { get; set; } = "";

    /// <summary>Unpack and scan inside archives (ZIP, CAB, installers…). Slower but safer.</summary>
    public bool ScanArchives { get; set; } = true;

    /// <summary>
    /// Keep ClamAV running in the background. Loading the signature database costs
    /// over a minute on a cold start, so a resident engine turns every scan after
    /// the first into a millisecond-scale operation.
    /// </summary>
    public bool UseBackgroundEngine { get; set; } = true;

    /// <summary>
    /// Split large folders across several ClamAV processes. Only used when the
    /// background engine is unavailable - each extra process loads the whole
    /// signature database again, which costs far more than it saves for most trees.
    /// </summary>
    public bool ParallelScan { get; set; }

    /// <summary>0 means "pick automatically from the CPU".</summary>
    public int ParallelWorkers { get; set; }

    /// <summary>Skip files larger than this many megabytes. 0 means no limit.</summary>
    public int MaxFileSizeMb { get; set; }

    /// <summary>Stop scanning a single file after this many megabytes. 0 means the engine default.</summary>
    public int MaxScanSizeMb { get; set; }

    /// <summary>Stop scanning a single file after this many milliseconds. 0 means the engine default.</summary>
    public int MaxScanTimeMs { get; set; }

    public int DefinitionsWarnDays { get; set; } = 14;
    public int HistoryLimit { get; set; } = 200;

    public int EffectiveParallelWorkers
    {
        get
        {
            if (ParallelWorkers > 0) return Math.Clamp(ParallelWorkers, 1, 8);
            return Math.Clamp(Environment.ProcessorCount, 1, 4);
        }
    }
}
