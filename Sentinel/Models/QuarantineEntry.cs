namespace Sentinel.Models;

public sealed class QuarantineEntry
{
    public string Id { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public string FileName { get; set; } = "";
    public string Threat { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public long SizeBytes { get; set; }
    public DateTime QuarantinedAtUtc { get; set; }
    public string Notes { get; set; } = "";
    public string PayloadFile { get; set; } = "";
    public bool Encrypted { get; set; } = true;
    public bool OriginalStillPresent { get; set; }
    public DateTime? RestoredAtUtc { get; set; }
    public string? RestorePath { get; set; }

    public string QuarantinedLocal => QuarantinedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    public string Sha256Short => Sha256.Length > 16 ? Sha256[..12] + "…" : Sha256;
    public string SizeDisplay => FormatSize(SizeBytes);
    public string StatusDisplay
    {
        get
        {
            if (OriginalStillPresent) return "Original still present";
            if (RestoredAtUtc is not null) return "Restored";
            return "Quarantined";
        }
    }

    private static string FormatSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        double size = bytes;
        int unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }
        return unit == 0 ? $"{bytes} B" : $"{size:0.#} {units[unit]}";
    }
}
