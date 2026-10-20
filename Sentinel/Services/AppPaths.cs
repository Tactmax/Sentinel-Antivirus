namespace Sentinel.Services;

public static class AppPaths
{
    // SENTINEL_DATA_ROOT lets tests (or portable setups) redirect Sentinel's data folder.
    public static string Root { get; } =
        Environment.GetEnvironmentVariable("SENTINEL_DATA_ROOT") is string custom && !string.IsNullOrWhiteSpace(custom)
            ? custom
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel");

    public static string QuarantineDir => Path.Combine(Root, "Quarantine");
    public static string LegacyManifestDir => Path.Combine(Root, "Manifests");
    public static string HistoryFile => Path.Combine(Root, "history.json");
    public static string SettingsFile => Path.Combine(Root, "settings.json");
    public static string QuarantineKeyFile => Path.Combine(Root, "quarantine.key");
    public static string LogsDir => Path.Combine(Root, "Logs");
    public static string ManagedClamDir => Path.Combine(Root, "ClamAV");
    public static string ManagedClamScan => Path.Combine(ManagedClamDir, "clamscan.exe");
    public static string ManagedFreshClam => Path.Combine(ManagedClamDir, "freshclam.exe");
    public static string ManagedClamDatabase => Path.Combine(ManagedClamDir, "database");
    public static string ManagedClamConfig => Path.Combine(ManagedClamDir, "freshclam.conf");

    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(QuarantineDir);
        Directory.CreateDirectory(LogsDir);
    }
}
