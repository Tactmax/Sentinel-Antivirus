using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using Sentinel.Models;

namespace Sentinel.Services;

public sealed record ClamAvEngineInfo(
    string ClamScanPath,
    string? FreshClamPath,
    string VersionLine,
    string? EngineVersion,
    string? SignatureVersion,
    DateTime? SignatureDateUtc,
    string? DatabaseDirectory);

public sealed class ClamAvLocator
{
    public ClamAvEngineInfo? Find(AppSettings settings)
    {
        foreach (string candidate in CandidateEnginePaths(settings))
        {
            if (!File.Exists(candidate)) continue;
            ClamAvEngineInfo? info = TryGetEngineInfo(candidate, settings);
            if (info is not null) return info;
        }
        return null;
    }

    public ClamAvEngineInfo? TryGetEngineInfo(string clamScanPath, AppSettings? settings = null)
    {
        if (!File.Exists(clamScanPath)) return null;
        try
        {
            string versionLine = RunVersion(clamScanPath);
            (string? engine, string? sig, DateTime? date) = ParseVersionLine(versionLine);
            string? freshclam = FindFreshClamFor(clamScanPath);
            string? dbDir = ResolveDatabaseDirectory(clamScanPath, settings);
            return new ClamAvEngineInfo(clamScanPath, freshclam, versionLine, engine, sig, date, dbDir);
        }
        catch
        {
            return null;
        }
    }

    private static string RunVersion(string clamScanPath)
    {
        var start = new ProcessStartInfo
        {
            FileName = clamScanPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(clamScanPath) ?? Environment.CurrentDirectory
        };
        start.ArgumentList.Add("--version");

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start clamscan.");
        string output = process.StandardOutput.ReadToEndAsync().WaitAsync(TimeSpan.FromSeconds(20)).GetAwaiter().GetResult();
        process.WaitForExit(20_000);
        return output.Trim();
    }

    // freshclam/clamscan banners are not stable across versions. Observed forms:
    //   "ClamAV 1.5.4/28159/Tue Oct 20 11:54:12 2026"   (ClamAV 1.5.x - weekday, then time, then year)
    //   "ClamAV 1.0.5/27000/Sep 02 2026 10:24:44"       (older - date, then time)
    //   "ClamAV 0.99/42/2026-01-02 03:04:05"            (ISO-ish)
    private static readonly string[] SignatureDateFormats =
    [
        "ddd MMM dd HH:mm:ss yyyy",
        "MMM dd HH:mm:ss yyyy",
        "MMM dd yyyy HH:mm:ss",
        "yyyy-MM-dd HH:mm:ss",
        "yyyy-MM-dd"
    ];

    public static (string? EngineVersion, string? SignatureVersion, DateTime? SignatureDateUtc) ParseVersionLine(string line)
    {
        Match match = Regex.Match(line, @"ClamAV\s+(?<ver>[^\s/]+)/(?<sig>\d+)/(?<date>.+)$");
        if (!match.Success) return (null, null, null);

        string engine = match.Groups["ver"].Value;
        string sig = match.Groups["sig"].Value;
        DateTime? date = null;
        string dateText = match.Groups["date"].Value.Trim();

        if (DateTime.TryParseExact(dateText, SignatureDateFormats, CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime exact) ||
            DateTime.TryParse(dateText, CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out exact))
        {
            // AdjustToUniversal matters: without it AssumeUniversal converts to the local
            // clock, and re-labelling that as UTC would skew the signature-age calculation.
            date = DateTime.SpecifyKind(exact, DateTimeKind.Utc);
        }
        return (engine, sig, date);
    }

    public static string? FindFreshClamFor(string clamScanPath)
    {
        string? dir = Path.GetDirectoryName(clamScanPath);
        if (dir is null) return null;
        string candidate = Path.Combine(dir, "freshclam.exe");
        return File.Exists(candidate) ? candidate : null;
    }

    public static string? ResolveDatabaseDirectory(string clamScanPath, AppSettings? settings)
    {
        if (settings is not null && !string.IsNullOrWhiteSpace(settings.DatabaseDirectory) &&
            Directory.Exists(settings.DatabaseDirectory))
        {
            return settings.DatabaseDirectory;
        }
        string? dir = Path.GetDirectoryName(clamScanPath);
        if (dir is null) return null;
        string local = Path.Combine(dir, "database");
        return Directory.Exists(local) ? local : null;
    }

    private static IEnumerable<string> CandidateEnginePaths(AppSettings settings)
    {
        if (!string.IsNullOrWhiteSpace(settings.EnginePath)) yield return settings.EnginePath;
        yield return AppPaths.ManagedClamScan;
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV", "clamscan.exe");
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ClamAV", "clamscan.exe");
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "ClamAV", "clamscan.exe");

        string? pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(pathEnv))
        {
            foreach (string entry in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                string trimmed = entry.Trim().Trim('"');
                if (trimmed.Length == 0) continue;
                yield return Path.Combine(trimmed, "clamscan.exe");
            }
        }
    }
}
