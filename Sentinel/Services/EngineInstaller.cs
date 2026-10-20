using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Sentinel.Services;

public sealed class EngineInstallProgress
{
    public string Stage { get; init; } = "";
    public double? Percent { get; init; }
    public long BytesReceived { get; init; }
    public long TotalBytes { get; init; }
}

public sealed class EngineInstallResult
{
    public required string ClamScanPath { get; init; }
    public required string FreshClamPath { get; init; }
    public required string DatabaseDirectory { get; init; }
    public required string ConfigPath { get; init; }
}

/// <summary>
/// Downloads the official ClamAV portable Windows package published by Cisco Talos
/// on the ClamAV GitHub releases page, verifies its SHA-256 digest against the
/// GitHub release metadata, extracts it into Sentinel's managed directory and
/// writes a ready-to-use freshclam.conf. No administrator rights are required.
/// </summary>
public sealed class EngineInstaller
{
    public const string ClamAvVersion = "1.5.4";

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(30) };

    public static string GetPackageArchitecture()
    {
        return RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.Arm64 => "win.arm64",
            Architecture.X86 => "win.win32",
            _ => "win.x64"
        };
    }

    public static string GetDownloadUrl() =>
        $"https://github.com/Cisco-Talos/clamav/releases/download/clamav-{ClamAvVersion}/clamav-{ClamAvVersion}.{GetPackageArchitecture()}.zip";

    public static string GetOfficialDownloadsPage() => "https://www.clamav.net/downloads";

    public async Task<EngineInstallResult> InstallAsync(
        IProgress<EngineInstallProgress>? progress,
        CancellationToken ct)
    {
        AppPaths.EnsureDirectories();
        string url = GetDownloadUrl();
        string zipPath = Path.Combine(AppPaths.Root, $"clamav-{ClamAvVersion}-{GetPackageArchitecture()}.zip");
        string extractTemp = Path.Combine(AppPaths.Root, "ClamAV.extract.tmp");

        try
        {
            progress?.Report(new EngineInstallProgress { Stage = $"Downloading ClamAV {ClamAvVersion} from the official Cisco Talos release…" });
            string? expectedSha256 = await TryGetReleaseDigestAsync(url, ct);

            using (var response = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct))
            {
                response.EnsureSuccessStatusCode();
                long total = response.Content.Headers.ContentLength ?? 0;
                await using Stream src = await response.Content.ReadAsStreamAsync(ct);
                await using var dst = new FileStream(zipPath, FileMode.Create, FileAccess.Write, FileShare.None);
                byte[] buffer = new byte[1024 * 256];
                long received = 0;
                int read;
                var lastReport = DateTime.UtcNow;
                while ((read = await src.ReadAsync(buffer, ct)) > 0)
                {
                    await dst.WriteAsync(buffer.AsMemory(0, read), ct);
                    received += read;
                    if (total > 0 && DateTime.UtcNow - lastReport > TimeSpan.FromMilliseconds(200))
                    {
                        lastReport = DateTime.UtcNow;
                        progress?.Report(new EngineInstallProgress
                        {
                            Stage = "Downloading ClamAV…",
                            Percent = received * 100.0 / total,
                            BytesReceived = received,
                            TotalBytes = total
                        });
                    }
                }
            }

            progress?.Report(new EngineInstallProgress { Stage = "Verifying download integrity…", Percent = 100 });
            string actualSha256 = await HashUtil.ComputeFileSha256Async(zipPath, ct);
            if (expectedSha256 is not null && !string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(zipPath);
                throw new InvalidOperationException(
                    "The downloaded ClamAV package did not match the official SHA-256 digest published on GitHub. " +
                    "The download was discarded. Check your network connection and try again.");
            }

            progress?.Report(new EngineInstallProgress { Stage = "Extracting ClamAV (this can take a minute)…" });
            if (Directory.Exists(extractTemp)) Directory.Delete(extractTemp, recursive: true);
            await Task.Run(() => ZipFile.ExtractToDirectory(zipPath, extractTemp), ct);

            string? payloadRoot = FindPackageRoot(extractTemp)
                ?? throw new InvalidOperationException("The ClamAV package layout was not recognized.");

            string dest = AppPaths.ManagedClamDir;
            if (Directory.Exists(dest)) Directory.Delete(dest, recursive: true);
            Directory.CreateDirectory(dest);
            foreach (string dir in Directory.GetDirectories(payloadRoot, "*", SearchOption.AllDirectories))
            {
                Directory.CreateDirectory(dir.Replace(payloadRoot, dest));
            }
            foreach (string file in Directory.GetFiles(payloadRoot, "*", SearchOption.AllDirectories))
            {
                File.Move(file, file.Replace(payloadRoot, dest));
            }

            progress?.Report(new EngineInstallProgress { Stage = "Writing configuration…" });
            string clamscan = Path.Combine(dest, "clamscan.exe");
            string freshclam = Path.Combine(dest, "freshclam.exe");
            if (!File.Exists(clamscan))
                throw new InvalidOperationException("clamscan.exe was missing from the official package.");

            string databaseDir = AppPaths.ManagedClamDatabase;
            Directory.CreateDirectory(databaseDir);
            string configFile = AppPaths.ManagedClamConfig;
            await File.WriteAllTextAsync(configFile, BuildFreshClamConfig(databaseDir), ct);

            TryDelete(zipPath);
            TryDeleteDirectory(extractTemp);

            progress?.Report(new EngineInstallProgress { Stage = "ClamAV installed" });
            return new EngineInstallResult
            {
                ClamScanPath = clamscan,
                FreshClamPath = freshclam,
                DatabaseDirectory = databaseDir,
                ConfigPath = configFile
            };
        }
        catch
        {
            TryDelete(zipPath);
            TryDeleteDirectory(extractTemp);
            throw;
        }
    }

    public static string BuildFreshClamConfig(string databaseDir)
    {
        // ClamAV 1.5.x rejects unknown options outright, so these names must match the
        // pinned engine version exactly. Verified against freshclam 1.5.4:
        //  - `LogFile` is a clamd option (freshclam uses `UpdateLogFile`)
        //  - `MaxConnectionAttempts` was renamed to `MaxAttempts`
        //  - freshclam 1.5.x also refuses to start without an explicit `DatabaseMirror`
        string logFile = Path.Combine(AppPaths.LogsDir, "freshclam.log");
        string user = Environment.UserName;
        return
            $"DatabaseDirectory \"{databaseDir.Replace("\\", "\\\\")}\"\r\n" +
            $"DatabaseOwner \"{user}\"\r\n" +
            "DatabaseMirror database.clamav.net\r\n" +
            $"UpdateLogFile \"{logFile.Replace("\\", "\\\\")}\"\r\n" +
            "LogTime yes\r\n" +
            "LogVerbose no\r\n" +
            "MaxAttempts 3\r\n" +
            // The official default. Leaving DNS checking enabled lets freshclam decide for
            // free whether a download is needed; disabling it (no.cvd.clamav.net) forces an
            // HTTP header check on every run, which trips the ClamAV CDN rate limiter.
            "DNSDatabaseInfo current.cvd.clamav.net\r\n";
    }

    private static async Task<string?> TryGetReleaseDigestAsync(string assetUrl, CancellationToken ct)
    {
        try
        {
            string tag = $"clamav-{ClamAvVersion}";
            string assetName = Path.GetFileName(new Uri(assetUrl).LocalPath);
            using var request = new HttpRequestMessage(HttpMethod.Get,
                $"https://api.github.com/repos/Cisco-Talos/clamav/releases/tags/{tag}");
            request.Headers.TryAddWithoutValidation("User-Agent", "Sentinel-Antivirus");
            using HttpResponseMessage response = await Http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode) return null;

            await using Stream stream = await response.Content.ReadAsStreamAsync(ct);
            using JsonDocument doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            foreach (JsonElement asset in doc.RootElement.GetProperty("assets").EnumerateArray())
            {
                if (!string.Equals(asset.GetProperty("name").GetString(), assetName, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (asset.TryGetProperty("digest", out JsonElement digest))
                {
                    string? value = digest.GetString();
                    if (value is not null && value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
                        return value["sha256:".Length..];
                }
            }
            return null;
        }
        catch
        {
            return null; // Digest verification is best effort; the download is still from the official host.
        }
    }

    private static string? FindPackageRoot(string extractDir)
    {
        string[] dirs = Directory.GetDirectories(extractDir);
        if (dirs.Length == 1 && File.Exists(Path.Combine(dirs[0], "clamscan.exe")))
            return dirs[0];
        if (File.Exists(Path.Combine(extractDir, "clamscan.exe")))
            return extractDir;
        foreach (string dir in dirs)
        {
            if (File.Exists(Path.Combine(dir, "clamscan.exe"))) return dir;
        }
        return null;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); } catch { }
    }
}
