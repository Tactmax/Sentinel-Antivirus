using System.Diagnostics;

namespace Sentinel.Services;

public sealed class SignatureUpdateResult
{
    public bool Success { get; init; }
    public bool AlreadyUpToDate { get; init; }
    public int ExitCode { get; init; }
    public string Message { get; init; } = "";
    public string RawOutput { get; init; } = "";
}

public sealed class SignatureService
{
    public async Task<SignatureUpdateResult> UpdateAsync(
        string freshClamPath,
        string? configFile,
        IProgress<string>? output,
        CancellationToken ct)
    {
        if (!File.Exists(freshClamPath))
        {
            return new SignatureUpdateResult
            {
                Success = false,
                Message = "freshclam.exe was not found next to the ClamAV engine. Reinstall the ClamAV engine from Settings."
            };
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = freshClamPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(freshClamPath) ?? Environment.CurrentDirectory
        };
        if (!string.IsNullOrWhiteSpace(configFile) && File.Exists(configFile))
        {
            startInfo.ArgumentList.Add($"--config-file={configFile}");
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            return new SignatureUpdateResult { Success = false, Message = $"freshclam could not be started: {ex.Message}" };
        }

        using var registration = ct.Register(() =>
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch { }
        });

        var lines = new List<string>();
        void Enqueue(string? line)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            lock (lines)
            {
                if (lines.Count < 500) lines.Add(line);
            }
            output?.Report(line);
        }

        Task stdout = Task.Run(async () =>
        {
            while (await process.StandardOutput.ReadLineAsync(CancellationToken.None) is string line) Enqueue(line);
        }, CancellationToken.None);
        Task stderr = Task.Run(async () =>
        {
            while (await process.StandardError.ReadLineAsync(CancellationToken.None) is string line) Enqueue(line);
        }, CancellationToken.None);

        await process.WaitForExitAsync(CancellationToken.None);
        await Task.WhenAll(stdout, stderr);

        string all;
        lock (lines) all = string.Join(Environment.NewLine, lines);

        if (ct.IsCancellationRequested)
        {
            return new SignatureUpdateResult
            {
                Success = false,
                ExitCode = process.ExitCode,
                Message = "Signature update was cancelled.",
                RawOutput = all
            };
        }

        // "cool-down"/"rate limit" means the CDN refused the check. freshclam still exits 0,
        // and the local databases are untouched, so this is not a failure - but it is also
        // not an update, so it must not be reported as "updated successfully".
        bool onCoolDown = all.Contains("cool-down", StringComparison.OrdinalIgnoreCase) ||
                          all.Contains("rate limit", StringComparison.OrdinalIgnoreCase);
        bool alreadyUpToDate = all.Contains("up to date", StringComparison.OrdinalIgnoreCase);
        bool success = process.ExitCode == 0 || alreadyUpToDate || onCoolDown;
        string message;
        if (onCoolDown)
        {
            message = "The ClamAV signature server is rate-limiting update checks right now. " +
                      "This is normal if updates were fetched recently; your existing signatures were left as they are. " +
                      "Try again later.";
        }
        else if (success)
        {
            message = alreadyUpToDate
                ? "Virus signatures are already up to date."
                : "Virus signatures updated successfully.";
        }
        else
        {
            message = FriendlyFreshClamError(all, process.ExitCode);
        }

        return new SignatureUpdateResult
        {
            Success = success,
            AlreadyUpToDate = alreadyUpToDate,
            ExitCode = process.ExitCode,
            Message = message,
            RawOutput = all
        };
    }

    public static string FriendlyFreshClamError(string output, int exitCode)
    {
        string lower = output.ToLowerInvariant();
        if (lower.Contains("rate limit") || lower.Contains("cool-down") || lower.Contains("cool down"))
            return "The ClamAV signature server is rate-limiting update checks right now. " +
                   "This is normal if updates were fetched recently; your existing signatures were left as they are. " +
                   "Try again later.";
        if (lower.Contains("could not resolve") || lower.Contains("dns") || lower.Contains("connection") ||
            lower.Contains("network") || lower.Contains("failed to connect") || lower.Contains("timed out"))
            return "Could not reach the ClamAV signature servers. Check your internet connection and try again. " +
                   "The update is not blocked by anything Sentinel controls; corporate proxies may need configuration in freshclam.conf.";
        if (lower.Contains("permission") || lower.Contains("access is denied") || lower.Contains("denied"))
            return "Windows denied access to the signature database folder. Make sure the database directory is writable by your user account.";
        if (lower.Contains("no such file") && lower.Contains("conf"))
            return "freshclam configuration is missing or broken. Reinstall the ClamAV engine from Settings to recreate it.";
        if (lower.Contains("wrong cvd header") || lower.Contains("corrupt") || lower.Contains("invalid"))
            return "The local signature database appears corrupt. Delete the database folder contents via Settings → Repair engine, then update again.";
        return $"Signature update failed (freshclam exit code {exitCode}). See the log for details:\n{Tail(output, 1200)}";
    }

    public static int SignatureAgeDays(DateTime? signatureDateUtc, string? databaseDirectory)
    {
        DateTime newest = DateTime.MinValue;
        if (signatureDateUtc is DateTime d) newest = d;
        if (!string.IsNullOrEmpty(databaseDirectory) && Directory.Exists(databaseDirectory))
        {
            try
            {
                foreach (string file in Directory.EnumerateFiles(databaseDirectory, "*.cvd")
                    .Concat(Directory.EnumerateFiles(databaseDirectory, "*.cld")))
                {
                    DateTime t = File.GetLastWriteTimeUtc(file);
                    if (t > newest) newest = t;
                }
            }
            catch
            {
                // Ignore enumeration failures; fall back to the version-line date.
            }
        }
        if (newest == DateTime.MinValue) return -1;
        return (int)Math.Max(0, (DateTime.UtcNow - newest).TotalDays);
    }

    private static string Tail(string text, int max)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= max ? text : text[^max..];
    }
}
