using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using Sentinel.Models;

namespace Sentinel.Services;

public sealed class ScanRequest
{
    public required string TargetPath { get; init; }
    public required string EnginePath { get; init; }
    public string? DatabaseDirectory { get; init; }
    public bool ScanArchives { get; init; } = true;

    /// <summary>Skip files larger than this many bytes. Null/0 means no limit.</summary>
    public long? MaxFileSizeBytes { get; init; }

    /// <summary>Stop scanning a single file after this many bytes. Null/0 means the engine default.</summary>
    public long? MaxScanSizeBytes { get; init; }

    /// <summary>Stop scanning a single file after this many milliseconds. Null/0 means the engine default.</summary>
    public int? MaxScanTimeMs { get; init; }

    /// <summary>
    /// A running ClamAV daemon. When it is ready the scan is delegated to it, which
    /// avoids reloading the signature database for every scan.
    /// </summary>
    public ClamDaemon? Daemon { get; init; }
}

public sealed class ClamAvScanner
{
    private const int MaxWarningLines = 200;

    // A directory's file count is expensive to compute, and quick scans repeat the same
    // folders many times a day. Cache it briefly so the second scan does not re-walk the tree.
    private static readonly ConcurrentDictionary<string, (long Count, DateTime CachedAt)> s_countCache =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan CountCacheTtl = TimeSpan.FromMinutes(2);

    private sealed class SharedState
    {
        public long TotalFiles;
        public long Scanned;
        public volatile bool TotalKnown;
        public DateTime LastReport = DateTime.UtcNow;
        public readonly Stopwatch Clock = Stopwatch.StartNew();
        public readonly object Gate = new();
    }

    public async Task<ScanOutcome> ScanAsync(ScanRequest request, IProgress<ScanProgressInfo>? progress, CancellationToken ct)
        => await ScanManyAsync([request], progress, ct);

    /// <summary>
    /// Scans one or more targets. The scan starts immediately; the file pre-count runs in
    /// the background so a huge tree no longer blocks the first file from being scanned.
    /// When <paramref name="parallelize"/> is set, independent chunks are scanned by
    /// separate engine processes at the same time.
    /// </summary>
    public async Task<ScanOutcome> ScanManyAsync(
        IReadOnlyList<ScanRequest> requests,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken ct,
        bool parallelize = false,
        int maxWorkers = 0)
    {
        var outcome = new ScanOutcome();
        var stopwatch = Stopwatch.StartNew();

        if (requests.Count == 0)
        {
            outcome.FatalError = "No scan target was supplied.";
            outcome.Duration = stopwatch.Elapsed;
            return outcome;
        }

        string enginePath = requests[0].EnginePath;
        if (!File.Exists(enginePath))
        {
            outcome.FatalError = $"The ClamAV scanner was not found at:\n{enginePath}\n\nInstall ClamAV or pick the correct clamscan.exe in Settings.";
            outcome.Duration = stopwatch.Elapsed;
            return outcome;
        }

        foreach (ScanRequest request in requests)
        {
            if (!File.Exists(request.TargetPath) && !Directory.Exists(request.TargetPath))
            {
                outcome.FatalError = $"The scan target does not exist:\n{request.TargetPath}";
                outcome.Duration = stopwatch.Elapsed;
                return outcome;
            }
        }

        if (ct.IsCancellationRequested)
        {
            outcome.Cancelled = true;
            outcome.Duration = stopwatch.Elapsed;
            return outcome;
        }

        // Always the first progress event, so the UI can move from "ready" to "running".
        // The real count arrives later, once the background pre-count finishes.
        progress?.Report(new ScanProgressInfo { CurrentFile = "Counting files…" });

        // A warm daemon answers in milliseconds; a cold clamscan has to reload the
        // whole signature database first, which is by far the slowest part of a scan.
        if (requests.Count >= 1 && requests[0].Daemon is { IsReady: true } daemon)
        {
            var combined = new ScanOutcome();
            foreach (ScanRequest request in requests)
            {
                ScanOutcome part = await ScanViaDaemonAsync(request, daemon, progress, ct).ConfigureAwait(false);
                combined.Detections.AddRange(part.Detections);
                combined.Warnings.AddRange(part.Warnings.Take(MaxWarningLines));
                combined.ScannedFileCount += part.ScannedFileCount;
            }
            combined.ExitCode = combined.Detections.Count > 0 ? 1 : 0;
            combined.Cancelled = combined.Cancelled || ct.IsCancellationRequested;
            combined.Duration = stopwatch.Elapsed;
            return combined;
        }

        int workerCount = maxWorkers <= 0 ? 1 : Math.Clamp(maxWorkers, 1, 8);
        List<Job> jobs = BuildJobs(requests, parallelize, workerCount);

        var state = new SharedState();

        // Start counting in the background. It never delays the scan.
        var countTasks = StartCounting(jobs, state, ct);

        var merged = new MergedOutcome();
        if (jobs.Count == 1)
        {
            merged.Add(await RunJobAsync(jobs[0], state, progress, ct).ConfigureAwait(false));
        }
        else
        {
            using var gate = new SemaphoreSlim(workerCount, workerCount);
            var tasks = jobs.Select(job => Task.Run(async () =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    return await RunJobAsync(job, state, progress, ct).ConfigureAwait(false);
                }
                finally
                {
                    gate.Release();
                }
            }, ct)).ToArray();

            foreach (Task<ScanOutcome> task in tasks)
            {
                try { merged.Add(await task.ConfigureAwait(false)); }
                catch (OperationCanceledException) { merged.Cancelled = true; }
                catch (Exception ex) { merged.Warnings.Add($"A scan worker failed: {ex.Message}"); }
            }
        }

        await Task.WhenAll(countTasks).ConfigureAwait(false);

        stopwatch.Stop();
        outcome.Duration = stopwatch.Elapsed;
        outcome.ScannedFileCount = Interlocked.Read(ref state.Scanned);
        outcome.Detections.AddRange(merged.Detections);
        outcome.Warnings.AddRange(merged.Warnings.Take(MaxWarningLines));

        string stderrText = merged.StdErr.ToString();
        outcome.StdErrExcerpt = stderrText.Length > 4000 ? stderrText[..4000] : stderrText;
        outcome.Cancelled = merged.Cancelled || ct.IsCancellationRequested;

        if (outcome.Cancelled) return outcome;

        int exitCode = merged.ExitCode;
        if (merged.FatalError is not null)
        {
            outcome.FatalError = merged.FatalError;
        }
        else if (exitCode is 0 or 1)
        {
            // Fine.
        }
        else if (exitCode == 2)
        {
            if (outcome.Detections.Count == 0 && outcome.Warnings.Count == 0 && outcome.ScannedFileCount == 0)
            {
                outcome.FatalError = BuildLikelyConfigError(stderrText, outcome);
            }
            else
            {
                outcome.ExitCode = exitCode;
            }
        }
        else
        {
            outcome.FatalError = $"ClamAV exited unexpectedly with code {exitCode}." +
                (string.IsNullOrWhiteSpace(stderrText) ? "" : $"\n\n{stderrText.Trim()}");
        }

        outcome.ExitCode = exitCode;
        return outcome;
    }

    // ------------------------------------------------------------------
    //  Warm daemon path
    // ------------------------------------------------------------------

    /// <summary>
    /// Scans through a running clamd. The signature database is already loaded, so
    /// each file only costs the time it takes to read and match it - no per-scan
    /// database reload at all.
    /// </summary>
    private static async Task<ScanOutcome> ScanViaDaemonAsync(
        ScanRequest request, ClamDaemon daemon, IProgress<ScanProgressInfo>? progress, CancellationToken ct)
    {
        var outcome = new ScanOutcome();
        var state = new SharedState();

        bool isDirectory = Directory.Exists(request.TargetPath);
        Task<long> countTask = isDirectory
            ? CountFilesAsync(request.TargetPath, ct)
            : Task.FromResult(1L);

        _ = countTask.ContinueWith(t =>
        {
            if (t.Status != TaskStatus.RanToCompletion) return;
            Interlocked.Add(ref state.TotalFiles, t.Result);
            state.TotalKnown = true;
        }, TaskScheduler.Default);

        long scanned = 0;
        DateTime lastReport = DateTime.UtcNow;

        foreach (string file in EnumerateScanFiles(request.TargetPath, isDirectory, ct))
        {
            ct.ThrowIfCancellationRequested();

            string? threat = daemon.ScanFile(file, out string? error);
            scanned++;
            Interlocked.Increment(ref state.Scanned);

            if (threat is not null)
            {
                lock (state.Gate)
                {
                    outcome.Detections.Add(new ScanResultItem
                    {
                        Kind = ScanItemKind.Detection,
                        Status = "DETECTED",
                        Threat = threat,
                        Path = file
                    });
                }
            }
            else if (error is not null)
            {
                lock (state.Gate)
                {
                    if (outcome.Warnings.Count < MaxWarningLines) outcome.Warnings.Add(error);
                }
            }

            var now = DateTime.UtcNow;
            if (now - lastReport <= TimeSpan.FromMilliseconds(120)) continue;
            lastReport = now;

            double seconds = state.Clock.Elapsed.TotalSeconds;
            progress?.Report(new ScanProgressInfo
            {
                FilesScanned = scanned,
                TotalFiles = Interlocked.Read(ref state.TotalFiles),
                TotalKnown = state.TotalKnown,
                CurrentFile = file,
                ElapsedSeconds = seconds,
                ScanSpeed = seconds > 0.05 ? scanned / seconds : 0
            });
        }

        outcome.ScannedFileCount = scanned;
        outcome.ExitCode = outcome.Detections.Count > 0 ? 1 : 0;
        outcome.Cancelled = ct.IsCancellationRequested;
        await Task.CompletedTask.ConfigureAwait(false);
        return outcome;
    }

    private static IEnumerable<string> EnumerateScanFiles(string target, bool isDirectory, CancellationToken ct)
    {
        if (!isDirectory)
        {
            yield return target;
            yield break;
        }

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            ReturnSpecialDirectories = false
        };
        foreach (string file in Directory.EnumerateFiles(target, "*", options))
        {
            ct.ThrowIfCancellationRequested();
            yield return file;
        }
    }

    // ------------------------------------------------------------------
    //  Job construction
    // ------------------------------------------------------------------

    private sealed record Job(ScanRequest Request, IReadOnlyList<string> Paths);

    private static List<Job> BuildJobs(IReadOnlyList<ScanRequest> requests, bool parallelize, int workerCount)
    {
        var jobs = new List<Job>();
        if (!parallelize)
        {
            // When every target shares the same engine, database and options, one engine
            // process can scan them all - loading the signature database only once.
            if (requests.Count > 1 && SameSettings(requests))
            {
                var template = requests[0];
                var combined = new ScanRequest
                {
                    TargetPath = template.TargetPath,
                    EnginePath = template.EnginePath,
                    DatabaseDirectory = template.DatabaseDirectory,
                    ScanArchives = template.ScanArchives,
                    MaxFileSizeBytes = template.MaxFileSizeBytes,
                    MaxScanSizeBytes = template.MaxScanSizeBytes,
                    MaxScanTimeMs = template.MaxScanTimeMs
                };
                jobs.Add(new Job(combined, requests.Select(r => r.TargetPath).ToList()));
                return jobs;
            }

            foreach (ScanRequest request in requests)
                jobs.Add(new Job(request, [request.TargetPath]));
            return jobs;
        }

        foreach (ScanRequest request in requests)
        {
            if (Directory.Exists(request.TargetPath))
            {
                List<List<string>>? groups = SplitDirectory(request.TargetPath, workerCount);
                if (groups is not null)
                {
                    foreach (List<string> group in groups)
                        jobs.Add(new Job(request, group));
                    continue;
                }
            }
            jobs.Add(new Job(request, [request.TargetPath]));
        }
        return jobs;
    }

    private static bool SameSettings(IReadOnlyList<ScanRequest> requests)
    {
        ScanRequest first = requests[0];
        return requests.All(r =>
            string.Equals(r.EnginePath, first.EnginePath, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.DatabaseDirectory, first.DatabaseDirectory, StringComparison.OrdinalIgnoreCase) &&
            r.ScanArchives == first.ScanArchives &&
            r.MaxFileSizeBytes == first.MaxFileSizeBytes &&
            r.MaxScanSizeBytes == first.MaxScanSizeBytes &&
            r.MaxScanTimeMs == first.MaxScanTimeMs);
    }

    /// <summary>
    /// Splits a directory into up to <paramref name="maxChunks"/> groups of immediate
    /// children so several engine processes can scan them at once. Returns null when the
    /// directory is too small to be worth splitting.
    /// </summary>
    private static List<List<string>>? SplitDirectory(string directory, int maxChunks)
    {
        string[] subdirectories = SafeEnumerateDirectories(directory);
        if (subdirectories.Length < 8) return null;

        int chunkCount = Math.Min(maxChunks, subdirectories.Length);
        var groups = new List<List<string>>(chunkCount);
        for (int i = 0; i < chunkCount; i++) groups.Add(new List<string>());

        for (int i = 0; i < subdirectories.Length; i++)
            groups[i % chunkCount].Add(subdirectories[i]);

        // Root-level files go with the first group; they are few and cheap.
        string[] rootFiles = SafeEnumerateFiles(directory);
        if (rootFiles.Length > 0) groups[0].AddRange(rootFiles);

        return groups.Where(g => g.Count > 0).ToList();
    }

    private static string[] SafeEnumerateDirectories(string directory)
    {
        try { return Directory.GetDirectories(directory); }
        catch { return []; }
    }

    private static string[] SafeEnumerateFiles(string directory)
    {
        try { return Directory.GetFiles(directory); }
        catch { return []; }
    }

    // ------------------------------------------------------------------
    //  Background file counting
    // ------------------------------------------------------------------

    private static Task[] StartCounting(IReadOnlyList<Job> jobs, SharedState state, CancellationToken ct)
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Job job in jobs)
        {
            foreach (string path in job.Paths)
                if (Directory.Exists(path)) roots.Add(path);
        }

        // Skip a folder that is nested inside another folder we are already counting,
        // so a target like "C:\" plus "C:\Users" is not counted twice.
        var toCount = roots
            .Where(root => !roots.Any(other => !string.Equals(other, root, StringComparison.OrdinalIgnoreCase) && IsSubPath(root, other)))
            .ToList();

        return toCount.Select(root => Task.Run(async () =>
        {
            try
            {
                long count = await CountFilesAsync(root, ct).ConfigureAwait(false);
                Interlocked.Add(ref state.TotalFiles, count);
                state.TotalKnown = true;
            }
            catch (OperationCanceledException) { /* counting is best effort */ }
            catch { /* a failed count just leaves the total unknown */ }
        }, CancellationToken.None)).ToArray();
    }

    private static bool IsSubPath(string path, string possibleParent)
    {
        string parent = possibleParent.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return path.Length > parent.Length &&
               path.StartsWith(parent, StringComparison.OrdinalIgnoreCase) &&
               (path[parent.Length] == Path.DirectorySeparatorChar || path[parent.Length] == Path.AltDirectorySeparatorChar);
    }

    private static async Task<long> CountFilesAsync(string root, CancellationToken ct)
    {
        if (s_countCache.TryGetValue(root, out (long Count, DateTime CachedAt) cached) &&
            DateTime.UtcNow - cached.CachedAt < CountCacheTtl)
        {
            return cached.Count;
        }

        long count = await Task.Run(() => CountFiles(root, ct), CancellationToken.None).ConfigureAwait(false);
        s_countCache[root] = (count, DateTime.UtcNow);
        return count;
    }

    private static long CountFiles(string root, CancellationToken ct)
    {
        long count = 0;
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            ReturnSpecialDirectories = false
        };
        foreach (string _ in Directory.EnumerateFiles(root, "*", options))
        {
            count++;
            if ((count & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
        }
        return count;
    }

    // ------------------------------------------------------------------
    //  One engine process
    // ------------------------------------------------------------------

    private static async Task<ScanOutcome> RunJobAsync(Job job, SharedState state, IProgress<ScanProgressInfo>? progress, CancellationToken ct)
    {
        var outcome = new ScanOutcome();

        bool anyDirectory = job.Paths.Any(Directory.Exists);
        var startInfo = new ProcessStartInfo
        {
            FileName = job.Request.EnginePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            WorkingDirectory = Path.GetDirectoryName(job.Request.EnginePath) ?? Environment.CurrentDirectory
        };

        if (anyDirectory) startInfo.ArgumentList.Add("--recursive");
        if (!job.Request.ScanArchives) startInfo.ArgumentList.Add("--archive=no");
        if (!string.IsNullOrWhiteSpace(job.Request.DatabaseDirectory) && Directory.Exists(job.Request.DatabaseDirectory))
            startInfo.ArgumentList.Add($"--database={job.Request.DatabaseDirectory}");
        if (job.Request.MaxFileSizeBytes is > 0) startInfo.ArgumentList.Add($"--max-filesize={job.Request.MaxFileSizeBytes.Value}");
        if (job.Request.MaxScanSizeBytes is > 0) startInfo.ArgumentList.Add($"--max-scansize={job.Request.MaxScanSizeBytes.Value}");
        if (job.Request.MaxScanTimeMs is > 0) startInfo.ArgumentList.Add($"--max-scantime={job.Request.MaxScanTimeMs.Value}");
        foreach (string path in job.Paths) startInfo.ArgumentList.Add(path);

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            outcome.FatalError = $"ClamAV could not be started.\n\n{DescribeProcessStartFailure(ex, job.Request.EnginePath)}";
            return outcome;
        }

        using var registration = ct.Register(() =>
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch { /* process may already be gone */ }
        });

        var stderrBuilder = new StringBuilder();
        var stdoutTask = Task.Run(async () =>
        {
            while (await process.StandardOutput.ReadLineAsync(CancellationToken.None).ConfigureAwait(false) is string line)
                HandleLine(line, outcome, state, progress);
        }, CancellationToken.None);

        var stderrTask = Task.Run(async () =>
        {
            while (await process.StandardError.ReadLineAsync(CancellationToken.None).ConfigureAwait(false) is string line)
                lock (stderrBuilder) stderrBuilder.AppendLine(line);
        }, CancellationToken.None);

        await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
        await stdoutTask.ConfigureAwait(false);
        await stderrTask.ConfigureAwait(false);

        outcome.ExitCode = process.ExitCode;
        outcome.Cancelled = ct.IsCancellationRequested;
        lock (stderrBuilder) outcome.StdErrExcerpt = stderrBuilder.ToString();
        return outcome;
    }

    private static void HandleLine(string line, ScanOutcome outcome, SharedState state, IProgress<ScanProgressInfo>? progress)
    {
        if (string.IsNullOrWhiteSpace(line)) return;

        if (line.EndsWith(": OK", StringComparison.Ordinal))
        {
            Interlocked.Increment(ref state.Scanned);
        }
        else if (line.EndsWith(" FOUND", StringComparison.Ordinal))
        {
            Interlocked.Increment(ref state.Scanned);
            (string path, string threat) = SplitFoundLine(line);
            lock (state.Gate)
            {
                outcome.Detections.Add(new ScanResultItem
                {
                    Kind = ScanItemKind.Detection,
                    Status = "DETECTED",
                    Threat = threat,
                    Path = path
                });
            }
        }
        else if (line.Contains("ERROR", StringComparison.OrdinalIgnoreCase) ||
                 line.StartsWith("WARNING", StringComparison.OrdinalIgnoreCase))
        {
            lock (state.Gate)
            {
                if (outcome.Warnings.Count < MaxWarningLines) outcome.Warnings.Add(line);
            }
        }

        var now = DateTime.UtcNow;
        if (now - state.LastReport <= TimeSpan.FromMilliseconds(120)) return;
        state.LastReport = now;

        long scanned = Interlocked.Read(ref state.Scanned);
        long total = Interlocked.Read(ref state.TotalFiles);
        double seconds = state.Clock.Elapsed.TotalSeconds;
        progress?.Report(new ScanProgressInfo
        {
            FilesScanned = scanned,
            TotalFiles = total,
            TotalKnown = state.TotalKnown,
            CurrentFile = line,
            ElapsedSeconds = seconds,
            ScanSpeed = seconds > 0.05 ? scanned / seconds : 0
        });
    }

    // ------------------------------------------------------------------
    //  Merging, parsing, diagnostics
    // ------------------------------------------------------------------

    private sealed class MergedOutcome
    {
        public readonly List<ScanResultItem> Detections = [];
        public readonly List<string> Warnings = [];
        public readonly StringBuilder StdErr = new();
        public int ExitCode;
        public bool Cancelled;
        public string? FatalError;

        public void Add(ScanOutcome outcome)
        {
            Detections.AddRange(outcome.Detections);
            Warnings.AddRange(outcome.Warnings);
            if (!string.IsNullOrWhiteSpace(outcome.StdErrExcerpt)) StdErr.AppendLine(outcome.StdErrExcerpt);
            FatalError ??= outcome.FatalError;
            Cancelled |= outcome.Cancelled;
            ExitCode = MergeExitCode(ExitCode, outcome.ExitCode);
        }

        private static int MergeExitCode(int current, int next)
        {
            if (current == 1 || next == 1) return 1;
            if (current == 2 || next == 2) return 2;
            return next;
        }
    }

    public static (string Path, string Threat) SplitFoundLine(string line)
    {
        // Format: "<path>: <threat> FOUND". Windows paths cannot contain ": " after the drive letter.
        int separator = line.IndexOf(": ", StringComparison.Ordinal);
        if (separator < 0)
        {
            int found = line.LastIndexOf(" FOUND", StringComparison.Ordinal);
            return (found > 0 ? line[..found] : line, "");
        }
        string path = line[..separator];
        int end = line.LastIndexOf(" FOUND", StringComparison.Ordinal);
        string threat = end > separator ? line[(separator + 2)..end] : line[(separator + 2)..];
        return (path, threat);
    }

    private static string BuildLikelyConfigError(string stderr, ScanOutcome outcome)
    {
        string detail = string.IsNullOrWhiteSpace(stderr) ? "" : stderr.Trim();
        if (detail.Contains("database", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("No suitable database", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("bytecode.cvd", StringComparison.OrdinalIgnoreCase))
        {
            return "ClamAV has no usable virus signatures yet.\n\nUse “Update definitions” to download the latest signature databases with freshclam, then scan again." +
                (detail.Length > 0 ? $"\n\nTechnical detail:\n{detail}" : "");
        }
        return "ClamAV reported an error and scanned no files." +
            (detail.Length > 0 ? $"\n\nTechnical detail:\n{detail}" : "");
    }

    private static string DescribeProcessStartFailure(Exception ex, string enginePath)
    {
        string dir = Path.GetDirectoryName(enginePath) ?? enginePath;
        return ex switch
        {
            System.ComponentModel.Win32Exception => "The scanner executable could not be started. Make sure clamscan.exe and the DLL files from the ClamAV package are together in the same folder.",
            _ => $"Reason: {ex.Message}\n\nExpected location: {dir}"
        };
    }
}
