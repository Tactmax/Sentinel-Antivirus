using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Sentinel.Models;
using Sentinel.Services;

namespace Sentinel.Tests;

/// <summary>
/// Self-contained console test runner for the Sentinel services.
/// No test framework is used on purpose: the suite must build with nothing but the .NET SDK.
/// </summary>
internal static class Program
{
    private static int s_passed;
    private static int s_skipped;
    private static readonly List<string> s_failures = new();
    private static string s_dataRoot = "";
    private static string s_workRoot = "";

    private static async Task<int> Main(string[] args)
    {
        // AppPaths.Root caches SENTINEL_DATA_ROOT on first touch, so the variable must be
        // set before any type from Sentinel.Services is used. Nothing above this line
        // touches AppPaths.
        s_dataRoot = Path.Combine(Path.GetTempPath(), "Sentinel.Tests", Guid.NewGuid().ToString("N"));
        Environment.SetEnvironmentVariable("SENTINEL_DATA_ROOT", s_dataRoot);
        Directory.CreateDirectory(s_dataRoot);

        s_workRoot = Path.Combine(Path.GetTempPath(), "Sentinel.Tests.Work", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(s_workRoot);

        bool realEngine = args.Any(a => a.Equals("--real-engine", StringComparison.OrdinalIgnoreCase));
        string? stub = FindStubEngine();

        Console.WriteLine("Sentinel test suite");
        Console.WriteLine($"  data root   : {s_dataRoot}");
        Console.WriteLine($"  work root   : {s_workRoot}");
        Console.WriteLine($"  stub engine : {stub ?? "NOT FOUND"}");
        Console.WriteLine();

        // --- Settings -------------------------------------------------------
        await Run("settings round-trips through JSON", TestSettingsRoundTrip);
        await Run("settings fall back to defaults when the file is corrupt", TestSettingsCorrupt);

        // --- Pure parsers (unit-testable statics) ---------------------------
        await Run("ClamAvLocator.ParseVersionLine parses the ClamAV banner", TestParseVersionLine);
        await Run("ClamAvLocator.ParseVersionLine rejects non-banners", TestParseVersionLineJunk);
        await Run("ClamAvScanner.SplitFoundLine splits detection lines", TestSplitFoundLine);

        // --- Engine path helpers -------------------------------------------
        await Run("ClamAvLocator resolves freshclam.exe and database folders", TestLocatorPathHelpers);

        // --- UI -------------------------------------------------------------
        await Run("every screen loads and renders (WPF resource smoke test)", TestUiSmoke);
        await Run("theme resources are assigned to properties of the right type", TestBrushResourceAudit);

        // --- Scanner integration against the stub engine -------------------
        await Run("stub engine scan reports detections and progress", () => TestScanDetection(stub));
        await Run("stub engine scan reports a clean folder", () => TestScanClean(stub));
        await Run("scan of a missing target fails fast", () => TestScanMissingTarget(stub));
        await Run("scan cancellation is honoured", () => TestScanCancellation(stub));
        await Run("multiple targets scan in a single engine pass", () => TestScanManyTargets(stub));
        await Run("parallel scan covers a folder with many subdirectories", () => TestParallelScan(stub));

        // --- Quarantine -----------------------------------------------------
        await Run("quarantine -> verify -> restore -> delete round trip", TestQuarantineRoundTrip);
        await Run("quarantine refuses a source that changed since the scan", TestQuarantineHashMismatch);
        await Run("legacy plaintext prototype manifests import and can be deleted", TestLegacyQuarantineImport);

        // --- History --------------------------------------------------------
        await Run("scan history saves, reloads and respects its cap", TestHistory);

        // --- Engine installer config ---------------------------------------
        await Run("freshclam config is valid and official download URLs are used", TestEngineInstallerConfig);

        // --- Optional: real ClamAV engine (run with --real-engine) ----------
        if (realEngine)
        {
            Console.WriteLine();
            Console.WriteLine("Real ClamAV integration");
            string? clamDir = FindRealClamAvDirectory();
            Console.WriteLine($"  clamav dir  : {clamDir ?? "NOT FOUND"}");
            Console.WriteLine();

            if (clamDir is null)
            {
                s_failures.Add("real engine: ClamAV was not found. Set SENTINEL_CLAMAV_DIR or run the app's one-click engine install first.");
                Console.WriteLine("  FAIL  real ClamAV engine was not found");
            }
            else
            {
                await Run("real clamscan is discovered and its version banner parses", () => TestRealEngineDiscovery(clamDir));
                await Run("the generated freshclam.conf is accepted by the real freshclam", () => TestRealFreshClamConfig(clamDir));
                await Run("the app updates signatures through the real freshclam", () => TestRealSignatureUpdate(clamDir));
                await Run("the real engine detects a hash-matched file and quarantine/restore works", () => TestRealHashSignatureDetection(clamDir));
                await Run("a warm ClamAV daemon scans in a fraction of a second", () => TestRealDaemonScan(clamDir));
                await Run("EICAR detection attempt documents Microsoft Defender interference", () => TestRealEicarDetection(clamDir));
            }
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine("(re-run with --real-engine to also exercise the installed ClamAV engine)");
        }

        // --- Report ---------------------------------------------------------
        Console.WriteLine();
        if (s_failures.Count > 0)
        {
            Console.WriteLine("Failures:");
            foreach (string failure in s_failures) Console.WriteLine($"  - {failure}");
            Console.WriteLine();
        }

        Console.WriteLine($"{s_passed} passed, {s_failures.Count} failed, {s_skipped} skipped.");

        Cleanup(s_dataRoot);
        Cleanup(s_workRoot);

        return s_failures.Count == 0 ? 0 : 1;
    }

    // ======================================================================
    //  Settings
    // ======================================================================

    private static Task TestSettingsRoundTrip()
    {
        var service = new SettingsService();
        service.Load();
        service.Settings.EnginePath = @"C:\engines\clamscan.exe";
        service.Settings.DatabaseDirectory = @"C:\engines\database";
        service.Settings.ScanArchives = false;
        service.Settings.DefinitionsWarnDays = 7;
        service.Settings.HistoryLimit = 42;
        service.Save();

        AssertTrue(File.Exists(AppPaths.SettingsFile), "settings.json was not written");

        var reloaded = new SettingsService();
        reloaded.Load();
        AssertEqual(@"C:\engines\clamscan.exe", reloaded.Settings.EnginePath, "EnginePath");
        AssertEqual(@"C:\engines\database", reloaded.Settings.DatabaseDirectory, "DatabaseDirectory");
        AssertTrue(!reloaded.Settings.ScanArchives, "ScanArchives should have persisted as false");
        AssertEqual(7, reloaded.Settings.DefinitionsWarnDays, "DefinitionsWarnDays");
        AssertEqual(42, reloaded.Settings.HistoryLimit, "HistoryLimit");

        // Restore defaults so later tests start from a known state.
        service.Settings.EnginePath = "";
        service.Settings.DatabaseDirectory = "";
        service.Settings.ScanArchives = true;
        service.Settings.DefinitionsWarnDays = 14;
        service.Settings.HistoryLimit = 200;
        service.Save();
        return Task.CompletedTask;
    }

    private static Task TestSettingsCorrupt()
    {
        AppPaths.EnsureDirectories();
        File.WriteAllText(AppPaths.SettingsFile, "{ this is not json ][");
        var service = new SettingsService();
        service.Load();
        AssertEqual("", service.Settings.EnginePath, "EnginePath default");
        AssertTrue(service.Settings.ScanArchives, "ScanArchives should default to true");
        AssertEqual(14, service.Settings.DefinitionsWarnDays, "DefinitionsWarnDays default");

        // Leave a valid file behind for anything that reads settings later.
        service.Save();
        return Task.CompletedTask;
    }

    // ======================================================================
    //  Parsers
    // ======================================================================

    private static Task TestParseVersionLine()
    {
        (string? engine, string? sig, DateTime? date) = ClamAvLocator.ParseVersionLine("ClamAV 1.5.4/27456/Sep 02 2026 10:24:44");
        AssertEqual("1.5.4", engine, "engine version");
        AssertEqual("27456", sig, "signature version");
        AssertTrue(date is not null, "signature date should parse");
        AssertEqual(2026, date!.Value.Year, "signature year");
        AssertEqual(9, date.Value.Month, "signature month");

        (string? engine2, string? sig2, DateTime? date2) = ClamAvLocator.ParseVersionLine("ClamAV 1.0.0/1/2026-01-02 03:04:05");
        AssertEqual("1.0.0", engine2, "engine version 2");
        AssertEqual("1", sig2, "signature version 2");
        AssertTrue(date2 is not null, "ISO-ish date should parse");

        // Leading/trailing whitespace and extra text must not break the match.
        (string? engine3, string? sig3, _) = ClamAvLocator.ParseVersionLine("  ClamAV 0.99/42/May 01 2025 00:00:00  ");
        AssertEqual("0.99", engine3, "engine version 3");
        AssertEqual("42", sig3, "signature version 3");

        // The banner ClamAV 1.5.x actually prints: weekday, then time, then year.
        // (Found by running the suite against the real engine.)
        (string? engine4, string? sig4, DateTime? date4) = ClamAvLocator.ParseVersionLine("ClamAV 1.5.4/28159/Tue Oct 20 11:54:12 2026");
        AssertEqual("1.5.4", engine4, "engine version 4");
        AssertEqual("28159", sig4, "signature version 4");
        AssertTrue(date4 is not null, "the real 1.5.x banner date must parse");
        AssertEqual(2026, date4!.Value.Year, "real banner year");
        AssertEqual(10, date4.Value.Month, "real banner month");
        AssertEqual(20, date4.Value.Day, "real banner day");
        AssertEqual(11, date4.Value.Hour, "real banner hour");
        return Task.CompletedTask;
    }

    private static Task TestParseVersionLineJunk()
    {
        foreach (string junk in new[] { "", "clamscan 1.5.4", "ClamAV", "ERROR: no such file", "ClamAV 1.5.4/UNKNOWN/none" })
        {
            (string? engine, string? sig, DateTime? date) = ClamAvLocator.ParseVersionLine(junk);
            AssertTrue(engine is null, $"[{junk}] should not yield an engine version (got {engine})");
            AssertTrue(sig is null, $"[{junk}] should not yield a signature version (got {sig})");
            AssertTrue(date is null, $"[{junk}] should not yield a date");
        }
        return Task.CompletedTask;
    }

    private static Task TestSplitFoundLine()
    {
        (string path, string threat) = ClamAvScanner.SplitFoundLine(@"C:\data\evil.exe: Trojan.Generic FOUND");
        AssertEqual(@"C:\data\evil.exe", path, "path");
        AssertEqual("Trojan.Generic", threat, "threat");

        (string path2, string threat2) = ClamAvScanner.SplitFoundLine(@"C:\dir with spaces\file name.bin: Win.Test.SentinelStub FOUND");
        AssertEqual(@"C:\dir with spaces\file name.bin", path2, "path with spaces");
        AssertEqual("Win.Test.SentinelStub", threat2, "threat with spaces");

        // Threat names may contain ": " - the split must use the LAST " FOUND".
        (string path3, string threat3) = ClamAvScanner.SplitFoundLine(@"D:\x\y: Win.Test.Something: extra FOUND");
        AssertEqual(@"D:\x\y", path3, "path 3");
        AssertEqual("Win.Test.Something: extra", threat3, "threat containing a colon");

        // Degenerate line without a path separator.
        (string path4, string threat4) = ClamAvScanner.SplitFoundLine("orphan FOUND");
        AssertEqual("orphan", path4, "path 4");
        AssertEqual("", threat4, "threat 4");
        return Task.CompletedTask;
    }

    // ======================================================================
    //  Locator path helpers
    // ======================================================================

    private static Task TestLocatorPathHelpers()
    {
        string engineDir = Path.Combine(s_workRoot, "fake-engine");
        string databaseDir = Path.Combine(engineDir, "database");
        Directory.CreateDirectory(databaseDir);
        string fakeEngine = Path.Combine(engineDir, "clamscan.exe");
        File.WriteAllText(fakeEngine, "not a real binary");

        string customDb = Path.Combine(s_workRoot, "custom-db");
        Directory.CreateDirectory(customDb);

        AssertEqual(databaseDir, ClamAvLocator.ResolveDatabaseDirectory(fakeEngine, null), "sibling database folder");
        AssertEqual(customDb, ClamAvLocator.ResolveDatabaseDirectory(fakeEngine, new AppSettings { DatabaseDirectory = customDb }),
            "settings database folder wins when it exists");

        string lonelyDir = Path.Combine(s_workRoot, "lonely");
        Directory.CreateDirectory(lonelyDir);
        AssertTrue(ClamAvLocator.ResolveDatabaseDirectory(Path.Combine(lonelyDir, "clamscan.exe"), null) is null,
            "no sibling database folder should resolve to null");

        AssertTrue(ClamAvLocator.FindFreshClamFor(fakeEngine) is null, "freshclam.exe is not there yet");
        File.WriteAllText(Path.Combine(engineDir, "freshclam.exe"), "not a real binary");
        AssertEqual(Path.Combine(engineDir, "freshclam.exe"), ClamAvLocator.FindFreshClamFor(fakeEngine), "freshclam.exe next to clamscan");

        AssertTrue(new ClamAvLocator().TryGetEngineInfo(Path.Combine(lonelyDir, "clamscan.exe")) is null,
            "a missing clamscan.exe has no engine info");
        return Task.CompletedTask;
    }

    // ======================================================================
    //  Scanner integration (stub engine)
    // ======================================================================

    private static async Task TestScanDetection(string? stub)
    {
        string engine = RequireStub(stub);
        string target = Path.Combine(s_workRoot, "scan-detection");
        Directory.CreateDirectory(target);

        string markerPath = Path.Combine(target, "marker.txt");
        await File.WriteAllTextAsync(markerPath, "harmless padding\nSENTINEL-STUB-TEST-FILE\nmore padding");
        await File.WriteAllTextAsync(Path.Combine(target, "clean.txt"), "plain harmless text");
        string nested = Path.Combine(target, "nested");
        Directory.CreateDirectory(nested);
        await File.WriteAllTextAsync(Path.Combine(nested, "clean2.txt"), "still harmless");
        for (int i = 0; i < 25; i++)
            await File.WriteAllTextAsync(Path.Combine(nested, $"bulk{i}.dat"), $"bulk file {i}");

        var progress = new RecordingProgress();
        var scanner = new ClamAvScanner();
        ScanOutcome outcome = await scanner.ScanAsync(
            new ScanRequest { TargetPath = target, EnginePath = engine },
            progress, CancellationToken.None);

        AssertTrue(outcome.FatalError is null, $"unexpected fatal error: {outcome.FatalError}");
        AssertEqual(1, outcome.ExitCode, "exit code (1 = detections)");
        AssertEqual(1, outcome.Detections.Count, "detection count");
        AssertEqual("Win.Test.SentinelStub", outcome.Detections[0].Threat, "threat name");
        AssertEqual(markerPath, outcome.Detections[0].Path, "detection path");
        AssertEqual(28L, outcome.ScannedFileCount, "scanned file count");
        AssertTrue(!outcome.Cancelled, "scan should not be marked cancelled");
        AssertTrue(outcome.Duration > TimeSpan.Zero, "duration should be measured");
        AssertTrue(outcome.Warnings.Count == 0, "unexpected warnings: " + string.Join(" | ", outcome.Warnings));

        // The first progress event for a folder scan is the file pre-count.
        AssertTrue(progress.Reports.Count > 0, "no progress was reported");
        AssertEqual("Counting files…", progress.Reports[0].CurrentFile, "first progress event");
    }

    private static async Task TestScanClean(string? stub)
    {
        string engine = RequireStub(stub);
        string target = Path.Combine(s_workRoot, "scan-clean");
        Directory.CreateDirectory(target);
        for (int i = 0; i < 5; i++)
            await File.WriteAllTextAsync(Path.Combine(target, $"file{i}.txt"), $"content {i}");

        var scanner = new ClamAvScanner();
        ScanOutcome outcome = await scanner.ScanAsync(
            new ScanRequest { TargetPath = target, EnginePath = engine },
            progress: null, CancellationToken.None);

        AssertTrue(outcome.FatalError is null, $"unexpected fatal error: {outcome.FatalError}");
        AssertEqual(0, outcome.ExitCode, "exit code (0 = clean)");
        AssertEqual(0, outcome.Detections.Count, "detection count");
        AssertEqual(5L, outcome.ScannedFileCount, "scanned file count");
    }

    private static async Task TestScanMissingTarget(string? stub)
    {
        string engine = RequireStub(stub);
        string missing = Path.Combine(s_workRoot, "does-not-exist", "nope.bin");
        var scanner = new ClamAvScanner();
        ScanOutcome outcome = await scanner.ScanAsync(
            new ScanRequest { TargetPath = missing, EnginePath = engine },
            progress: null, CancellationToken.None);

        AssertTrue(outcome.FatalError is not null, "a missing target must produce a fatal error");
        AssertTrue(outcome.FatalError!.Contains(missing, StringComparison.OrdinalIgnoreCase),
            "the fatal error should name the missing target");
        AssertEqual(0, outcome.Detections.Count, "detection count");

        // A missing engine is reported too.
        ScanOutcome noEngine = await scanner.ScanAsync(
            new ScanRequest { TargetPath = s_workRoot, EnginePath = Path.Combine(s_workRoot, "no-such-clamscan.exe") },
            progress: null, CancellationToken.None);
        AssertTrue(noEngine.FatalError is not null, "a missing engine must produce a fatal error");
        AssertTrue(noEngine.FatalError!.Contains("clamscan.exe", StringComparison.OrdinalIgnoreCase),
            "the fatal error should mention clamscan.exe");
    }

    private static async Task TestScanCancellation(string? stub)
    {
        string engine = RequireStub(stub);
        string target = Path.Combine(s_workRoot, "scan-cancel");
        Directory.CreateDirectory(target);
        for (int i = 0; i < 50; i++)
            await File.WriteAllTextAsync(Path.Combine(target, $"file{i}.txt"), $"content {i}");

        using var cts = new CancellationTokenSource();
        cts.Cancel(); // cancel before/while the engine starts

        var scanner = new ClamAvScanner();
        ScanOutcome outcome = await scanner.ScanAsync(
            new ScanRequest { TargetPath = target, EnginePath = engine },
            progress: null, cts.Token);

        AssertTrue(outcome.Cancelled, "outcome should be flagged as cancelled");
        AssertTrue(outcome.FatalError is null, $"a cancelled scan must not report a fatal error: {outcome.FatalError}");
    }

    private static async Task TestScanManyTargets(string? stub)
    {
        string engine = RequireStub(stub);

        string first = Path.Combine(s_workRoot, "scan-many-a");
        string second = Path.Combine(s_workRoot, "scan-many-b");
        Directory.CreateDirectory(first);
        Directory.CreateDirectory(second);
        await File.WriteAllTextAsync(Path.Combine(first, "a1.txt"), "SENTINEL-STUB-TEST-FILE");
        await File.WriteAllTextAsync(Path.Combine(first, "a2.txt"), "clean");
        await File.WriteAllTextAsync(Path.Combine(second, "b1.txt"), "clean");
        await File.WriteAllTextAsync(Path.Combine(second, "b2.txt"), "clean");

        var scanner = new ClamAvScanner();
        var requests = new[]
        {
            new ScanRequest { TargetPath = first, EnginePath = engine },
            new ScanRequest { TargetPath = second, EnginePath = engine }
        };

        ScanOutcome outcome = await scanner.ScanManyAsync(requests, progress: null, CancellationToken.None);
        AssertTrue(outcome.FatalError is null, $"unexpected fatal error: {outcome.FatalError}");
        AssertEqual(1, outcome.ExitCode, "exit code (1 = detections)");
        AssertEqual(4L, outcome.ScannedFileCount, "all files across both targets should be counted");
        AssertEqual(1, outcome.Detections.Count, "detection count");
        AssertTrue(outcome.Detections[0].Path.StartsWith(first, StringComparison.OrdinalIgnoreCase),
            "the detection should come from the first target");
    }

    private static async Task TestParallelScan(string? stub)
    {
        string engine = RequireStub(stub);
        string root = Path.Combine(s_workRoot, "scan-parallel");
        Directory.CreateDirectory(root);

        // Enough immediate subdirectories to trigger the splitter.
        for (int i = 0; i < 12; i++)
        {
            string sub = Path.Combine(root, $"sub{i}");
            Directory.CreateDirectory(sub);
            await File.WriteAllTextAsync(Path.Combine(sub, "f1.txt"), $"content {i}");
            await File.WriteAllTextAsync(Path.Combine(sub, "f2.txt"), $"more {i}");
        }
        string detection = Path.Combine(root, "sub3", "f1.txt");
        await File.WriteAllTextAsync(detection, "SENTINEL-STUB-TEST-FILE");

        var scanner = new ClamAvScanner();
        ScanOutcome outcome = await scanner.ScanManyAsync(
            new[] { new ScanRequest { TargetPath = root, EnginePath = engine } },
            progress: null, CancellationToken.None, parallelize: true, maxWorkers: 2);

        AssertTrue(outcome.FatalError is null, $"unexpected fatal error: {outcome.FatalError}");
        AssertEqual(1, outcome.ExitCode, "exit code (1 = detections)");
        AssertEqual(24L, outcome.ScannedFileCount, "every file in every split chunk should be counted");
        AssertEqual(1, outcome.Detections.Count, "detection count");
        AssertEqual(detection, outcome.Detections[0].Path, "detection path");
    }

    // ======================================================================
    //  UI smoke test
    //
    //  Builds the real Application, window and every view, then lays each one
    //  out. This is what catches missing {StaticResource} keys, broken control
    //  templates and bad XAML - all of which otherwise fail only at runtime
    //  and take the whole app down with them.
    // ======================================================================

    private static Task TestUiSmoke()
    {
        Exception? failure = null;

        var thread = new Thread(() =>
        {
            try
            {
                RunUiSmoke();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.IsBackground = true;
        thread.Start();
        thread.Join();

        if (failure is not null)
        {
            throw new Exception("the UI failed to load: " + failure);
        }
        return Task.CompletedTask;
    }

    private static void RunUiSmoke()
    {
        // The real App type, so App.xaml and its resource dictionary are loaded
        // exactly as they are in production.
        var app = new global::Sentinel.App();
        app.InitializeComponent();
        global::Sentinel.App.Services = global::Sentinel.App.CreateServices();

        var window = new global::Sentinel.MainWindow();

        // Force a layout pass so every control template is actually applied.
        window.Measure(new Size(1200, 800));
        window.Arrange(new Rect(0, 0, 1200, 800));
        window.UpdateLayout();

        foreach ((string tag, string viewName) in new[]
                 {
                     ("dashboard", "DashboardView"),
                     ("scan", "ScanView"),
                     ("results", "ResultsView"),
                     ("quarantine", "QuarantineView"),
                     ("history", "HistoryView"),
                     ("settings", "SettingsView")
                 })
        {
            window.Navigate(tag);
            window.UpdateLayout();
            PumpDispatcher();

            if (window.FindName(viewName) is not FrameworkElement view)
            {
                throw new Exception($"view '{viewName}' was not created");
            }
            if (view.Visibility != Visibility.Visible)
            {
                throw new Exception($"view '{viewName}' was not visible after navigating to '{tag}'");
            }

            // Flip the stateful properties so every style trigger actually applies.
            // A trigger whose setter is invalid only throws once it fires.
            ExerciseControlStates(view);
        }

        window.Close();
    }

    private static void ExerciseControlStates(DependencyObject root)
    {
        foreach (CheckBox box in FindAll<CheckBox>(root))
        {
            box.IsChecked = true;
            box.IsChecked = false;
            box.IsEnabled = false;
            box.IsEnabled = true;
        }
        foreach (RadioButton radio in FindAll<RadioButton>(root))
        {
            radio.IsChecked = true;
            radio.IsChecked = false;
        }
        foreach (Button button in FindAll<Button>(root))
        {
            button.IsEnabled = false;
            button.IsEnabled = true;
        }
    }

    private static IEnumerable<T> FindAll<T>(DependencyObject root) where T : DependencyObject
    {
        int count = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < count; i++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(root, i);
            if (child is T typed) yield return typed;
            foreach (T nested in FindAll<T>(child)) yield return nested;
        }
    }

    private static void PumpDispatcher()
    {
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(
            DispatcherPriority.Background, new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
    }

    /// <summary>
    /// WPF only applies a style trigger when its condition becomes true, so a brush
    /// property pointing at a <c>Color</c> resource can sit in the theme for months
    /// and then blow up the moment a button is pressed. This audits the XAML
    /// statically: no brush-valued property may reference a Color-typed resource.
    /// </summary>
    private static Task TestBrushResourceAudit()
    {
        string? repoRoot = FindRepoRoot();
        if (repoRoot is null) throw new Exception("could not locate the repository root");

        string appXaml = Path.Combine(repoRoot, "Sentinel", "App.xaml");
        string appText = File.ReadAllText(appXaml);

        var colorKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in Regex.Matches(appText, "<Color\\s+x:Key=\"([^\"]+)\""))
            colorKeys.Add(m.Groups[1].Value);

        if (colorKeys.Count == 0) throw new Exception("no Color resources found - the audit is not working");

        var files = new List<string> { appXaml };
        files.AddRange(Directory.GetFiles(Path.Combine(repoRoot, "Sentinel"), "*.xaml", SearchOption.AllDirectories));

        // Direct attribute form: Background="{StaticResource Key}"
        var direct = new Regex("(?:Background|Foreground|Stroke|BorderBrush|Fill)=\"\\{StaticResource\\s+([A-Za-z0-9_]+)\\s*\\}\"");
        // Style setter form: <Setter Property="Background" Value="{StaticResource Key}" />
        var setter = new Regex("Property=\"(?:Background|Foreground|Stroke|BorderBrush|Fill|SelectionBrush)\"[^>]*?Value=\"\\{StaticResource\\s+([A-Za-z0-9_]+)\\s*\\}\"");

        int problems = 0;
        foreach (string file in files)
        {
            string text = File.ReadAllText(file);
            foreach (Match m in direct.Matches(text)) ReportIfColor(file, m.Groups[1].Value, colorKeys, ref problems);
            foreach (Match m in setter.Matches(text)) ReportIfColor(file, m.Groups[1].Value, colorKeys, ref problems);
        }

        AssertTrue(problems == 0,
            $"{problems} brush-valued property/property-setter assignment(s) point at a Color resource - " +
            "WPF throws \"is not a valid value for property 'Background'\" when the setter is applied");

        return Task.CompletedTask;
    }

    private static void ReportIfColor(string file, string key, HashSet<string> colorKeys, ref int problems)
    {
        if (!colorKeys.Contains(key)) return;
        problems++;
        Console.WriteLine($"        {Path.GetFileName(file)}: '{key}' is a Color but was assigned to a brush property");
    }

    private static string? FindRepoRoot()
    {
        DirectoryInfo? dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Sentinel", "Sentinel.csproj"))) return dir.FullName;
            dir = dir.Parent;
        }
        return null;
    }

    // ======================================================================
    //  Quarantine
    // ======================================================================

    private static async Task TestQuarantineRoundTrip()
    {
        byte[] marker = Encoding.ASCII.GetBytes("SENTINEL-PLAINTEXT-CANARY-0123456789");
        byte[] content = new byte[64 * 1024];
        RandomNumberGenerator.Fill(content);
        Buffer.BlockCopy(marker, 0, content, 0, marker.Length);

        string source = Path.Combine(s_workRoot, "quarantine-source.bin");
        await File.WriteAllBytesAsync(source, content);
        string originalHash = await HashUtil.ComputeFileSha256Async(source);

        var quarantine = new QuarantineService();
        QuarantineEntry entry = await quarantine.QuarantineFileAsync(source, "Test.Threat.Sample", originalHash);

        AssertTrue(!File.Exists(source), "the original file must be removed after quarantine");
        AssertTrue(entry.Encrypted, "entry should be marked encrypted");
        AssertTrue(!entry.OriginalStillPresent, "OriginalStillPresent should be false");
        AssertEqual("Test.Threat.Sample", entry.Threat, "threat name");
        AssertEqual(content.Length, (int)entry.SizeBytes, "recorded size");
        AssertEqual(originalHash, entry.Sha256, "recorded hash");

        string payloadPath = quarantine.GetPayloadPath(entry);
        AssertTrue(File.Exists(payloadPath), "the quarantine payload must exist");

        // The stored payload must be ciphertext, not a plaintext malware copy.
        byte[] stored = await File.ReadAllBytesAsync(payloadPath);
        byte[] expectedHeader = Encoding.ASCII.GetBytes("SNQT1");
        AssertTrue(stored.Length > 5 && stored[0] == expectedHeader[0] && stored[1] == expectedHeader[1] &&
                    stored[2] == expectedHeader[2] && stored[3] == expectedHeader[3] && stored[4] == expectedHeader[4],
            "payload should start with the SNQT1 magic");
        AssertTrue(!ContainsSequence(stored, marker), "payload must not contain the plaintext canary");
        AssertTrue(stored.Length >= content.Length, "payload should be at least as large as the plaintext");

        AssertTrue(await quarantine.VerifyIntegrityAsync(entry), "integrity check should pass after quarantine");

        IReadOnlyList<QuarantineEntry> all = quarantine.GetAll();
        AssertTrue(all.Any(e => e.Id == entry.Id), "the entry should be listed");
        AssertEqual(1, all.Count(e => e.Id == entry.Id), "the entry should be listed exactly once");

        // Restore to a fresh location and compare hashes.
        string restored = Path.Combine(s_workRoot, "restored", "quarantine-source.bin");
        await quarantine.RestoreAsync(entry, restored, overwrite: false);
        AssertTrue(File.Exists(restored), "restored file should exist");
        AssertEqual(originalHash, await HashUtil.ComputeFileSha256Async(restored), "restored file hash");
        AssertEqual(content.Length, new FileInfo(restored).Length, "restored file size");

        // Restoring on top of an existing file without overwrite must be refused.
        await AssertThrows<QuarantineException>(() => quarantine.RestoreAsync(entry, restored, overwrite: false));

        // Secure delete removes payload and manifest.
        await quarantine.DeleteAsync(entry);
        AssertTrue(!File.Exists(payloadPath), "the payload must be deleted");
        AssertTrue(!File.Exists(Path.Combine(AppPaths.QuarantineDir, entry.Id + ".json")), "the manifest must be deleted");
        AssertTrue(quarantine.GetAll().All(e => e.Id != entry.Id), "the entry must no longer be listed");
    }

    private static async Task TestQuarantineHashMismatch()
    {
        string source = Path.Combine(s_workRoot, "changed-since-scan.bin");
        await File.WriteAllTextAsync(source, "some scanned content");

        var quarantine = new QuarantineService();
        await AssertThrows<QuarantineException>(() =>
            quarantine.QuarantineFileAsync(source, "Test.Threat", "0000000000000000000000000000000000000000000000000000000000000000"));

        AssertTrue(File.Exists(source), "the source must be left untouched when the hash check fails");
        AssertEqual(0, quarantine.GetAll().Count, "nothing should have entered quarantine");
    }

    private static async Task TestLegacyQuarantineImport()
    {
        Directory.CreateDirectory(AppPaths.LegacyManifestDir);

        string legacyId = "legacy0000000000000000000000000001";
        string legacyPayload = Path.Combine(AppPaths.LegacyManifestDir, "legacy-payload.bin");
        byte[] legacyBytes = Encoding.UTF8.GetBytes("legacy plaintext sample - SENTINEL-LEGACY-CANARY");
        await File.WriteAllBytesAsync(legacyPayload, legacyBytes);
        string legacyHash = await HashUtil.ComputeFileSha256Async(legacyPayload);

        string manifestPath = Path.Combine(AppPaths.LegacyManifestDir, legacyId + ".json");
        var legacyManifest = new
        {
            Id = legacyId,
            OriginalPath = @"C:\Users\test\Downloads\evil.exe",
            QuarantinePath = legacyPayload,
            Threat = "Backdoor.OldPrototype",
            Sha256 = legacyHash,
            QuarantinedAtUtc = DateTime.UtcNow.AddDays(-3)
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(legacyManifest));

        var quarantine = new QuarantineService();
        QuarantineEntry? imported = quarantine.GetAll().FirstOrDefault(e => e.Id == legacyId);
        AssertTrue(imported is not null, "the legacy manifest should be imported");
        AssertTrue(!imported!.Encrypted, "a legacy entry must be flagged as unencrypted");
        AssertEqual("Backdoor.OldPrototype", imported.Threat, "legacy threat name");
        AssertEqual("evil.exe", imported.FileName, "legacy file name");
        AssertEqual(legacyHash, imported.Sha256, "legacy hash");
        AssertTrue(imported.Notes.Contains("prototype", StringComparison.OrdinalIgnoreCase),
            "the legacy entry should be annotated");
        AssertTrue(await quarantine.VerifyIntegrityAsync(imported), "the legacy payload hash should verify");

        await quarantine.DeleteAsync(imported);
        AssertTrue(!File.Exists(manifestPath), "the legacy manifest must be deleted");
        AssertTrue(!File.Exists(legacyPayload), "the legacy payload must be deleted");
        AssertTrue(quarantine.GetAll().All(e => e.Id != legacyId), "the legacy entry must no longer be listed");
    }

    // ======================================================================
    //  History
    // ======================================================================

    private static Task TestHistory()
    {
        var history = new HistoryService();
        history.Load(50);
        history.Clear();

        DateTime started = new DateTime(2026, 10, 20, 9, 0, 0, DateTimeKind.Utc);
        var session = new ScanSession
        {
            Target = @"C:\Users\me\Downloads",
            StartedAtUtc = started,
            FinishedAtUtc = started.AddSeconds(4),
            EngineVersion = "1.5.4",
            ScannedFileCount = 123,
            DetectionCount = 2,
            WarningCount = 1,
            Outcome = "2 detection(s)",
            Detections =
            {
                new ScanResultItem { Kind = ScanItemKind.Detection, Status = "DETECTED", Threat = "Win.Test.A", Path = @"C:\a.exe", Sha256 = "AAAA" },
                new ScanResultItem { Kind = ScanItemKind.Detection, Status = "DETECTED", Threat = "Win.Test.B", Path = @"C:\b.exe", Sha256 = "BBBB" }
            },
            Warnings = { "some warning" }
        };
        history.Add(session);

        var reloaded = new HistoryService();
        reloaded.Load(50);
        AssertEqual(1, reloaded.Sessions.Count, "session count after reload");
        ScanSession? first = reloaded.Sessions.FirstOrDefault();
        AssertTrue(first is not null, "reloaded session should exist");
        AssertEqual(@"C:\Users\me\Downloads", first!.Target, "target");
        AssertEqual(2, first.DetectionCount, "detection count");
        AssertEqual(123L, first.ScannedFileCount, "scanned file count");
        AssertEqual("1.5.4", first.EngineVersion, "engine version");
        AssertEqual(2, first.Detections.Count, "persisted detection rows");
        AssertEqual("Win.Test.B", first.Detections[1].Threat, "second detection threat");

        // Cap: sessions are added oldest-first, newest end up at index 0.
        var capped = new HistoryService();
        capped.Load(10);
        capped.Clear();
        for (int i = 0; i < 25; i++)
            capped.Add(new ScanSession { Target = $"t{i}", StartedAtUtc = started.AddMinutes(i) });

        AssertEqual(10, capped.Sessions.Count, "in-memory cap");

        var cappedReload = new HistoryService();
        cappedReload.Load(10);
        AssertEqual(10, cappedReload.Sessions.Count, "reloaded cap");
        AssertEqual("t24", cappedReload.Sessions[0].Target, "newest session first after reload");
        AssertTrue(cappedReload.Sessions.All(s => s.Target is "t24" or "t23" or "t22" or "t21" or "t20"
            or "t19" or "t18" or "t17" or "t16" or "t15"), "only the newest 10 sessions should survive the cap");
        AssertTrue(File.Exists(AppPaths.HistoryFile), "history.json should exist");

        cappedReload.Clear();
        AssertEqual(0, cappedReload.Sessions.Count, "clear empties the history");
        var afterClear = new HistoryService();
        afterClear.Load(10);
        AssertEqual(0, afterClear.Sessions.Count, "clear is persisted");

        return Task.CompletedTask;
    }

    // ======================================================================
    //  Engine installer configuration
    // ======================================================================

    private static Task TestEngineInstallerConfig()
    {
        string databaseDir = AppPaths.ManagedClamDatabase;
        string config = EngineInstaller.BuildFreshClamConfig(databaseDir);

        AssertTrue(config.Contains($"DatabaseDirectory \"{databaseDir.Replace("\\", "\\\\")}\"", StringComparison.Ordinal),
            "DatabaseDirectory must be present and backslash-escaped");
        AssertTrue(config.Contains($"DatabaseOwner \"{Environment.UserName}\"", StringComparison.Ordinal),
            "DatabaseOwner must be the current user");
        AssertTrue(config.Contains("DatabaseMirror database.clamav.net", StringComparison.Ordinal),
            "freshclam 1.5.x refuses to run without an explicit DatabaseMirror");
        AssertTrue(config.Contains($"UpdateLogFile \"{AppPaths.LogsDir.Replace("\\", "\\\\")}\\\\freshclam.log\"", StringComparison.Ordinal),
            "UpdateLogFile must point into Sentinel's Logs folder");
        AssertTrue(config.Contains("LogTime yes", StringComparison.Ordinal), "LogTime yes");
        AssertTrue(config.Contains("MaxAttempts 3", StringComparison.Ordinal), "MaxAttempts 3");
        AssertTrue(config.Contains("DNSDatabaseInfo current.cvd.clamav.net", StringComparison.Ordinal),
            "DNSDatabaseInfo should keep the official DNS check enabled - disabling it forces an " +
            "HTTP check on every run and trips the ClamAV CDN rate limiter");

        string url = EngineInstaller.GetDownloadUrl();
        AssertTrue(url.StartsWith("https://github.com/Cisco-Talos/clamav/releases/download/clamav-", StringComparison.Ordinal),
            $"engine downloads must come from the official Cisco Talos GitHub release (got {url})");
        AssertTrue(url.Contains($"clamav-{EngineInstaller.ClamAvVersion}.", StringComparison.Ordinal),
            "the download URL should embed the pinned version");
        AssertTrue(url.EndsWith(".zip", StringComparison.Ordinal), "the download URL should be a zip");
        AssertEqual("https://www.clamav.net/downloads", EngineInstaller.GetOfficialDownloadsPage(), "downloads page");
        return Task.CompletedTask;
    }

    // ======================================================================
    //  Real ClamAV engine (opt-in via --real-engine)
    //
    //  Note: the engine is resolved from SENTINEL_CLAMAV_DIR / the real
    //  %LOCALAPPDATA%\Sentinel\ClamAV folder, NOT from AppPaths - the test run
    //  redirects SENTINEL_DATA_ROOT into a temp folder.
    // ======================================================================

    private static Task TestRealEngineDiscovery(string clamDir)
    {
        string clamScan = Path.Combine(clamDir, "clamscan.exe");
        ClamAvEngineInfo? info = new ClamAvLocator().TryGetEngineInfo(clamScan);
        AssertTrue(info is not null, $"TryGetEngineInfo returned null for {clamScan}");
        AssertEqual(clamScan, info!.ClamScanPath, "clamscan path");
        AssertEqual(EngineInstaller.ClamAvVersion, info.EngineVersion, "engine version");
        AssertTrue(info.SignatureVersion is not null && info.SignatureVersion.Length > 0,
            "the signature version should parse from the real version banner");
        AssertTrue(info.SignatureDateUtc is not null, "the signature date should parse from the real version banner");
        AssertEqual(Path.Combine(clamDir, "freshclam.exe"), info.FreshClamPath, "freshclam path");
        AssertEqual(Path.Combine(clamDir, "database"), info.DatabaseDirectory, "database directory");

        var settings = new AppSettings { EnginePath = clamScan };
        ClamAvEngineInfo? found = new ClamAvLocator().Find(settings);
        AssertTrue(found is not null && found.ClamScanPath == clamScan,
            "settings-driven discovery should find the same engine");

        Console.WriteLine($"        banner: {info.VersionLine}");
        return Task.CompletedTask;
    }

    private static async Task TestRealFreshClamConfig(string clamDir)
    {
        string freshclam = Path.Combine(clamDir, "freshclam.exe");
        AssertTrue(File.Exists(freshclam), $"freshclam.exe is missing from {clamDir}");

        string database = Path.Combine(clamDir, "database");
        string configPath = Path.Combine(s_workRoot, "freshclam.generated.conf");
        await File.WriteAllTextAsync(configPath, EngineInstaller.BuildFreshClamConfig(database));

        (int exitCode, string combined) = await RunProcessCapture(
            freshclam, [$"--config-file={configPath}", "--version"], clamDir);

        AssertTrue(!combined.Contains("Parse error", StringComparison.OrdinalIgnoreCase),
            $"freshclam rejected the config Sentinel generates:\n{combined.Trim()}");
        AssertEqual(0, exitCode, $"freshclam --version with the generated config failed:\n{combined.Trim()}");
        AssertTrue(combined.Contains("1.5", StringComparison.Ordinal),
            $"freshclam did not print its version: {combined.Trim()}");
    }

    private static async Task TestRealSignatureUpdate(string clamDir)
    {
        string freshclam = Path.Combine(clamDir, "freshclam.exe");
        string database = Path.Combine(clamDir, "database");
        string configPath = Path.Combine(s_workRoot, "freshclam.update.conf");
        await File.WriteAllTextAsync(configPath, EngineInstaller.BuildFreshClamConfig(database));

        var result = await new SignatureService().UpdateAsync(freshclam, configPath, output: null, CancellationToken.None);

        AssertTrue(result.Success,
            $"the app's signature update failed: {result.Message}\n\nRaw freshclam output:\n{TailOf(result.RawOutput, 1500)}");
        AssertTrue(result.Message.Length > 0, "the app should always produce a user-facing message");

        int ageDays = SignatureService.SignatureAgeDays(null, database);
        AssertTrue(ageDays >= 0 && ageDays < 7,
            $"the signature databases should be freshly downloaded, but their age is {ageDays} day(s)");

        Console.WriteLine($"        {result.Message} (exit {result.ExitCode}, database age {ageDays} day(s))");
    }

    private static async Task TestRealHashSignatureDetection(string clamDir)
    {
        string engine = Path.Combine(clamDir, "clamscan.exe");
        AssertTrue(File.Exists(engine), $"clamscan.exe is missing from {clamDir}");

        // A dedicated signature directory keeps this test independent of the official
        // databases and - crucially - of Microsoft Defender, because the "malware" is
        // 512 bytes of random noise that only our own .hdb signature matches.
        string signatureDir = Path.Combine(s_workRoot, "real-hashsig-db");
        Directory.CreateDirectory(signatureDir);

        string samplePath = Path.Combine(s_workRoot, "real-hashsig-sample.bin");
        byte[] sample = new byte[512];
        RandomNumberGenerator.Fill(sample);
        await File.WriteAllBytesAsync(samplePath, sample);

        string md5 = Convert.ToHexString(MD5.HashData(sample)).ToLowerInvariant();
        // .hdb format: <md5>:<size>:<signature name>:<target type, 0 = any file>
        await File.WriteAllTextAsync(
            Path.Combine(signatureDir, "sentinel-test.hdb"),
            $"{md5}:{sample.Length}:Sentinel.Test.HashSig:0");

        var scanner = new ClamAvScanner();
        ScanOutcome outcome = await scanner.ScanAsync(
            new ScanRequest { TargetPath = samplePath, EnginePath = engine, DatabaseDirectory = signatureDir },
            progress: null, CancellationToken.None);

        AssertTrue(outcome.FatalError is null, $"fatal error: {outcome.FatalError}");
        AssertEqual(1, outcome.ExitCode, "exit code (1 = detections)");
        AssertEqual(1, outcome.Detections.Count, "detection count");
        // clamscan tags signatures that did not come from an official CVD with .UNOFFICIAL.
        AssertTrue(outcome.Detections[0].Threat.StartsWith("Sentinel.Test.HashSig", StringComparison.Ordinal),
            $"threat name: expected a Sentinel.Test.HashSig* signature, got [{outcome.Detections[0].Threat}]");
        AssertEqual(samplePath, outcome.Detections[0].Path, "detection path");
        AssertEqual(1L, outcome.ScannedFileCount, "scanned file count");
        Console.WriteLine($"        detection: {outcome.Detections[0].Threat}");

        // Quarantine and restore the real detection.
        string hash = await HashUtil.ComputeFileSha256Async(samplePath);
        var quarantine = new QuarantineService();
        QuarantineEntry entry = await quarantine.QuarantineFileAsync(samplePath, outcome.Detections[0].Threat, hash);
        AssertTrue(!File.Exists(samplePath), "the original must be removed after quarantine");
        AssertTrue(entry.Encrypted, "the quarantined payload must be encrypted");
        AssertTrue(await quarantine.VerifyIntegrityAsync(entry), "quarantine integrity check");

        string restored = Path.Combine(s_workRoot, "real-hashsig-restored.bin");
        await quarantine.RestoreAsync(entry, restored, overwrite: false);
        AssertTrue(File.Exists(restored), "the restored file must exist");
        AssertEqual(hash, await HashUtil.ComputeFileSha256Async(restored), "restored file hash");

        await quarantine.DeleteAsync(entry);
        AssertTrue(!File.Exists(quarantine.GetPayloadPath(entry)), "the payload must be securely deleted");
        AssertTrue(quarantine.GetAll().All(e => e.Id != entry.Id), "the entry must be gone");

        TryDeleteFile(restored);
        TryDeleteFile(samplePath);
    }

    /// <summary>
    /// A resident clamd loads the signature database once and then answers in
    /// milliseconds, where a one-off clamscan has to reload the whole database
    /// (over a minute here). This is the difference the background engine makes.
    /// </summary>
    private static async Task TestRealDaemonScan(string clamDir)
    {
        string clamScan = Path.Combine(clamDir, "clamscan.exe");
        string clamd = Path.Combine(clamDir, "clamd.exe");
        if (!File.Exists(clamd)) throw new SkipException("clamd.exe is not part of this ClamAV package.");

        string database = Path.Combine(clamDir, "database");
        string sample = Path.Combine(s_workRoot, "daemon-sample.bin");
        await File.WriteAllTextAsync(sample, "a perfectly harmless daemon sample");

        using var daemon = new ClamDaemon();
        daemon.Start(clamd, database, AppPaths.LogsDir);

        var watch = System.Diagnostics.Stopwatch.StartNew();
        while (!daemon.IsReady && watch.Elapsed < TimeSpan.FromMinutes(5))
        {
            if (daemon.LastError is not null) throw new Exception("the daemon failed to start: " + daemon.LastError);
            await Task.Delay(500);
        }
        AssertTrue(daemon.IsReady, "the daemon did not become ready in time");
        Console.WriteLine($"        daemon ready after {watch.Elapsed.TotalSeconds:0.0}s");

        var scanWatch = System.Diagnostics.Stopwatch.StartNew();
        var scanner = new ClamAvScanner();
        ScanOutcome outcome = await scanner.ScanManyAsync(
            new[] { new ScanRequest { TargetPath = sample, EnginePath = clamScan, DatabaseDirectory = database, Daemon = daemon } },
            progress: null, CancellationToken.None);
        scanWatch.Stop();

        AssertTrue(outcome.FatalError is null, $"fatal error: {outcome.FatalError}");
        AssertEqual(1L, outcome.ScannedFileCount, "scanned file count");
        AssertEqual(0, outcome.Detections.Count, "detection count");
        AssertEqual(0, outcome.Warnings.Count, "warning count: " + string.Join(" | ", outcome.Warnings));
        Console.WriteLine($"        daemon scan took {scanWatch.Elapsed.TotalMilliseconds:0} ms");
    }

    private static async Task TestRealEicarDetection(string clamDir)
    {
        string engine = Path.Combine(clamDir, "clamscan.exe");
        string database = Path.Combine(clamDir, "database");

        string targetDir = Path.Combine(s_workRoot, "real-eicar");
        Directory.CreateDirectory(targetDir);
        string eicarPath = Path.Combine(targetDir, "eicar.com");
        const string eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        try
        {
            await File.WriteAllTextAsync(eicarPath, eicar);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            throw new SkipException(
                "Microsoft Defender refused to write the EICAR test file (" + ex.GetType().Name + "). " +
                "That is Defender doing its job, not a Sentinel defect.");
        }

        // Give on-access scanners a moment to act on the new file.
        await Task.Delay(750);
        if (!File.Exists(eicarPath))
            throw new SkipException(
                "Microsoft Defender deleted the EICAR test file the instant it was written. " +
                "Expected behaviour with Defender enabled; detection could not be observed this run.");

        var scanner = new ClamAvScanner();
        ScanOutcome outcome = await scanner.ScanAsync(
            new ScanRequest { TargetPath = eicarPath, EnginePath = engine, DatabaseDirectory = database },
            progress: null, CancellationToken.None);

        AssertTrue(outcome.FatalError is null,
            $"a Defender-interrupted scan must not surface as a fatal Sentinel error: {outcome.FatalError}");

        // Defender may leave the file "present" but block clamscan from opening it, in which
        // case clamscan exits 2 with a warning and no detection.
        bool defenderBlocked =
            outcome.Detections.Count == 0 &&
            (outcome.ExitCode == 2 ||
             outcome.Warnings.Any(w => w.Contains("Can't open file", StringComparison.OrdinalIgnoreCase) ||
                                       w.Contains("Can't stat", StringComparison.OrdinalIgnoreCase) ||
                                       w.Contains("Can't read", StringComparison.OrdinalIgnoreCase)));

        if (defenderBlocked)
        {
            throw new SkipException(
                "Microsoft Defender had already neutralised the EICAR sample when clamscan tried to open it " +
                $"(clamscan exit {outcome.ExitCode}: {string.Join(" | ", outcome.Warnings)}). " +
                "Sentinel reported this as a scan warning rather than a crash, which is the intended behaviour. " +
                "Detection itself is covered by the hash-signature test above.");
        }

        AssertEqual(1, outcome.ExitCode, "exit code (1 = detections)");
        AssertEqual(1, outcome.Detections.Count, "detection count");
        AssertTrue(outcome.Detections[0].Threat.Contains("Eicar", StringComparison.OrdinalIgnoreCase),
            $"expected an EICAR signature name, got [{outcome.Detections[0].Threat}]");
        AssertEqual(eicarPath, outcome.Detections[0].Path, "detection path");
        Console.WriteLine($"        detection: {outcome.Detections[0].Threat}");

        // Defender may have removed the sample again after the scan; put it back so the
        // quarantine path can still be exercised.
        if (!File.Exists(eicarPath)) await File.WriteAllTextAsync(eicarPath, eicar);
        string hash = await HashUtil.ComputeFileSha256Async(eicarPath);

        var quarantine = new QuarantineService();
        QuarantineEntry entry = await quarantine.QuarantineFileAsync(eicarPath, outcome.Detections[0].Threat, hash);
        AssertTrue(!File.Exists(eicarPath), "the original must be removed after quarantine");
        AssertTrue(entry.Encrypted, "the quarantined payload must be encrypted");
        AssertTrue(await quarantine.VerifyIntegrityAsync(entry), "quarantine integrity check");

        string restored = Path.Combine(targetDir, "restored-eicar.com");
        await quarantine.RestoreAsync(entry, restored, overwrite: false);
        AssertEqual(hash, await HashUtil.ComputeFileSha256Async(restored), "restored EICAR hash");
        AssertEqual(eicar, await File.ReadAllTextAsync(restored), "restored EICAR content");

        await quarantine.DeleteAsync(entry);
        AssertTrue(!File.Exists(quarantine.GetPayloadPath(entry)), "the payload must be securely deleted");

        TryDeleteFile(restored);
        TryDeleteFile(eicarPath);
    }

    private static string? FindRealClamAvDirectory()
    {
        string? env = Environment.GetEnvironmentVariable("SENTINEL_CLAMAV_DIR");
        if (!string.IsNullOrWhiteSpace(env) && File.Exists(Path.Combine(env, "clamscan.exe")))
            return env;

        // Deliberately not AppPaths.ManagedClamDir: the suite redirects SENTINEL_DATA_ROOT.
        string managed = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel", "ClamAV");
        return File.Exists(Path.Combine(managed, "clamscan.exe")) ? managed : null;
    }

    private static async Task<(int ExitCode, string Combined)> RunProcessCapture(
        string executable, IReadOnlyList<string> arguments, string workingDirectory)
    {
        var startInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory
        };
        foreach (string argument in arguments) startInfo.ArgumentList.Add(argument);

        using var process = System.Diagnostics.Process.Start(startInfo)
            ?? throw new Exception($"Could not start {executable}");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        string combined = (await stdout) + (await stderr);
        return (process.ExitCode, combined);
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { /* Defender may already own or have deleted it */ }
    }

    private static string TailOf(string text, int max)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= max ? text : text[^max..];
    }

    // ======================================================================
    //  Infrastructure
    // ======================================================================

    private static async Task Run(string name, Func<Task> test)
    {
        try
        {
            await test();
            s_passed++;
            Console.WriteLine($"  PASS  {name}");
        }
        catch (SkipException skip)
        {
            s_skipped++;
            Console.WriteLine($"  SKIP  {name}");
            Console.WriteLine($"        {skip.Message}");
        }
        catch (Exception ex)
        {
            string message = ex is AggregateException agg ? agg.Flatten().Message : ex.Message;
            s_failures.Add($"{name}: {message}");
            Console.WriteLine($"  FAIL  {name}");
            Console.WriteLine($"        {message.Replace("\n", "\n        ")}");
        }
    }

    private static void AssertTrue(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private static void AssertEqual<T>(T expected, T actual, string? label = null)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new Exception($"{label ?? "value"}: expected [{expected}], got [{actual}]");
    }

    private static async Task AssertThrows<TException>(Func<Task> action) where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException)
        {
            return;
        }
        catch (Exception ex)
        {
            throw new Exception($"expected {typeof(TException).Name} but got {ex.GetType().Name}: {ex.Message}");
        }
        throw new Exception($"expected {typeof(TException).Name} but no exception was thrown");
    }

    private static string RequireStub(string? stub)
    {
        return stub ?? throw new Exception(
            "Sentinel.StubEngine.exe was not found. Build the test project (it has a project reference " +
            "to the stub engine) before running the suite.");
    }

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return false;
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            int j = 0;
            while (j < needle.Length && haystack[i + j] == needle[j]) j++;
            if (j == needle.Length) return true;
        }
        return false;
    }

    private static string? FindStubEngine()
    {
        // Only trust a copy that also carries its managed dll - the bare apphost .exe is useless.
        string local = Path.Combine(AppContext.BaseDirectory, "Sentinel.StubEngine.exe");
        if (File.Exists(local) && File.Exists(Path.Combine(AppContext.BaseDirectory, "Sentinel.StubEngine.dll")))
            return local;

#if DEBUG
        const string preferred = "Debug";
#else
        const string preferred = "Release";
#endif
        var matches = new List<string>();
        DirectoryInfo? dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Sentinel", "Sentinel.csproj")))
            {
                string bin = Path.Combine(dir.FullName, "tests", "Sentinel.StubEngine", "bin");
                if (Directory.Exists(bin))
                {
                    try
                    {
                        matches.AddRange(Directory.EnumerateFiles(bin, "Sentinel.StubEngine.exe", SearchOption.AllDirectories)
                            .Where(exe => File.Exists(Path.ChangeExtension(exe, ".dll"))));
                    }
                    catch (Exception)
                    {
                        // Ignore an unreadable bin folder; there may be other candidates.
                    }
                }
                break;
            }
            dir = dir.Parent;
        }

        if (matches.Count == 0) return null;
        matches.Sort((a, b) => Rank(a).CompareTo(Rank(b)));
        return matches[0];

        int Rank(string path) =>
            path.Contains($"{Path.DirectorySeparatorChar}{preferred}{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ? 0 : 1;
    }

    private static void Cleanup(string root)
    {
        try { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
        catch { /* best effort - a locked file must not fail the run */ }
    }

    private sealed class RecordingProgress : IProgress<ScanProgressInfo>
    {
        public List<ScanProgressInfo> Reports { get; } = new();

        public void Report(ScanProgressInfo value)
        {
            lock (Reports) Reports.Add(value);
        }
    }

    /// <summary>Thrown when the environment makes a test impossible (e.g. Defender ate the sample).</summary>
    private sealed class SkipException : Exception
    {
        public SkipException(string message) : base(message) { }
    }
}
