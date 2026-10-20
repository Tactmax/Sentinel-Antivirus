using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using Sentinel.Models;
using Sentinel.Services;

namespace Sentinel.Views;

public partial class ScanView : UserControl, INotifyPropertyChanged
{
    private readonly ClamAvScanner _scanner = App.Services.Scanner;
    private CancellationTokenSource? _scanCts;
    private bool _scanning;
    private ClamAvEngineInfo? _engine;
    private bool _hasScanned;

    public event EventHandler? EngineStatusChanged;

    public ObservableCollection<ScanResultItem> Results { get; } = new();
    public event PropertyChangedEventHandler? PropertyChanged;

    public ScanView()
    {
        InitializeComponent();
        ResultsGrid.ItemsSource = Results;
        UpdateResultButtons();
        App.Services.Daemon.StateChanged += (_, _) => Dispatcher.Invoke(UpdateEngineHint);
        Loaded += (_, _) =>
        {
            RefreshEngineState();
            if (string.IsNullOrEmpty(TargetBox.Text) &&
                !string.IsNullOrWhiteSpace(App.Services.Settings.Settings.LastScanTarget) &&
                !App.Services.Settings.Settings.LastScanTarget.Contains(';'))
            {
                TargetBox.Text = App.Services.Settings.Settings.LastScanTarget;
            }
        };
    }

    private void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    // ---------- engine status ----------

    public void RefreshEngineState()
    {
        _engine = App.Services.Locator.Find(App.Services.Settings.Settings);
        if (_engine is null)
        {
            EngineLabel.Text = "No engine";
            EngineLabel.ToolTip = "Install the ClamAV engine from the Dashboard.";
            EngineDot.Fill = FindResource("MutedBrush") as System.Windows.Media.Brush;
            if (!_scanning) ScanButton.IsEnabled = false;
        }
        else
        {
            EngineLabel.Text = $"ClamAV {_engine.EngineVersion ?? "?"}";
            EngineLabel.ToolTip = _engine.ClamScanPath;
            EngineDot.Fill = FindResource("AccentBrush") as System.Windows.Media.Brush;
            if (!_scanning) ScanButton.IsEnabled = true;
        }
        UpdateDefsButton.IsEnabled = _engine is not null && !_scanning;
        UpdateEngineHint();
    }

    /// <summary>Explains the engine state: a warm daemon is fast, a cold one is not.</summary>
    private void UpdateEngineHint()
    {
        var daemon = App.Services.Daemon;
        if (daemon.IsReady)
        {
            EngineHint.Text = "Background engine ready — scans start instantly.";
            EngineHint.Foreground = FindResource("AccentBrush") as System.Windows.Media.Brush;
        }
        else if (daemon.IsRunning)
        {
            EngineHint.Text = "Warming up the background engine — the first scan still has to load the signature database.";
            EngineHint.Foreground = FindResource("WarningBrush") as System.Windows.Media.Brush;
        }
        else if (!string.IsNullOrWhiteSpace(daemon.LastError))
        {
            EngineHint.Text = "The background engine could not start, so each scan reloads the signature database (about a minute).";
            EngineHint.Foreground = FindResource("WarningBrush") as System.Windows.Media.Brush;
            EngineHint.ToolTip = daemon.LastError;
        }
        else
        {
            EngineHint.Text = "Each scan loads the signature database again, which takes about a minute.";
            EngineHint.Foreground = FindResource("MutedBrush") as System.Windows.Media.Brush;
        }
    }

    // ---------- target selection ----------

    private void ChooseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose a file to scan", CheckFileExists = true };
        if (dialog.ShowDialog() == true) TargetBox.Text = dialog.FileName;
    }

    private void ChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose a folder to scan", Multiselect = false };
        if (dialog.ShowDialog() == true) TargetBox.Text = dialog.FolderName;
    }

    private void TargetBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && !_scanning) Scan_Click(sender, e);
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        string target = TargetBox.Text.Trim().Trim('"');
        if (string.IsNullOrEmpty(target))
        {
            MessageBox.Show("Type a file or folder path, or use the browse buttons.", "No target chosen",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        await RunScanMultiAsync([target]);
    }

    public async Task QuickScanAsync()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] candidates =
        [
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(profile, "OneDrive", "Desktop"),
            Path.Combine(profile, "OneDrive", "Documents")
        ];
        string[] targets = candidates.Distinct(StringComparer.OrdinalIgnoreCase).Where(Directory.Exists).ToArray();
        if (targets.Length == 0)
        {
            MessageBox.Show("No common folders (Downloads, Desktop, Documents) were found to quick-scan.",
                "Quick scan", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        TargetBox.Text = targets.Length == 1 ? targets[0] : string.Join("; ", targets);
        await RunScanMultiAsync(targets);
    }

    public async Task FullScanAsync()
    {
        var confirm = MessageBox.Show(
            "A full scan of the C: drive reads most files on this PC and can take a long time.\n\n" +
            "Large folders are split across several engine processes automatically, and you can cancel at any time.\n\nContinue?",
            "Full scan", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;
        TargetBox.Text = @"C:\";
        await RunScanMultiAsync([@"C:\"]);
    }

    private async void QuickScan_Click(object sender, RoutedEventArgs e) => await QuickScanAsync();

    private async void FullScan_Click(object sender, RoutedEventArgs e) => await FullScanAsync();

    // ---------- scan entry points ----------

    public Task SetTargetAndScan(string target)
    {
        TargetBox.Text = target;
        return RunScanMultiAsync([target]);
    }

    public Task StartScanAsync(string target) => RunScanMultiAsync([target]);

    public Task StartScanAsync(string[] targets)
    {
        if (targets.Length == 1) TargetBox.Text = targets[0];
        return RunScanMultiAsync(targets);
    }

    // ---------- the scan ----------

    private async Task RunScanAsync(string target) => await RunScanMultiAsync([target]);

    private async Task RunScanMultiAsync(string[] targets)
    {
        if (_scanning) return;

        if (_engine is null)
        {
            RefreshEngineState();
            if (_engine is null)
            {
                MessageBox.Show("The ClamAV engine is not installed yet. Install it from the Dashboard.",
                    "No engine", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
        }

        foreach (string target in targets)
        {
            if (!File.Exists(target) && !Directory.Exists(target))
            {
                MessageBox.Show($"This path does not exist:\n{target}", "Invalid target",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        if (!HasAnySignatureFile(_engine.DatabaseDirectory))
        {
            var proceed = MessageBox.Show(
                "No virus signatures were detected. Scanning without signatures will not find anything.\n\nDownload signatures now?",
                "Signatures missing", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (proceed == MessageBoxResult.Yes)
            {
                await UpdateSignaturesAsync();
                RefreshEngineState();
                if (_engine is null) return;
            }
            else
            {
                return;
            }
        }

        _scanning = true;
        _scanCts = new CancellationTokenSource();
        SetIdle(false);
        Results.Clear();
        ResultsSummary.Text = "Scan running…";
        ScanStatusText.Text = "Starting ClamAV…";
        ScanProgress.IsIndeterminate = true;
        ScanProgress.Value = 0;
        ScanPercentText.Text = "";
        SpeedText.Text = "";
        ElapsedText.Text = "";

        var settings = App.Services.Settings.Settings;
        settings.LastScanTarget = targets.Length == 1 ? targets[0] : string.Join(";", targets);
        App.Services.Settings.Save();

        var session = new ScanSession
        {
            StartedAtUtc = DateTime.UtcNow,
            Target = targets.Length == 1 ? targets[0] : string.Join("; ", targets),
            EngineVersion = _engine.EngineVersion ?? "?"
        };

        var requests = targets.Select(t => new ScanRequest
        {
            TargetPath = t,
            EnginePath = _engine.ClamScanPath,
            DatabaseDirectory = _engine.DatabaseDirectory,
            ScanArchives = settings.ScanArchives,
            MaxFileSizeBytes = settings.MaxFileSizeMb > 0 ? settings.MaxFileSizeMb * 1024L * 1024L : null,
            MaxScanSizeBytes = settings.MaxScanSizeMb > 0 ? settings.MaxScanSizeMb * 1024L * 1024L : null,
            MaxScanTimeMs = settings.MaxScanTimeMs > 0 ? settings.MaxScanTimeMs : null,
            Daemon = App.Services.Daemon
        }).ToArray();

        bool parallelize = settings.ParallelScan;
        var allOutcomes = new List<ScanOutcome>();
        try
        {
            var progress = new Progress<ScanProgressInfo>(p =>
            {
                if (p.TotalKnown && p.TotalFiles > 0)
                {
                    ScanProgress.IsIndeterminate = false;
                    double pct = Math.Min(100, p.FilesScanned * 100.0 / p.TotalFiles);
                    ScanProgress.Value = pct;
                    ScanPercentText.Text = $"{pct:0}%";
                    ScanStatusText.Text = $"{p.FilesScanned:N0} / {p.TotalFiles:N0} files · {Truncate(p.CurrentFile, 110)}";
                }
                else
                {
                    ScanProgress.IsIndeterminate = true;
                    ScanPercentText.Text = "";
                    ScanStatusText.Text = $"{p.FilesScanned:N0} files scanned · {Truncate(p.CurrentFile, 110)}";
                }
                SpeedText.Text = p.ScanSpeed >= 1 ? $"{p.ScanSpeed:0} files/s" : "";
                ElapsedText.Text = FormatElapsed(p.ElapsedSeconds);
            });

            ScanOutcome outcome = await _scanner.ScanManyAsync(
                requests, progress, _scanCts.Token, parallelize, settings.EffectiveParallelWorkers);
            allOutcomes.Add(outcome);

            session.ScannedFileCount += outcome.ScannedFileCount;
            foreach (ScanResultItem item in outcome.Detections)
            {
                session.Detections.Add(item);
                Results.Add(item);
            }
            foreach (string warning in outcome.Warnings)
            {
                if (session.Warnings.Count < 100) session.Warnings.Add(warning);
            }
            session.WarningCount = session.Warnings.Count;

            var fatal = allOutcomes.FirstOrDefault(o => o.FatalError is not null);
            bool cancelled = allOutcomes.Any(o => o.Cancelled) || _scanCts.IsCancellationRequested;

            session.FinishedAtUtc = DateTime.UtcNow;
            session.DetectionCount = session.Detections.Count;
            session.Outcome = cancelled ? "Cancelled" : fatal is not null ? "Error" : session.DetectionCount > 0 ? "Detections found" : "Clean";
            App.Services.History.Add(session);

            int detectionCount = Results.Count(r => r.IsDetection);
            int warningCount = allOutcomes.Sum(o => o.Warnings.Count);
            long scannedTotal = session.ScannedFileCount;

            if (fatal is not null)
            {
                ResultsSummary.Text = "Scan reported an error.";
                ScanStatusText.Text = "Scan failed.";
                MessageBox.Show(fatal.FatalError, "Scan problem", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else if (cancelled)
            {
                ResultsSummary.Text = $"{detectionCount} detection(s) before cancellation.";
                ScanStatusText.Text = "Scan cancelled.";
            }
            else if (detectionCount > 0)
            {
                ResultsSummary.Text = $"{detectionCount} detection(s), {scannedTotal:N0} files scanned.";
                ScanStatusText.Text = "Scan finished — review detections below.";
                MessageBox.Show(
                    $"{detectionCount} suspicious file(s) were detected.\n\n" +
                    "Select items and use “Quarantine” to move them into Sentinel's encrypted quarantine. " +
                    "Only quarantine files you are prepared to have removed from their current location.",
                    "Detections found", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else if (warningCount > 0)
            {
                ResultsSummary.Text = $"{scannedTotal:N0} files scanned, {warningCount} warning(s), no detections.";
                ScanStatusText.Text = "Scan finished with warnings (some files may be inaccessible).";
            }
            else
            {
                ResultsSummary.Text = $"{scannedTotal:N0} files scanned — no detections.";
                ScanStatusText.Text = "Scan finished. Everything looked clean.";
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"The scan could not be completed:\n\n{ex.Message}", "Scan error",
                MessageBoxButton.OK, MessageBoxImage.Error);
            ScanStatusText.Text = "Scan failed.";
        }
        finally
        {
            _scanning = false;
            _hasScanned = true;
            _scanCts?.Dispose();
            _scanCts = null;
            ScanProgress.IsIndeterminate = false;
            SpeedText.Text = "";
            ElapsedText.Text = "";
            SetIdle(true);
            UpdateResultButtons();
        }
    }

    private void CancelScan_Click(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
        ScanStatusText.Text = "Cancelling…";
    }

    private void SetIdle(bool idle)
    {
        ScanButton.IsEnabled = idle;
        TargetBox.IsEnabled = idle;
        UpdateDefsButton.IsEnabled = idle && _engine is not null;
        ProgressPanel.Visibility = idle ? Visibility.Collapsed : Visibility.Visible;
        CancelButton.Visibility = idle ? Visibility.Collapsed : Visibility.Visible;
    }

    // ---------- signatures ----------

    private void UpdateDefs_Click(object sender, RoutedEventArgs e) => _ = UpdateSignaturesAsync();

    public async Task UpdateSignaturesAsync()
    {
        if (_engine is null)
        {
            MessageBox.Show("Install the ClamAV engine first.", "No engine", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        string? freshclam = _engine.FreshClamPath
            ?? (File.Exists(App.Services.Settings.Settings.FreshClamPath) ? App.Services.Settings.Settings.FreshClamPath : null);
        if (freshclam is null)
        {
            MessageBox.Show(
                "freshclam.exe was not found next to clamscan.exe.\nReinstall the ClamAV engine from Settings to fix this.",
                "freshclam missing", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        string? config = File.Exists(AppPaths.ManagedClamConfig) ? AppPaths.ManagedClamConfig : null;
        UpdateDefsButton.IsEnabled = false;
        ScanStatusText.Text = "Downloading virus definitions…";
        try
        {
            var output = new Progress<string>(line => ScanStatusText.Text = Truncate(line, 160));
            SignatureUpdateResult result = await App.Services.Signatures.UpdateAsync(freshclam, config, output, CancellationToken.None);
            MessageBox.Show(result.Message, result.Success ? "Definitions" : "Update problem",
                MessageBoxButton.OK, result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
            RefreshEngineState();
            EngineStatusChanged?.Invoke(this, EventArgs.Empty);
            if (!_scanning) ScanStatusText.Text = "Ready.";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Signature update failed:\n\n{ex.Message}", "Update error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            UpdateDefsButton.IsEnabled = _engine is not null && !_scanning;
        }
    }

    // ---------- results actions ----------

    private void UpdateResultButtons()
    {
        bool hasDetections = Results.Any(r => r.IsDetection);
        QuarantineSelectedButton.IsEnabled = hasDetections && ResultsGrid.SelectedItem is ScanResultItem { IsDetection: true, Quarantined: false };
        QuarantineAllButton.IsEnabled = hasDetections;
        bool empty = Results.Count == 0;
        ResultsEmptyHint.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        ResultsGrid.Visibility = empty ? Visibility.Collapsed : Visibility.Visible;

        if (empty && _hasScanned)
        {
            ResultsEmptyTitle.Text = "No threats found";
            ResultsEmptyText.Text = "The scan finished and did not flag anything.";
        }
        else
        {
            ResultsEmptyTitle.Text = "Nothing scanned yet";
            ResultsEmptyText.Text = "Run a scan above — results appear here as soon as the engine finds something.";
        }
    }

    private async void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateResultButtons();
        if (ResultsGrid.SelectedItem is ScanResultItem { IsDetection: true } item &&
            string.IsNullOrEmpty(item.Sha256) && File.Exists(item.Path))
        {
            _ = ComputeHashAsync(item);
        }
    }

    private async Task ComputeHashAsync(ScanResultItem item)
    {
        try
        {
            item.Sha256 = await HashUtil.ComputeFileSha256Async(item.Path);
        }
        catch
        {
            item.Sha256 = "unavailable";
        }
    }

    private void ResultsGrid_DoubleClick(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is ScanResultItem item && File.Exists(item.Path))
        {
            try { ProcessStartUtil.OpenInExplorer(item.Path); }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Could not open location", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }

    private void OpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is ScanResultItem item)
        {
            if (File.Exists(item.Path)) ProcessStartUtil.OpenInExplorer(item.Path);
            else if (Directory.Exists(item.Path)) ProcessStartUtil.OpenFolder(item.Path);
            else MessageBox.Show("That path no longer exists.", "Not found", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show("Select a result first.", "Nothing selected", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void ClearResults_Click(object sender, RoutedEventArgs e)
    {
        Results.Clear();
        _hasScanned = false;
        ResultsSummary.Text = "Run a scan to see results here.";
        ScanStatusText.Text = "Ready. Choose a target, or use Quick scan.";
        ScanProgress.Value = 0;
        ScanPercentText.Text = "";
        UpdateResultButtons();
    }

    private async void QuarantineSelected_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ScanResultItem item) return;
        await QuarantineItemsAsync([item]);
    }

    private async void QuarantineAll_Click(object sender, RoutedEventArgs e)
    {
        var items = Results.Where(r => r.IsDetection && !r.Quarantined).ToList();
        if (items.Count == 0) return;
        await QuarantineItemsAsync(items);
    }

    private async Task QuarantineItemsAsync(IReadOnlyList<ScanResultItem> items)
    {
        if (items.Count == 0) return;

        string message = items.Count == 1
            ? $"Quarantine this detected file?\n\n{items[0].Path}\n\n" +
              "The file will be encrypted, verified, and removed from its original location. " +
              "You can restore it later from the Quarantine screen if it turns out to be a false positive."
            : $"Quarantine {items.Count} detected files?\n\n" +
              "Each file will be encrypted, verified, and removed from its original location. You can restore them later from the Quarantine screen.";

        var confirm = MessageBox.Show(message, "Confirm quarantine", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        int ok = 0;
        var failures = new List<string>();
        foreach (ScanResultItem item in items)
        {
            try
            {
                if (string.IsNullOrEmpty(item.Sha256) && File.Exists(item.Path))
                    await ComputeHashAsync(item);

                item.Status = "QUARANTINING…";
                ResultsGrid.Items.Refresh();
                await App.Services.Quarantine.QuarantineFileAsync(item.Path, item.Threat, item.Sha256);
                item.Status = "QUARANTINED";
                item.Quarantined = true;
                ok++;
            }
            catch (QuarantineException ex) when (ex.Message.Contains("could not delete the original", StringComparison.OrdinalIgnoreCase))
            {
                item.Status = "COPIED — ORIGINAL PRESENT";
                failures.Add($"{item.Path}\n  {ex.Message}");
            }
            catch (Exception ex)
            {
                item.Status = "FAILED";
                failures.Add($"{item.Path}\n  {ex.Message}");
            }
            ResultsGrid.Items.Refresh();
        }

        UpdateResultButtons();

        if (failures.Count > 0)
        {
            MessageBox.Show(
                $"{ok} file(s) quarantined. Some items need attention:\n\n" + string.Join("\n\n", failures.Take(5)),
                "Quarantine finished with problems", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        else
        {
            MessageBox.Show($"{ok} file(s) moved to encrypted quarantine.", "Quarantine complete",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    // ---------- helpers ----------

    private static bool HasAnySignatureFile(string? dbDir)
    {
        if (string.IsNullOrEmpty(dbDir) || !Directory.Exists(dbDir)) return false;
        try
        {
            return Directory.EnumerateFiles(dbDir, "*.cvd").Any() ||
                   Directory.EnumerateFiles(dbDir, "*.cld").Any();
        }
        catch
        {
            return false;
        }
    }

    private static string Truncate(string text, int max) =>
        text.Length <= max ? text : text[..max] + "…";

    private static string FormatElapsed(double seconds)
    {
        if (seconds < 60) return $"{seconds:0}s";
        var ts = TimeSpan.FromSeconds(seconds);
        return ts.TotalHours >= 1 ? $"{(int)ts.TotalHours}:{ts.Minutes:00}:{ts.Seconds:00}" : $"{ts.Minutes:00}:{ts.Seconds:00}";
    }

    // ---------- drag & drop ----------

    private void Root_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Link : DragDropEffects.None;
        e.Handled = true;
    }

    private void Root_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is not string[] { Length: > 0 } paths) return;
        TargetBox.Text = paths[0];
        if (!_scanning) _ = RunScanMultiAsync([paths[0]]);
    }
}

internal static class ProcessStartUtil
{
    public static void OpenInExplorer(string filePath)
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = $"/select,\"{filePath}\"",
            UseShellExecute = true
        });
    }

    public static void OpenFolder(string folder)
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = folder,
            UseShellExecute = true
        });
    }
}
